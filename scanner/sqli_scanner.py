from __future__ import annotations

import logging
from dataclasses import dataclass

import logging
from dataclasses import dataclass
from typing import Any

from data.models import Endpoint, ScanResult, Vulnerability
from utils.http_client import HTTPClient


LOGGER = logging.getLogger(__name__)


@dataclass(slots=True)
class SQLiScanner:
	client: HTTPClient
	payloads: list[str]
	error_signatures: list[str]
	min_confidence: float
	severity: str

	def scan_endpoint(self, endpoint: Endpoint) -> ScanResult:
		result = ScanResult(
			vulnerabilities=[],
			raw_outputs=[],
			metadata={"scanner": "sqli", "endpoint": endpoint.to_dict(), "safe_testing_mode": True},
		)

		if endpoint.method != "GET" or not endpoint.params:
			return result

		try:
			for parameter_name in sorted(endpoint.params):
				vulnerability = self._scan_parameter(endpoint=endpoint, parameter_name=parameter_name)
				if vulnerability is not None:
					result.vulnerabilities.append(vulnerability)
			result.metadata["vulnerability_count"] = len(result.vulnerabilities)
			return result
		except Exception:
			LOGGER.exception("Unexpected SQLi scanner failure for endpoint: %s", endpoint.url)
			result.metadata["error"] = "sqli_scanner_failure"
			return result

	def _scan_parameter(self, endpoint: Endpoint, parameter_name: str) -> Vulnerability | None:
		detected_payloads: list[str] = []
		evidence: list[str] = []
		best_confidence = 0.0

		for payload in self.payloads:
			response = self._inject_and_request(endpoint=endpoint, parameter_name=parameter_name, payload=payload)
			if response is None:
				continue

			confidence, matched_signatures = self._score_sqli_response(
				status_code=response.status_code,
				body=response.text,
			)
			if confidence < self.min_confidence:
				continue

			detected_payloads.append(payload)
			signatures_evidence = ",".join(matched_signatures) if matched_signatures else "status-based"
			evidence.append(f"param={parameter_name} status={response.status_code} signatures={signatures_evidence}")
			best_confidence = max(best_confidence, confidence)
			
			# Capture request data for replay (last successful payload)
			params = {name: "scan" for name in endpoint.params}
			params[parameter_name] = payload
			request_data = {
				"method": "GET",
				"url": endpoint.url,
				"params": params,
				"headers": dict(endpoint.headers),
			}

		if not detected_payloads:
			return None

		return Vulnerability(
			vuln_type="sqli",
			endpoint=endpoint,
			severity=self.severity,
			payloads=detected_payloads,
			evidence=evidence,
			confidence=best_confidence,
			request_data=request_data,
		)

	def _inject_and_request(self, endpoint: Endpoint, parameter_name: str, payload: str) -> Any | None:
		params = {name: "scan" for name in endpoint.params}
		params[parameter_name] = payload

		try:
			return self.client.request(
				method="GET",
				url=endpoint.url,
				params=params,
			)
		except Exception:
			return None

	def _score_sqli_response(self, status_code: int, body: str) -> tuple[float, list[str]]:
		lowered_body = body.lower()
		matched_signatures = [
			signature for signature in self.error_signatures if signature.lower() in lowered_body
		]

		score = 0.0
		if matched_signatures:
			score += min(0.8, 0.2 * len(matched_signatures))
		if status_code >= 500:
			score += 0.3

		return min(1.0, score), matched_signatures
