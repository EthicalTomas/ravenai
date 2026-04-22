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
class XSSScanner:
	client: HTTPClient
	payloads: list[str]
	reflection_markers: list[str]
	min_confidence: float
	severity: str

	def scan_endpoint(self, endpoint: Endpoint) -> ScanResult:
		result = ScanResult(
			vulnerabilities=[],
			raw_outputs=[],
			metadata={"scanner": "xss", "endpoint": endpoint.to_dict(), "safe_testing_mode": True},
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
			LOGGER.exception("Unexpected XSS scanner failure for endpoint: %s", endpoint.url)
			result.metadata["error"] = "xss_scanner_failure"
			return result

	def _scan_parameter(self, endpoint: Endpoint, parameter_name: str) -> Vulnerability | None:
		detected_payloads: list[str] = []
		evidence: list[str] = []
		best_confidence = 0.0

		for payload in self.payloads:
			response = self._inject_and_request(endpoint=endpoint, parameter_name=parameter_name, payload=payload)
			if response is None:
				continue

			confidence = self._score_reflection(payload=payload, body=response.text)
			if confidence < self.min_confidence:
				continue

			detected_payloads.append(payload)
			evidence.append(f"param={parameter_name} status={response.status_code}")
			best_confidence = max(best_confidence, confidence)
			
			# Capture request data for replay (last successful payload)
			params = {name: "scan" for name in endpoint.params}
			params[parameter_name] = payload
			request_data = {
				"method": endpoint.method,
				"url": endpoint.url,
				"params": params,
				"headers": dict(endpoint.headers),
			}

		if not detected_payloads:
			return None

		return Vulnerability(
			vuln_type="xss",
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

	def _score_reflection(self, payload: str, body: str) -> float:
		lowered_body = body.lower()
		lowered_payload = payload.lower()
		marker_hits = sum(1 for marker in self.reflection_markers if marker.lower() in lowered_body)
		reflected = lowered_payload in lowered_body

		score = 0.0
		if reflected:
			score += 0.7
		if marker_hits > 0:
			score += min(0.3, marker_hits * 0.1)
		return min(1.0, score)
