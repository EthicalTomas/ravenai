from __future__ import annotations

import logging
from dataclasses import dataclass

from ai.llm_client import LLMClient, LLMRequest
from data.models import Endpoint, ScanResult, Vulnerability


LOGGER = logging.getLogger(__name__)


@dataclass(slots=True)
class VulnerabilityClassifier:
	llm_client: LLMClient
	prompt_template: str
	constraints: list[str]
	allowed_severities: set[str]
	min_ai_confidence: float

	def classify(self, endpoint: Endpoint, scan_result: ScanResult) -> list[Vulnerability]:
		enriched_vulnerabilities: list[Vulnerability] = []

		for vulnerability in scan_result.vulnerabilities:
			if vulnerability.endpoint != endpoint:
				continue

			request = LLMRequest(
				prompt=self.prompt_template.format(
					vuln_type=vulnerability.vuln_type,
					endpoint_url=endpoint.url,
					current_severity=vulnerability.severity,
				),
				context={
					"endpoint": endpoint.to_dict(),
					"vulnerability": vulnerability.to_dict(),
					"instruction": "Classify severity/confidence for this existing finding only.",
					"output_format": "severity=<severity>\nconfidence=<0.0-1.0>",
				},
				constraints=list(self.constraints),
			)
			response = self.llm_client.generate(request)

			if response.confidence < self.min_ai_confidence:
				enriched_vulnerabilities.append(vulnerability)
				continue

			parsed_severity, parsed_confidence = self._parse_classification(
				content=response.content,
				fallback_severity=vulnerability.severity,
				fallback_confidence=vulnerability.confidence,
			)
			enriched_vulnerabilities.append(
				Vulnerability(
					vuln_type=vulnerability.vuln_type,
					endpoint=vulnerability.endpoint,
					severity=parsed_severity,
					payloads=list(vulnerability.payloads),
					evidence=list(vulnerability.evidence),
					confidence=max(vulnerability.confidence, parsed_confidence),
				)
			)

		return enriched_vulnerabilities

	def _parse_classification(
		self,
		content: str,
		fallback_severity: str,
		fallback_confidence: float,
	) -> tuple[str, float]:
		parsed: dict[str, str] = {}

		for line in content.splitlines():
			line = line.strip()
			if "=" not in line:
				continue
			key, value = line.split("=", 1)
			parsed[key.strip().lower()] = value.strip()

		severity = parsed.get("severity", fallback_severity).lower()
		if severity not in {value.lower() for value in self.allowed_severities}:
			LOGGER.debug("Unsupported severity from AI response: %s", severity)
			severity = fallback_severity

		confidence_value = parsed.get("confidence")
		if confidence_value is None:
			return severity, fallback_confidence

		try:
			confidence = float(confidence_value)
			confidence = max(0.0, min(1.0, confidence))
		except ValueError:
			confidence = fallback_confidence

		return severity, confidence
