from __future__ import annotations

import logging
from dataclasses import dataclass

from data.models import ScanResult, Vulnerability


LOGGER = logging.getLogger(__name__)


@dataclass(slots=True)
class RiskScorer:
	severity_weights: dict[str, float]

	def score(self, scan_result: ScanResult) -> ScanResult:
		vulnerability_scores: dict[str, float] = {}
		total = 0.0

		for vulnerability in scan_result.vulnerabilities:
			score = self._score_vulnerability(vulnerability)
			key = self._vulnerability_key(vulnerability)
			vulnerability_scores[key] = score
			total += score

		average = total / len(scan_result.vulnerabilities) if scan_result.vulnerabilities else 0.0
		metadata = dict(scan_result.metadata)
		metadata["risk_scores"] = vulnerability_scores
		metadata["risk_total"] = round(total, 4)
		metadata["risk_average"] = round(average, 4)

		LOGGER.info("Calculated risk score total=%s average=%s", metadata["risk_total"], metadata["risk_average"])
		return ScanResult(
			vulnerabilities=list(scan_result.vulnerabilities),
			raw_outputs=list(scan_result.raw_outputs),
			metadata=metadata,
		)

	def _score_vulnerability(self, vulnerability: Vulnerability) -> float:
		base = self.severity_weights.get(vulnerability.severity.lower(), 1.0)
		confidence = max(0.0, min(1.0, vulnerability.confidence))
		payload_bonus = min(1.0, len(vulnerability.payloads) * 0.1)
		evidence_bonus = min(1.0, len(vulnerability.evidence) * 0.05)
		return round(base * confidence + payload_bonus + evidence_bonus, 4)

	def _vulnerability_key(self, vulnerability: Vulnerability) -> str:
		endpoint = vulnerability.endpoint
		return f"{vulnerability.vuln_type}:{endpoint.method}:{endpoint.url}"
