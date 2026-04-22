from __future__ import annotations

import logging
from dataclasses import dataclass

from ai.llm_client import LLMClient, LLMRequest
from data.models import Allnsight, Endpoint, ScanResult, Vulnerability


LOGGER = logging.getLogger(__name__)
AIInsight = Allnsight


@dataclass(slots=True)
class PayloadGenerator:
	llm_client: LLMClient
	prompt_template: str
	constraints: list[str]
	max_payloads_per_vuln: int
	min_ai_confidence: float

	def enhance(self, endpoint: Endpoint, scan_result: ScanResult) -> tuple[list[Vulnerability], list[AIInsight]]:
		enriched_vulnerabilities: list[Vulnerability] = []
		insights: list[AIInsight] = []

		for vulnerability in scan_result.vulnerabilities:
			if vulnerability.endpoint != endpoint:
				continue

			llm_request = self._build_request(endpoint=endpoint, vulnerability=vulnerability)
			llm_response = self.llm_client.generate(llm_request)

			if llm_response.confidence < self.min_ai_confidence:
				LOGGER.debug("Skipping low-confidence payload suggestions for %s", endpoint.url)
				enriched_vulnerabilities.append(vulnerability)
				continue

			candidate_payloads = self._parse_payload_lines(llm_response.content)
			merged_payloads = self._merge_payloads(
				existing_payloads=vulnerability.payloads,
				candidate_payloads=candidate_payloads,
			)
			enriched = Vulnerability(
				vuln_type=vulnerability.vuln_type,
				endpoint=vulnerability.endpoint,
				severity=vulnerability.severity,
				payloads=merged_payloads,
				evidence=list(vulnerability.evidence),
				confidence=max(vulnerability.confidence, llm_response.confidence),
			)
			enriched_vulnerabilities.append(enriched)
			insights.append(
				AIInsight(
					description="AI suggested additional payload variants for an existing finding.",
					confidence=llm_response.confidence,
					related_vuln=enriched,
				)
			)

		return enriched_vulnerabilities, insights

	def _build_request(self, endpoint: Endpoint, vulnerability: Vulnerability) -> LLMRequest:
		context = {
			"endpoint": endpoint.to_dict(),
			"vulnerability": vulnerability.to_dict(),
			"safe_testing_mode": True,
			"instruction": "Enhance payloads for an existing finding only.",
		}
		prompt = self.prompt_template.format(
			vuln_type=vulnerability.vuln_type,
			endpoint_url=endpoint.url,
			existing_payloads=", ".join(vulnerability.payloads),
		)
		return LLMRequest(prompt=prompt, context=context, constraints=list(self.constraints))

	def _parse_payload_lines(self, content: str) -> list[str]:
		payloads: list[str] = []
		for raw_line in content.splitlines():
			payload = raw_line.strip().lstrip("- ").strip()
			if payload:
				payloads.append(payload)
		return payloads

	def _merge_payloads(self, existing_payloads: list[str], candidate_payloads: list[str]) -> list[str]:
		seen: set[str] = set(existing_payloads)
		merged = list(existing_payloads)

		for payload in candidate_payloads:
			if payload in seen:
				continue
			merged.append(payload)
			seen.add(payload)
			if len(merged) >= self.max_payloads_per_vuln:
				break

		return merged
