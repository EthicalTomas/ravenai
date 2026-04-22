from __future__ import annotations

from dataclasses import dataclass

from ai.llm_client import LLMClient, LLMRequest
from data.models import Allnsight, Endpoint, ScanResult


AIInsight = Allnsight


@dataclass(slots=True)
class ResponseAnalyzer:
	llm_client: LLMClient
	prompt_template: str
	constraints: list[str]
	min_ai_confidence: float

	def analyze(self, endpoint: Endpoint, scan_result: ScanResult) -> list[AIInsight]:
		insights: list[AIInsight] = []

		for vulnerability in scan_result.vulnerabilities:
			if vulnerability.endpoint != endpoint:
				continue

			request = LLMRequest(
				prompt=self.prompt_template.format(
					vuln_type=vulnerability.vuln_type,
					endpoint_url=endpoint.url,
				),
				context={
					"endpoint": endpoint.to_dict(),
					"vulnerability": vulnerability.to_dict(),
					"safe_testing_mode": True,
					"instruction": "Summarize and score evidence quality for this existing finding only.",
				},
				constraints=list(self.constraints),
			)
			response = self.llm_client.generate(request)
			if response.confidence < self.min_ai_confidence:
				continue

			insights.append(
				AIInsight(
					description=response.content.strip(),
					confidence=response.confidence,
					related_vuln=vulnerability,
				)
			)

		return insights
