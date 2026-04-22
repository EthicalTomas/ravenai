from __future__ import annotations

import unittest

from ai.llm_client import CallableLLMClient, LLMRequest, LLMResponse
from ai.payload_generator import PayloadGenerator
from ai.response_analyzer import ResponseAnalyzer
from ai.vuln_classifier import VulnerabilityClassifier
from data.models import Endpoint, ScanResult, Vulnerability


def _fake_completion(request: LLMRequest) -> LLMResponse:
	if "output_format" in request.context:
		return LLMResponse(content="severity=high\nconfidence=0.9", confidence=0.9)
	if "enhance payloads" in str(request.context.get("instruction", "")).lower():
		return LLMResponse(content="- new_payload_1\n- new_payload_2", confidence=0.8)
	return LLMResponse(content="Evidence is consistent with the existing finding.", confidence=0.75)


class TestAILayer(unittest.TestCase):
	def setUp(self) -> None:
		self.client = CallableLLMClient(provider_name="test", completion_callable=_fake_completion)
		self.endpoint = Endpoint(url="https://example.com/search", method="GET", params={"q"})
		self.vulnerability = Vulnerability(
			vuln_type="xss",
			endpoint=self.endpoint,
			severity="medium",
			payloads=["base_payload"],
			evidence=["reflected string"],
			confidence=0.6,
		)
		self.scan_result = ScanResult(vulnerabilities=[self.vulnerability])

	def test_payload_generator_enhances_existing_finding(self) -> None:
		generator = PayloadGenerator(
			llm_client=self.client,
			prompt_template="Enhance payloads for {vuln_type} at {endpoint_url}: {existing_payloads}",
			constraints=["existing findings only"],
			max_payloads_per_vuln=5,
			min_ai_confidence=0.5,
		)

		enriched, insights = generator.enhance(self.endpoint, self.scan_result)

		self.assertEqual(len(enriched), 1)
		self.assertIn("base_payload", enriched[0].payloads)
		self.assertIn("new_payload_1", enriched[0].payloads)
		self.assertEqual(len(insights), 1)

	def test_response_analyzer_returns_insight_for_existing_finding(self) -> None:
		analyzer = ResponseAnalyzer(
			llm_client=self.client,
			prompt_template="Analyze {vuln_type} at {endpoint_url}",
			constraints=["no hallucination"],
			min_ai_confidence=0.5,
		)

		insights = analyzer.analyze(self.endpoint, self.scan_result)

		self.assertEqual(len(insights), 1)
		self.assertIsNotNone(insights[0].related_vuln)
		self.assertIn("existing finding", insights[0].description.lower())

	def test_vulnerability_classifier_enriches_existing_finding_only(self) -> None:
		classifier = VulnerabilityClassifier(
			llm_client=self.client,
			prompt_template="Classify {vuln_type} at {endpoint_url} severity={current_severity}",
			constraints=["existing findings only"],
			allowed_severities={"low", "medium", "high", "critical"},
			min_ai_confidence=0.5,
		)

		enriched = classifier.classify(self.endpoint, self.scan_result)

		self.assertEqual(len(enriched), 1)
		self.assertEqual(enriched[0].severity, "high")
		self.assertGreaterEqual(enriched[0].confidence, self.vulnerability.confidence)


if __name__ == "__main__":
	unittest.main()
