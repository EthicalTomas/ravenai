from __future__ import annotations

import unittest

from data.models import Allnsight, Endpoint, ScanResult, Target, Vulnerability


class TestDataModels(unittest.TestCase):
	def test_endpoint_hash_prevents_duplicates(self) -> None:
		first = Endpoint(url="https://example.com/search", method="get", params={"q"}, headers={"A": "1"})
		second = Endpoint(url="https://example.com/search", method="GET", params={"q"}, headers={"A": "1"})

		endpoint_set = {first, second}
		self.assertEqual(len(endpoint_set), 1)

	def test_target_to_dict_keeps_structured_content(self) -> None:
		endpoint = Endpoint(url="https://example.com/profile", method="GET", params={"id"})
		target = Target(domain="example.com")
		target.subdomains.update({"api.example.com", "www.example.com"})
		target.add_endpoint(endpoint)
		target.add_parameter_values("id", {"https://example.com/profile"})

		serialized = target.to_dict()
		self.assertEqual(serialized["domain"], "example.com")
		self.assertIn("api.example.com", serialized["subdomains"])
		self.assertEqual(serialized["endpoints"][0]["url"], "https://example.com/profile")
		self.assertEqual(serialized["parameters"]["id"], ["https://example.com/profile"])

	def test_scan_result_and_ai_insight_serialization(self) -> None:
		endpoint = Endpoint(url="https://example.com/search", method="GET", params={"q"})
		vulnerability = Vulnerability(
			vuln_type="xss",
			endpoint=endpoint,
			severity="medium",
			payloads=["<script>alert(1)</script>"],
			evidence=["reflected response"],
			confidence=0.8,
		)
		scan_result = ScanResult(vulnerabilities=[vulnerability], raw_outputs=["tool output"], metadata={"m": 1})
		insight = Allnsight(description="related finding", confidence=0.7, related_vuln=vulnerability)

		serialized_scan = scan_result.to_dict()
		serialized_insight = insight.to_dict()

		self.assertEqual(serialized_scan["vulnerabilities"][0]["vuln_type"], "xss")
		self.assertEqual(serialized_scan["metadata"]["m"], 1)
		self.assertEqual(serialized_insight["related_vuln"]["severity"], "medium")


if __name__ == "__main__":
	unittest.main()