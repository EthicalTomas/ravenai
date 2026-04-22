from __future__ import annotations

import unittest
from unittest.mock import patch

from data.models import Endpoint, ScanResult, Target, Vulnerability
from scanner.fuzzing_engine import FuzzingEngine
from scanner.sqli_scanner import SQLiScanner
from scanner.xss_scanner import XSSScanner


class _MockResponse:
	def __init__(self, text: str, status_code: int = 200) -> None:
		self.text = text
		self.status_code = status_code


class _StaticScanner:
	def __init__(self, vulnerability: Vulnerability) -> None:
		self._vulnerability = vulnerability

	def scan_endpoint(self, endpoint: Endpoint) -> ScanResult:
		return ScanResult(vulnerabilities=[self._vulnerability], raw_outputs=[], metadata={"scanner": "static"})


class TestScannerLayer(unittest.TestCase):
	@patch("utils.http_client.HTTPClient.request")
	def test_xss_scanner_detects_reflection(self, mocked_request: object) -> None:
		mocked_request.return_value = _MockResponse(
			text="<html><body><script>alert(1)</script></body></html>",
			status_code=200,
		)

		from utils.http_client import HTTPClient, HTTPClientConfig
		scanner = XSSScanner(
			client=HTTPClient(HTTPClientConfig()),
			payloads=["<script>alert(1)</script>"],
			reflection_markers=["script"],
			min_confidence=0.6,
			severity="medium",
		)
		endpoint = Endpoint(url="https://example.com/search", method="GET", params={"q"})

		result = scanner.scan_endpoint(endpoint)

		self.assertEqual(len(result.vulnerabilities), 1)
		self.assertEqual(result.vulnerabilities[0].vuln_type, "xss")
		self.assertGreaterEqual(result.vulnerabilities[0].confidence, 0.6)

	@patch("utils.http_client.HTTPClient.request")
	def test_sqli_scanner_detects_error_signatures(self, mocked_request: object) -> None:
		mocked_request.return_value = _MockResponse(
			text="SQL syntax error near mysql_fetch_array",
			status_code=500,
		)

		from utils.http_client import HTTPClient, HTTPClientConfig
		scanner = SQLiScanner(
			client=HTTPClient(HTTPClientConfig()),
			payloads=["' OR '1'='1"],
			error_signatures=["sql syntax", "mysql"],
			min_confidence=0.6,
			severity="high",
		)
		endpoint = Endpoint(url="https://example.com/search", method="GET", params={"q"})

		result = scanner.scan_endpoint(endpoint)

		self.assertEqual(len(result.vulnerabilities), 1)
		self.assertEqual(result.vulnerabilities[0].vuln_type, "sqli")
		self.assertGreaterEqual(result.vulnerabilities[0].confidence, 0.6)

	def test_fuzzing_engine_parallel_aggregation(self) -> None:
		endpoint_one = Endpoint(url="https://example.com/a", method="GET", params={"q"})
		endpoint_two = Endpoint(url="https://example.com/b", method="GET", params={"id"})
		target = Target(domain="example.com", endpoints={endpoint_one, endpoint_two})

		vulnerability = Vulnerability(
			vuln_type="xss",
			endpoint=endpoint_one,
			severity="medium",
			payloads=["p"],
			evidence=["e"],
			confidence=0.8,
		)
		engine = FuzzingEngine(scanners=[_StaticScanner(vulnerability)], max_workers=2)

		result = engine.scan_target(target)

		self.assertEqual(result.metadata["endpoint_count"], 2)
		self.assertEqual(result.metadata["scanner_count"], 1)
		self.assertEqual(len(result.vulnerabilities), 2)


if __name__ == "__main__":
	unittest.main()
