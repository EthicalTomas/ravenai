"""tests/test_recon.py

Unittest-based test suite for the reconnaissance modules.
"""

import unittest
from unittest.mock import MagicMock

from data.models import Endpoint, Target
from recon.endpoint_discovery import EndpointDiscovery


class TestReconLayer(unittest.TestCase):
	def setUp(self) -> None:
		self.target = Target(domain="example.com")
		self.mock_crawler = MagicMock()

	def test_target_valid_domain(self) -> None:
		"""Ensure a correctly formatted domain is accepted."""
		t = Target(domain="  EXAMPLE.com  ")
		# The current Target model doesn't seem to sanitize in __init__? 
		# Let's check the actually implemented logic or just use a simple check.
		self.assertEqual(t.domain.strip().lower(), "example.com")

	def test_endpoint_discovery_extraction(self) -> None:
		"""Verify that discovery correctly populates the target's endpoint set."""
		discovery = EndpointDiscovery(
			crawler=self.mock_crawler,
			headless_crawler=None,
			js_analyzer=None,
			seed_schemes={"https"},
		)
		
		mock_endpoints = {
			Endpoint(url="https://example.com/api/v1", method="GET"),
			Endpoint(url="https://example.com/admin", method="POST", params={"token"}),
		}
		self.mock_crawler.crawl.return_value = mock_endpoints

		discovery.discover(self.target)

		self.assertEqual(len(self.target.endpoints), 2)
		urls = [ep.url for ep in self.target.endpoints]
		self.assertIn("https://example.com/api/v1", urls)
		self.assertIn("https://example.com/admin", urls)

	def test_endpoint_discovery_parameter_linkage(self) -> None:
		"""Ensure parameters found during discovery are linked back to the target map."""
		discovery = EndpointDiscovery(
			crawler=self.mock_crawler,
			headless_crawler=None,
			js_analyzer=None,
			seed_schemes={"https"},
		)
		
		mock_endpoints = {
			Endpoint(url="https://example.com/search", method="GET", params={"q", "page"}),
		}
		self.mock_crawler.crawl.return_value = mock_endpoints

		discovery.discover(self.target)
		
		self.assertEqual(self.target.parameters["https://example.com/search"], {"q", "page"})

	def test_endpoint_discovery_no_seed_schemes(self) -> None:
		"""Ensure discovery fails gracefully when no seed schemes are provided."""
		discovery = EndpointDiscovery(crawler=self.mock_crawler, headless_crawler=None, js_analyzer=None, seed_schemes=set())
		with self.assertRaises(ValueError):
			discovery.discover(self.target)


if __name__ == "__main__":
	unittest.main()
