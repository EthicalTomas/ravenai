from __future__ import annotations

import logging
from dataclasses import dataclass
from urllib.parse import urlparse

from data.models import Target
from recon.crawler import BasicCrawler
from recon.headless_crawler import HeadlessCrawler
from recon.js_analyzer import JSAnalyzer


LOGGER = logging.getLogger(__name__)


@dataclass(slots=True)
class EndpointDiscovery:
	"""Central orchestrator for discovering target endpoints and parameters."""

	crawler: BasicCrawler
	headless_crawler: HeadlessCrawler | None
	js_analyzer: JSAnalyzer | None
	seed_schemes: set[str]

	def discover(self, target: Target) -> Target:
		"""Unify all discovery sources (Static, Headless, JS) for a target."""
		if not self.seed_schemes:
			raise ValueError("seed_schemes must contain at least one scheme")

		allowed_hosts = self._build_allowed_hosts(target)
		seed_urls = list(self._build_seed_urls(allowed_hosts))

		# 1. Static Crawling
		LOGGER.info("Starting static crawl for target: %s", target.domain)
		static_endpoints = self.crawler.crawl(seed_urls=seed_urls, allowed_hosts=allowed_hosts)
		for ep in static_endpoints:
			target.endpoints.add(ep)

		# 2. Headless Crawling (JS-heavy apps)
		if self.headless_crawler:
			LOGGER.info("Starting headless crawl for target: %s", target.domain)
			self.headless_crawler.crawl(target, seed_urls=seed_urls)

		# 3. JS Deep Analysis (Hidden routes)
		if self.js_analyzer:
			LOGGER.info("Starting JS deep analysis for target: %s", target.domain)
			# Find all potential JS files found so far
			js_files = [ep for ep in target.endpoints if ep.url.endswith(".js")]
			for js_ep in js_files:
				# In a real run, we would fetch the content. 
				# For the pipeline integration, we'll try to get it via crawler's cache if available, 
				# or simulate a single fetch.
				try:
					# We use the crawler's client to fetch JS if not already analyzed
					# (Simplified for POC integration)
					response = self.crawler.client.request("GET", js_ep.url)
					if response:
						self.js_analyzer.analyze_js(response.text, js_ep.url, target)
				except Exception as e:
					LOGGER.warning("Could not analyze JS at %s: %s", js_ep.url, e)

		# 4. Final Parameter Map Update
		for endpoint in target.endpoints:
			if endpoint.params:
				target.add_parameter_values(endpoint.url, endpoint.params)

		LOGGER.info("Discovery complete. Total endpoints identified: %d", len(target.endpoints))
		return target

	def _build_allowed_hosts(self, target: Target) -> set[str]:
		hosts: set[str] = {target.domain.lower()}
		hosts.update(subdomain.lower() for subdomain in target.subdomains)
		return hosts

	def _build_seed_urls(self, allowed_hosts: set[str]) -> set[str]:
		seed_urls: set[str] = set()
		for host in allowed_hosts:
			if urlparse(host).scheme:
				parsed = urlparse(host)
				if parsed.hostname:
					for scheme in self.seed_schemes:
						seed_urls.add(f"{scheme}://{parsed.hostname}")
				continue

			for scheme in self.seed_schemes:
				seed_urls.add(f"{scheme}://{host}")
		return seed_urls
