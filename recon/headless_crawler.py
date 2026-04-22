"""recon/headless_crawler.py

Headless browser crawler using Playwright to discover JavaScript-rendered 
routes and intercepted API calls (XHR/Fetch).
"""

from __future__ import annotations

import logging
from dataclasses import dataclass, field
from typing import Any
from urllib.parse import urljoin, urlparse

try:
	from playwright.sync_api import sync_playwright, Request, Page, BrowserContext
except ImportError:
	# Fallback if playwright is not installed; will log error on use
	sync_playwright = None

from data.models import Endpoint, Target
from utils.parser import ResponseParser, ParsedURL


LOGGER = logging.getLogger(__name__)


@dataclass(slots=True)
class HeadlessCrawler:
	"""Crawls targets using a headless browser to discover dynamic routes."""

	timeout_ms: int = 30000
	user_agent: str = "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/RavenAI"
	headless: bool = True
	_discovered_endpoints: set[Endpoint] = field(default_factory=set, init=False)

	def crawl(self, target: Target, seed_urls: list[str] | None = None) -> set[Endpoint]:
		"""Execute headless crawl of the target starting from seed URLs."""
		if not sync_playwright:
			LOGGER.error("Playwright not installed. HeadlessCrawler cannot run.")
			return set()

		seeds = seed_urls or list(target.subdomains) or [target.domain]
		
		try:
			with sync_playwright() as p:
				try:
					browser = p.chromium.launch(headless=self.headless)
					context = browser.new_context(user_agent=self.user_agent)
					
					for url in seeds:
						# Ensure protocol
						if not url.startswith(("http://", "https://")):
							url = f"https://{url}"
						
						self._crawl_page(context, url, target)
					
					browser.close()
				except Exception as inner_exc:
					LOGGER.error("Browser process error during crawl: %s", inner_exc)
					# Partial results are still stored in self._discovered_endpoints
		except Exception as outer_exc:
			LOGGER.critical("Terminal failure in headless crawler initialization: %s", outer_exc)
			return set()

		# Final merge into target
		new_count = 0
		for ep in self._discovered_endpoints:
			if ep not in target.endpoints:
				target.endpoints.add(ep)
				new_count += 1
		
		LOGGER.info("Headless crawl complete. Found %d total endpoints (%d new).", 
					len(self._discovered_endpoints), new_count)
		
		return self._discovered_endpoints

	def _crawl_page(self, context: BrowserContext, url: str, target: Target) -> None:
		"""Single page crawl logic: navigation and extraction."""
		LOGGER.info("Headless visiting: %s", url)
		page = context.new_page()
		
		# Register network interception to find API calls
		page.on("request", lambda request: self._handle_request_interception(request, target))
		
		try:
			page.goto(url, wait_until="networkidle", timeout=self.timeout_ms)
			
			# 1. Extract rendered links from DOM
			links = page.eval_on_selector_all("a[href]", "elements => elements.map(el => el.href)")
			for link_url in links:
				self._add_endpoint_if_in_scope(link_url, "GET", target)
			
			# 2. Extract dynamic routes from common JS patterns or data attributes
			# (Optional extension: clicking buttons/forms or scroll-to-load)
			
		except Exception as exc:
			LOGGER.warning("Failed to crawl %s: %s", url, exc)
		finally:
			page.close()

	def _handle_request_interception(self, request: Request, target: Target) -> None:
		"""Intercept XHR/Fetch/Dynamic requests made by the page's JS."""
		try:
			if request.resource_type in ["fetch", "xhr"]:
				url = request.url
				method = request.method
				headers = dict(request.headers)
				
				self._add_endpoint_if_in_scope(url, method, target, headers)
		except Exception:
			pass

	def _add_endpoint_if_in_scope(self, url: str, method: str, target: Target, headers: dict[str, str] | None = None) -> None:
		"""Validate, normalize, and store discovered endpoints if they belong to the target."""
		try:
			parsed = urlparse(url)
			host = parsed.hostname
			if not host:
				return

			# Scope check: Must be target domain or authorized subdomain
			if not (host == target.domain or host.endswith(f".{target.domain}")):
				return

			# Extract params from URL
			query_params = set()
			if parsed.query:
				from urllib.parse import parse_qs
				query_params = set(parse_qs(parsed.query).keys())

			endpoint = Endpoint(
				url=url.split('?')[0].split('#')[0],  # Normalized base path
				method=method.upper(),
				params=query_params,
				headers=headers or {}
			)
			
			self._discovered_endpoints.add(endpoint)
		except Exception:
			pass
