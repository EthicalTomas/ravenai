from __future__ import annotations

import logging
from collections import deque
from dataclasses import dataclass, field
from typing import Any, Iterable
from urllib.parse import parse_qs, urljoin, urlparse, urlunparse

from bs4 import BeautifulSoup
from data.models import Endpoint
from utils.http_client import HTTPClient


LOGGER = logging.getLogger(__name__)


@dataclass(slots=True)
class BasicCrawler:
	client: HTTPClient
	max_pages: int
	allowed_schemes: set[str] = field(default_factory=set)

	def crawl(self, seed_urls: set[str], allowed_hosts: set[str]) -> set[Endpoint]:
		if self.max_pages <= 0:
			raise ValueError("max_pages must be greater than 0")
		if not seed_urls:
			return set()

		endpoints: set[Endpoint] = set()
		queue: deque[str] = deque()
		visited: set[str] = set()

		for seed_url in seed_urls:
			normalized_seed = self._normalize_url(seed_url)
			queue.append(normalized_seed)

		while queue and len(visited) < self.max_pages:
			current_url = queue.popleft()
			if current_url in visited:
				continue
			visited.add(current_url)

			parsed = urlparse(current_url)
			if parsed.hostname is None or parsed.hostname not in allowed_hosts:
				LOGGER.debug("Skipping out-of-scope URL: %s", current_url)
				continue
			if self.allowed_schemes and parsed.scheme not in self.allowed_schemes:
				LOGGER.debug("Skipping unsupported scheme URL: %s", current_url)
				continue

			response = self._safe_get(current_url)
			endpoint = self._endpoint_from_url(current_url)
			endpoints.add(endpoint)

			if response is None:
				continue
			if "text/html" not in response.headers.get("Content-Type", ""):
				continue

			for discovered_url in self._extract_links(base_url=current_url, html=response.text):
				normalized_url = self._normalize_url(discovered_url)
				parsed_discovered = urlparse(normalized_url)
				if parsed_discovered.hostname in allowed_hosts and normalized_url not in visited:
					queue.append(normalized_url)

		LOGGER.info("Crawler discovered %d unique endpoints", len(endpoints))
		return endpoints

	def _safe_get(self, url: str) -> Any | None:
		try:
			return self.client.request(
				method="GET",
				url=url,
			)
		except Exception:
			LOGGER.debug("Failed to fetch URL: %s", url)
			return None

	def _extract_links(self, base_url: str, html: str) -> set[str]:
		soup = BeautifulSoup(html, "html.parser")
		links: set[str] = set()

		for anchor in soup.find_all("a", href=True):
			href = str(anchor["href"]).strip()
			if not href:
				continue
			absolute_url = urljoin(base_url, href)
			links.add(absolute_url)

		for form in soup.find_all("form"):
			action = str(form.get("action", "")).strip()
			if action:
				links.add(urljoin(base_url, action))

		return links

	def _normalize_url(self, url: str) -> str:
		parsed = urlparse(url)
		normalized_path = parsed.path or "/"
		normalized = parsed._replace(fragment="", path=normalized_path)
		return urlunparse(normalized)

	def _endpoint_from_url(self, url: str) -> Endpoint:
		parsed = urlparse(url)
		query_params = set(parse_qs(parsed.query).keys())
		clean_url = urlunparse(parsed._replace(query="", fragment=""))
		return Endpoint(url=clean_url, method="GET", params=query_params, headers={})
