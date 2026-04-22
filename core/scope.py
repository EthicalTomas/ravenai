"""core/scope.py

Logic for determining if a URL or Domain is within the authorized scope of a scan.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass
from urllib.parse import urlparse

from data.models import Target


LOGGER = logging.getLogger(__name__)


@dataclass(slots=True)
class ScopeManager:
	"""Enforces whitelist/blacklist rules for targets and discovery."""

	target: Target

	def is_allowed(self, url: str) -> bool:
		"""Check if a URL is within the target's authorized scope."""
		try:
			parsed = urlparse(url)
			host = parsed.hostname
			if not host:
				return False

			# 1. Host-based whitelist
			allowed = False
			for domain in self.target.scope_rules.allowed_domains:
				if host == domain or host.endswith(f".{domain}"):
					allowed = True
					break
			
			if not allowed:
				return False

			# 2. Host-based blacklist
			for domain in self.target.scope_rules.excluded_domains:
				if host == domain or host.endswith(f".{domain}"):
					return False

			return True

		except Exception:
			return False

	def filter(self, urls: set[str]) -> set[str]:
		"""Filter a set of URLs, returning only those within scope."""
		return {u for u in urls if self.is_allowed(u)}