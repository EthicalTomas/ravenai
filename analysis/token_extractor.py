"""analysis/token_extractor.py

Extraction of sensitive tokens, API keys, and session identifiers from 
HTTP responses, headers, and cookies to fuel logical exploit chaining.
"""

from __future__ import annotations

import logging
import re
from dataclasses import dataclass, field
from datetime import datetime
from typing import Any

from data.models import Endpoint, ScanResult, Vulnerability


LOGGER = logging.getLogger(__name__)


@dataclass(slots=True, frozen=True)
class ExtractedToken:
	"""Structured representation of a discovered token or secret."""
	value: str
	token_type: str  # jwt, api_key, session, etc.
	source: str      # body, header, cookie
	source_url: str
	captured_at: str = field(default_factory=lambda: datetime.now().isoformat())
	metadata: dict[str, Any] = field(default_factory=dict)


@dataclass(slots=True)
class TokenExtractor:
	"""Identifies and extracts sensitive tokens from scan interactions."""

	# Common token and secret patterns
	_patterns: dict[str, re.Pattern] = field(default_factory=lambda: {
		"jwt": re.compile(r'eyJ[a-zA-Z0-9_-]{10,}\.eyJ[a-zA-Z0-9_-]{10,}\.[a-zA-Z0-9_-]{10,}'),
		"api_key": re.compile(r'(?:api_key|apikey|secret|token|auth)["\']?\s*[:=]\s*["\']?([a-zA-Z0-9_\-]{16,})["\']?', re.I),
		"bearer": re.compile(r'Bearer\s+([a-zA-Z0-9_\-\.]{16,})', re.I),
		"generic_hex": re.compile(r'["\']([a-fA-S0-9]{32,64})["\']', re.I),
	})

	def extract_all(self, endpoint: Endpoint, response_text: str, headers: dict[str, str], cookies: dict[str, str]) -> list[ExtractedToken]:
		"""Extract tokens from all available interaction surfaces."""
		tokens: list[ExtractedToken] = []
		
		# 1. Extract from Body
		tokens.extend(self._extract_from_body(response_text, endpoint.url))
		
		# 2. Extract from Headers
		tokens.extend(self._extract_from_headers(headers, endpoint.url))
		
		# 3. Extract from Cookies
		tokens.extend(self._extract_from_cookies(cookies, endpoint.url))
		
		return self._deduplicate(tokens)

	def _extract_from_body(self, text: str, url: str) -> list[ExtractedToken]:
		found: list[ExtractedToken] = []
		for t_type, pattern in self._patterns.items():
			matches = pattern.findall(text)
			for val in matches:
				# findall returns tuple for groups, or string for no groups
				token_val = val[0] if isinstance(val, tuple) else val
				found.append(ExtractedToken(value=token_val, token_type=t_type, source="body", source_url=url))
		return found

	def _extract_from_headers(self, headers: dict[str, str], url: str) -> list[ExtractedToken]:
		found: list[ExtractedToken] = []
		sensitive_headers = {"Authorization", "X-Auth-Token", "X-API-Key", "X-Session-ID", "Token"}
		
		for h_name, h_val in headers.items():
			# Check against sensitive header names
			if any(s.lower() in h_name.lower() for s in sensitive_headers):
				# Also applies Bearer regex to the value if needed
				bearer_match = self._patterns["bearer"].search(h_val)
				token_val = bearer_match.group(1) if bearer_match else h_val
				found.append(ExtractedToken(value=token_val, token_type="header_token", source="header", source_url=url))
		return found

	def _extract_from_cookies(self, cookies: dict[str, str], url: str) -> list[ExtractedToken]:
		found: list[ExtractedToken] = []
		sensitive_cookies = {"session", "token", "auth", "jwt", "id", "key"}
		
		for c_name, c_val in cookies.items():
			if any(s.lower() in c_name.lower() for s in sensitive_cookies):
				found.append(ExtractedToken(value=c_val, token_type="cookie_token", source="cookie", source_url=url))
		return found

	def _deduplicate(self, tokens: list[ExtractedToken]) -> list[ExtractedToken]:
		seen: set[str] = set()
		unique: list[ExtractedToken] = []
		for t in tokens:
			if t.value not in seen:
				unique.append(t)
				seen.add(t.value)
		return unique
