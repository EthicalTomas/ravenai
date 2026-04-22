"""recon/js_analyzer.py

Static and dynamic analysis of JavaScript files to extract hidden API routes,
hardcoded endpoints, and parameter patterns in SPAs.
"""

from __future__ import annotations

import logging
import re
from dataclasses import dataclass, field
from urllib.parse import urljoin, urlparse

from data.models import Endpoint, Target


LOGGER = logging.getLogger(__name__)


@dataclass(slots=True)
class JSAnalyzer:
	"""Analyzes JS content to find hidden API endpoints and parameters."""

	# Patterns for discovering API routes and versioned endpoints
	_route_patterns: list[re.Pattern] = field(default_factory=lambda: [
		re.compile(r'["\'](/api/v\d+/[a-zA-Z0-9_\-/]*)["\']'),
		re.compile(r'["\'](/[a-zA-Z0-9_\-/]*api/[a-zA-Z0-9_\-/]*)["\']'),
		re.compile(r'["\'](/[a-zA-Z0-9_\-/\.]+)/?["\']'),  # Match potential internal paths
	])

	# Patterns for identifying potential parameters
	_param_patterns: list[re.Pattern] = field(default_factory=lambda: [
		re.compile(r'[?&]([a-zA-Z0-9_]+)=([\$\{\}a-zA-Z0-9_]*)'),
		re.compile(r'["\']([a-zA-Z0-9_]+)["\']:\s*["\']?'), # JSON-like keys (potential params)
	])

	def analyze_js(self, js_content: str, base_url: str, target: Target) -> set[Endpoint]:
		"""Parse JS source code for API endpoints and parameters."""
		endpoints: set[Endpoint] = set()
		
		# 1. Extract potential routes
		found_paths: set[str] = set()
		for pattern in self._route_patterns:
			matches = pattern.findall(js_content)
			for path in matches:
				if self._is_likely_route(path):
					found_paths.add(path)
		
		# 2. Extract potential parameters
		all_params: set[str] = set()
		for pattern in self._param_patterns:
			param_matches = pattern.findall(js_content)
			for p_name, p_val in param_matches:
				if len(p_name) > 1: # Basic noise filter
					all_params.add(p_name)

		# 3. Create Endpoint objects
		for path in found_paths:
			full_url = urljoin(base_url, path)
			
			# Scope check: Must be target domain or authorized subdomain
			parsed = urlparse(full_url)
			if parsed.hostname and (parsed.hostname == target.domain or parsed.hostname.endswith(f".{target.domain}")):
				
				# Attempt to link params to the correct path (heuristics)
				# For now, we attach all likely parameters found in the same file to the base route
				# as potential fuzzing targets.
				endpoint = Endpoint(
					url=full_url.split('?')[0].split('#')[0],
					method="GET", # Default for discovered routes
					params=all_params,
					headers={"X-Source": "JSAnalyzer"}
				)
				
				if endpoint not in target.endpoints:
					target.endpoints.add(endpoint)
					endpoints.add(endpoint)

		LOGGER.debug("JS analysis found %d potential endpoints from base=%s", len(endpoints), base_url)
		return endpoints

	def _is_likely_route(self, path: str) -> bool:
		"""Heuristic noise filter for candidate path strings."""
		# Filter out common static assets or file paths that are not API routes
		blacklist = {'.png', '.jpg', '.css', '.svg', '.json', '.js', '.woff2', '.html', 'utf-8'}
		if any(ext in path.lower() for ext in blacklist):
			return False
		
		# Must contain a slash and have reasonable length
		if '/' not in path or len(path) < 3:
			return False
			
		return True
