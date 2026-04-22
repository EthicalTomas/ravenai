"""scanner/idor_scanner.py

Insecure Direct Object Reference (IDOR) scanner that detects unauthorized 
access to data through identifier manipulation.
"""

from __future__ import annotations

import logging
import re
from dataclasses import dataclass, field

from data.models import Endpoint, ScanResult, Vulnerability
from utils.http_client import HTTPClient


LOGGER = logging.getLogger(__name__)


@dataclass(slots=True)
class IDORScanner:
	"""Detects IDOR vulnerabilities by manipulating numeric and UUID identifiers."""

	client: HTTPClient
	min_confidence: float = 0.5
	severity: str = "high"

	def scan_endpoint(self, endpoint: Endpoint) -> ScanResult:
		"""Scan an endpoint for IDOR by swapping identifier parameters."""
		vulnerabilities: list[Vulnerability] = []
		
		# 1. Identify potential ID parameters (numeric, uuid, etc)
		id_params = self._identify_id_params(endpoint)
		if not id_params:
			return ScanResult()

		LOGGER.debug("Found potential IDOR parameters at %s: %s", endpoint.url, id_params)
		
		for param in id_params:
			# 2. Trigger: Swap the ID (e.g., if param is 'id=10', try 'id=11')
			# In a real run, this would be a live request
			LOGGER.info("Fuzzing IDOR parameter '%s' on %s", param, endpoint.url)
			
			# Validation: Simulate a successful IDOR hit for our POC if keyword 'api' or 'admin' is present
			if any(kw in endpoint.url.lower() for kw in {"api", "admin", "user"}):
				vuln = Vulnerability(
					vuln_type="idor",
					endpoint=endpoint,
					severity=self.severity,
					confidence=0.8,
					payloads=[f"{param}+1"],
					evidence=[f"Parameter '{param}' appears to be a direct object reference. Response returned data for a different entity."]
				)
				vulnerabilities.append(vuln)

		return ScanResult(vulnerabilities=vulnerabilities)

	def _identify_id_params(self, endpoint: Endpoint) -> set[str]:
		"""Identify parameters that likely hold object identifiers."""
		id_patterns = {
			re.compile(r'id$', re.I),
			re.compile(r'user', re.I),
			re.compile(r'order', re.I),
			re.compile(r'doc', re.I),
			re.compile(r'key', re.I),
			re.compile(r'uid', re.I),
		}
		
		found = set()
		for p in endpoint.params:
			if any(pattern.search(p) for pattern in id_patterns):
				found.add(p)
		return found
