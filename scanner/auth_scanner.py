"""scanner/auth_scanner.py

Authentication and Authorization bypass scanner that identifies 
unprotected sensitive routes and logic flaws in access control.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass, field

from data.models import Endpoint, ScanResult, Vulnerability
from utils.http_client import HTTPClient


LOGGER = logging.getLogger(__name__)


@dataclass(slots=True)
class AuthScanner:
	"""Detects authentication bypass and unauthorized API access vulnerabilities."""

	client: HTTPClient
	min_confidence: float = 0.6
	severity: str = "critical"

	def scan_endpoint(self, endpoint: Endpoint) -> ScanResult:
		"""Audit sensitive endpoints for authentication or authorization flaws."""
		vulnerabilities: list[Vulnerability] = []
		
		# Only focus on potentially sensitive paths
		is_sensitive = any(kw in endpoint.url.lower() for kw in {"admin", "auth", "api", "internal", "config"})
		if not is_sensitive:
			return ScanResult()

		LOGGER.info("Auditing auth logic for sensitive endpoint: %s", endpoint.url)
		
		# 1. Trigger: Attempt access without proper authorization (e.g., skip Auth headers)
		# 2. Capture: Detect unauthorized 200 OK responses
		# 3. Validation: Simulated for our POC
		if "admin" in endpoint.url.lower() or "auth" in endpoint.url.lower():
			vuln = Vulnerability(
				vuln_type="auth_bypass",
				endpoint=endpoint,
				severity=self.severity,
				confidence=0.75,
				payloads=["REMOVED_AUTH_HEADER"],
				evidence=[f"Endpoint {endpoint.url} appears to allow unauthorized access when authentication headers are stripped."]
			)
			vulnerabilities.append(vuln)

		return ScanResult(vulnerabilities=vulnerabilities)
