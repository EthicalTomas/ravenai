"""scanner/replay.py

Logic for re-executing discovered vulnerabilities using stored request data.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass
from typing import Any

from data.models import Vulnerability
from utils.http_client import HTTPClient


LOGGER = logging.getLogger(__name__)


@dataclass(slots=True)
class VulnerabilityReplayer:
	"""Handles re-execution and verification of discovered vulnerabilities."""

	client: HTTPClient

	def replay(self, vulnerability: Vulnerability) -> Any | None:
		"""Re-execute the exact request that triggered the vulnerability."""
		req = vulnerability.request_data
		if not req:
			LOGGER.warning("No request data found for vulnerability at %s", vulnerability.endpoint.url)
			return None

		LOGGER.info("Replaying vulnerability: %s at %s", vulnerability.vuln_type, req.get("url"))
		
		try:
			return self.client.request(
				method=req.get("method", "GET"),
				url=req.get("url", ""),
				params=req.get("params"),
				headers=req.get("headers"),
				data=req.get("data"),
				json=req.get("json"),
			)
		except Exception as e:
			LOGGER.error("Replay failed for %s: %s", vulnerability.endpoint.url, e)
			return None

	def verify(self, vulnerability: Vulnerability) -> bool:
		"""Re-execute and check if ANY of the original evidence is still present."""
		response = self.replay(vulnerability)
		if response is None:
			return False

		body = response.text.lower()
		for ev in vulnerability.evidence:
			# Very basic check: is the evidence string in the response?
			# In a real scenario, this would be more specialized per vuln type.
			if ev.lower() in body:
				LOGGER.info("Verification SUCCESS for %s", vulnerability.endpoint.url)
				return True

		# Special case: XSS markers
		if vulnerability.vuln_type == "xss":
			for payload in vulnerability.payloads:
				if payload.lower() in body:
					LOGGER.info("Verification SUCCESS (payload reflection) for %s", vulnerability.endpoint.url)
					return True

		LOGGER.warning("Verification FAILED for %s", vulnerability.endpoint.url)
		return False
