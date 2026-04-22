"""analysis/deduplicator.py

Consolidation of duplicate vulnerabilities and endpoints through 
advanced URL and parameter normalization and stable fingerprinting.
"""

from __future__ import annotations

import hashlib
import logging
from dataclasses import dataclass
from urllib.parse import urlparse, urlunparse, parse_qsl, urlencode

from data.models import ScanResult, Vulnerability, Endpoint


LOGGER = logging.getLogger(__name__)


@dataclass(slots=True)
class Deduplicator:
	"""Normalizes and merges duplicate findings based on surface-area fingerprints."""

	def deduplicate(self, scan_result: ScanResult) -> ScanResult:
		"""Group and merge vulnerabilities by canonical signature."""
		if not scan_result.vulnerabilities:
			return scan_result

		unique_findings: dict[str, Vulnerability] = {}
		
		for vuln in scan_result.vulnerabilities:
			fingerprint = self._generate_fingerprint(vuln)
			
			if fingerprint in unique_findings:
				existing = unique_findings[fingerprint]
				unique_findings[fingerprint] = self._merge_findings(existing, vuln)
			else:
				unique_findings[fingerprint] = vuln

		deduplicated = list(unique_findings.values())
		
		metadata = dict(scan_result.metadata)
		metadata["original_count"] = len(scan_result.vulnerabilities)
		metadata["deduplicated_count"] = len(deduplicated)
		
		LOGGER.info("Deduplicated findings: %d -> %d", len(scan_result.vulnerabilities), len(deduplicated))

		return ScanResult(
			vulnerabilities=deduplicated,
			raw_outputs=list(scan_result.raw_outputs),
			metadata=metadata
		)

	def _generate_fingerprint(self, vuln: Vulnerability) -> str:
		"""Generate a stable SHA-256 hash for a vulnerability based on its surface area."""
		norm_url = self._normalize_url(vuln.endpoint.url)
		norm_method = vuln.endpoint.method.upper()
		# Sort parameters to ensure order-independence
		norm_params = "|".join(sorted(vuln.endpoint.params))
		
		raw_sig = f"{vuln.vuln_type}:{norm_method}:{norm_url}:{norm_params}"
		return hashlib.sha256(raw_sig.encode()).hexdigest()

	def _normalize_url(self, url: str) -> str:
		"""Canonicalize a URL: lower host, strip slash, sort query params."""
		try:
			parsed = urlparse(url)
			# Lowercase domain/netloc
			netloc = parsed.netloc.lower()
			# Strip trailing slashes from path
			path = parsed.path.rstrip('/') or '/'
			# Canonicalize query parameters (sort by key)
			query_list = sorted(parse_qsl(parsed.query))
			query = urlencode(query_list)
			
			# Reconstruct without redundant elements (ports if default, etc.)
			return urlunparse((parsed.scheme, netloc, path, parsed.params, query, parsed.fragment))
		except Exception:
			# Fallback if URL is malformed
			return url.lower().rstrip('/')

	def _merge_findings(self, left: Vulnerability, right: Vulnerability) -> Vulnerability:
		"""Consolidate two duplicate vulnerabilities into one high-confidence finding."""
		# Merge evidence and payloads (unique sets)
		merged_payloads = list(set(left.payloads) | set(right.payloads))
		merged_evidence = list(set(left.evidence) | set(right.evidence))
		
		return Vulnerability(
			vuln_type=left.vuln_type,
			endpoint=left.endpoint,  # Retain original endpoint for context
			severity=self._pick_highest_severity(left.severity, right.severity),
			payloads=merged_payloads,
			evidence=merged_evidence,
			confidence=max(left.confidence, right.confidence)
		)

	def _pick_highest_severity(self, s1: str, s2: str) -> str:
		"""Determine which severity value is more critical."""
		weights = {"critical": 4, "high": 3, "medium": 2, "low": 1, "info": 0}
		return s1 if weights.get(s1.lower(), 0) >= weights.get(s2.lower(), 0) else s2
