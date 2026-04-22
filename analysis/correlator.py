from __future__ import annotations

import logging
from dataclasses import dataclass, field

from data.models import ScanResult, Vulnerability
from data.memory.vector_space import VectorSpace


LOGGER = logging.getLogger(__name__)


@dataclass(slots=True)
class CorrelationMap:
	vulnerabilities: dict[str, Vulnerability] = field(default_factory=dict)
	relationships: dict[str, set[str]] = field(default_factory=dict)

	def to_dict(self) -> dict[str, object]:
		return {
			"vulnerabilities": {key: value.to_dict() for key, value in self.vulnerabilities.items()},
			"relationships": {key: sorted(values) for key, values in self.relationships.items()},
		}


@dataclass(slots=True)
class Correlator:
	def correlate(self, scan_result: ScanResult) -> CorrelationMap:
		indexed: dict[str, Vulnerability] = {}
		by_endpoint: dict[tuple[str, str], set[str]] = {}
		by_vuln_type: dict[str, set[str]] = {}

		for vulnerability in scan_result.vulnerabilities:
			vuln_id = self._build_id(vulnerability)
			indexed[vuln_id] = vulnerability

			endpoint_key = (vulnerability.endpoint.method, vulnerability.endpoint.url)
			if endpoint_key not in by_endpoint:
				by_endpoint[endpoint_key] = set()
			by_endpoint[endpoint_key].add(vuln_id)

			vuln_type_key = vulnerability.vuln_type.lower()
			if vuln_type_key not in by_vuln_type:
				by_vuln_type[vuln_type_key] = set()
			by_vuln_type[vuln_type_key].add(vuln_id)

		relationships: dict[str, set[str]] = {vuln_id: set() for vuln_id in indexed}

		for vuln_ids in by_endpoint.values():
			self._connect_group(vuln_ids, relationships)

		for vuln_ids in by_vuln_type.values():
			self._connect_group(vuln_ids, relationships)

		total_edges = sum(len(neighbors) for neighbors in relationships.values())
		LOGGER.info("Correlated %d vulnerabilities with %d directional edges", len(indexed), total_edges)

		return CorrelationMap(vulnerabilities=indexed, relationships=relationships)

	def _build_id(self, vulnerability: Vulnerability) -> str:
		endpoint = vulnerability.endpoint
		return f"{vulnerability.vuln_type}:{endpoint.method}:{endpoint.url}"

	def _connect_group(self, vuln_ids: set[str], relationships: dict[str, set[str]]) -> None:
		"""Create bi-directional edges between all vulnerabilities in a group."""
		for a in vuln_ids:
			for b in vuln_ids:
				if a != b:
					relationships[a].add(b)


@dataclass(slots=True)
class VectorCorrelator:
	"""Advanced correlator that uses VectorSpace for semantic relationship discovery.

	Unlike the base Correlator, which relies on exact string matches, this
	discoverer finds vulnerabilities that 'look similar' in terms of context,
	payloads, and evidence.
	"""

	vector_space: VectorSpace

	def correlate_vectors(self, scan_result: ScanResult, min_similarity: float = 0.85) -> CorrelationMap:
		indexed: dict[str, Vulnerability] = {}
		relationships: dict[str, set[str]] = {}

		# 1. Populate the space and identify findings
		for vulnerability in scan_result.vulnerabilities:
			vuln_id = self._build_id(vulnerability)
			indexed[vuln_id] = vulnerability
			relationships[vuln_id] = set()

			# Add to space (dedup handled by VectorSpace if enabled)
			self.vector_space.add_vulnerability(vulnerability)

		# 2. Perform similarity search for each finding to discover semantic clones
		for vuln_id, vulnerability in indexed.items():
			matches = self.vector_space.similarity_search(
				query=vulnerability,
				top_k=5,
				min_similarity=min_similarity,
			)

			for match in matches:
				match_id = self._build_id(match.vulnerability)
				if match_id != vuln_id and match_id in indexed:
					# We found a similar vulnerability in the current scan set
					relationships[vuln_id].add(match_id)

		LOGGER.info(
			"VectorCorrelator: identified %d semantic relationships across %d findings",
			sum(len(v) for v in relationships.values()),
			len(indexed),
		)
		return CorrelationMap(vulnerabilities=indexed, relationships=relationships)

	def _build_id(self, vulnerability: Vulnerability) -> str:
		"""Stable ID for a vulnerability in a correlation map."""
		endpoint = vulnerability.endpoint
		return f"{vulnerability.vuln_type}:{endpoint.method}:{endpoint.url}"


@dataclass(slots=True)
class VulnerabilityValidator:
	"""Enforces the 'Require proof' rule by filtering unverified findings."""

	min_confidence: float = 0.5

	def validate_and_filter(self, vulnerabilities: list[Vulnerability]) -> tuple[list[Vulnerability], list[Vulnerability]]:
		"""
		Split vulnerabilities into verified findings and re-test candidates.
		
		Returns:
			(verified_list, retest_candidates)
		"""
		verified: list[Vulnerability] = []
		retest: list[Vulnerability] = []

		for vuln in vulnerabilities:
			# Rule: Require proof (evidence) or high confidence
			has_evidence = len(vuln.evidence) > 0
			
			if has_evidence and vuln.confidence >= self.min_confidence:
				verified.append(vuln)
			elif has_evidence or vuln.confidence >= 0.3:
				# Some evidence or marginal confidence -> try to re-test
				retest.append(vuln)
			else:
				# No evidence and low confidence -> drop noisy findings
				LOGGER.info("Dropping unverified finding without evidence: %s at %s", vuln.vuln_type, vuln.endpoint.url)

		return verified, retest
