from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any


@dataclass(slots=True)
class Endpoint:
	url: str
	method: str
	params: set[str] = field(default_factory=set)
	headers: dict[str, str] = field(default_factory=dict)
	priority: float = 0.5

	def __post_init__(self) -> None:
		self.method = self.method.upper()
		self.params = set(self.params)
		self.headers = dict(self.headers)

	def __hash__(self) -> int:
		normalized_headers = tuple(sorted((str(k), str(v)) for k, v in self.headers.items()))
		normalized_params = tuple(sorted(self.params))
		return hash((self.url, self.method, normalized_params, normalized_headers))

	def __eq__(self, other: object) -> bool:
		if not isinstance(other, Endpoint):
			return False
		return (self.url, self.method, self.params, self.headers) == (other.url, other.method, other.params, other.headers)

	def to_dict(self) -> dict[str, Any]:
		return {
			"url": self.url,
			"method": self.method,
			"params": sorted(self.params),
			"headers": dict(sorted(self.headers.items())),
			"priority": round(self.priority, 3),
		}


@dataclass(slots=True)
class Vulnerability:
	vuln_type: str
	endpoint: Endpoint
	severity: str
	payloads: list[str] = field(default_factory=list)
	evidence: list[str] = field(default_factory=list)
	confidence: float = 0.0
	request_data: dict[str, Any] = field(default_factory=dict)
	priority: float = 0.5

	def to_dict(self) -> dict[str, Any]:
		return {
			"vuln_type": self.vuln_type,
			"endpoint": self.endpoint.to_dict(),
			"severity": self.severity,
			"payloads": list(self.payloads),
			"evidence": list(self.evidence),
			"confidence": self.confidence,
			"request_data": dict(self.request_data),
			"priority": round(self.priority, 3),
		}


@dataclass(slots=True)
class ScanResult:
	vulnerabilities: list[Vulnerability] = field(default_factory=list)
	raw_outputs: list[str] = field(default_factory=list)
	metadata: dict[str, Any] = field(default_factory=dict)

	def to_dict(self) -> dict[str, Any]:
		return {
			"vulnerabilities": [vulnerability.to_dict() for vulnerability in self.vulnerabilities],
			"raw_outputs": list(self.raw_outputs),
			"metadata": dict(self.metadata),
		}


@dataclass(slots=True)
class Allnsight:
	description: str
	confidence: float
	related_vuln: Vulnerability | None = None

	def to_dict(self) -> dict[str, Any]:
		return {
			"description": self.description,
			"confidence": self.confidence,
			"related_vuln": self.related_vuln.to_dict() if self.related_vuln is not None else None,
		}


@dataclass(slots=True)
class ScopeRules:
	allowed_domains: set[str] = field(default_factory=set)
	blocked_domains: set[str] = field(default_factory=set)
	allow_subdomains: bool = True

	def __post_init__(self) -> None:
		self.allowed_domains = {domain.strip().lower() for domain in self.allowed_domains if domain.strip()}
		self.blocked_domains = {domain.strip().lower() for domain in self.blocked_domains if domain.strip()}

	def to_dict(self) -> dict[str, Any]:
		return {
			"allowed_domains": sorted(self.allowed_domains),
			"blocked_domains": sorted(self.blocked_domains),
			"allow_subdomains": self.allow_subdomains,
		}


@dataclass(slots=True)
class Target:
	domain: str
	subdomains: set[str] = field(default_factory=set)
	endpoints: set[Endpoint] = field(default_factory=set)
	parameters: dict[str, set[str]] = field(default_factory=dict)
	scope_rules: ScopeRules = field(default_factory=ScopeRules)

	def __post_init__(self) -> None:
		self.domain = self.domain.strip().lower()
		self.subdomains = set(self.subdomains)
		self.endpoints = set(self.endpoints)
		# No need to process self.parameters here, default_factory handles it
		if not self.scope_rules.allowed_domains:
			self.scope_rules.allowed_domains = {self.domain}
		if self.domain not in self.scope_rules.allowed_domains:
			self.scope_rules.allowed_domains.add(self.domain)

	def add_endpoint(self, endpoint: Endpoint) -> None:
		self.endpoints.add(endpoint)

	def add_parameter_values(self, url: str, parameter_names: set[str]) -> None:
		if url not in self.parameters:
			self.parameters[url] = set()
		self.parameters[url].update(parameter_names)

	def to_dict(self) -> dict[str, Any]:
		return {
			"domain": self.domain,
			"subdomains": sorted(self.subdomains),
			"endpoints": [endpoint.to_dict() for endpoint in sorted(self.endpoints, key=lambda ep: (ep.url, ep.method))],
			"parameters": {key: sorted(values) for key, values in sorted(self.parameters.items())},
			"scope_rules": self.scope_rules.to_dict(),
		}
