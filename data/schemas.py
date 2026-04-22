"""data/schemas.py

Strict validation schemas for the three core domain objects:
    Target, Endpoint, Vulnerability.

Design rationale
----------------
* **Zero external dependencies** — pure Python 3.11+ stdlib.  Pydantic would
  add the same guarantees but is not guaranteed to be installed; the guardrails
  require dataclasses, so this module uses them exclusively.
* **Two-way bridge** — each schema can be built from either a raw dict
  (``from_dict``) or a domain model (``from_model``), and converted back to a
  domain model via ``to_model()``.
* **Strict typing** — every field has an explicit type check.  Wrong types
  raise ``ValidationError`` immediately; no silent coercions.
* **Field-level errors** — a single validation pass collects *all* errors
  before raising, so callers see every problem at once.
* **Never passes raw strings** — ``to_model()`` always returns domain objects.
"""

from __future__ import annotations

import logging
import re
from dataclasses import dataclass, field
from typing import Any
from urllib.parse import urlparse

from data.models import Endpoint, ScanResult, ScopeRules, Target, Vulnerability


LOGGER = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Allowed value registries (no hardcoded literals scattered in validators)
# ---------------------------------------------------------------------------

_ALLOWED_HTTP_METHODS: frozenset[str] = frozenset(
    {"GET", "POST", "PUT", "PATCH", "DELETE", "HEAD", "OPTIONS", "TRACE"}
)

_ALLOWED_SEVERITIES: frozenset[str] = frozenset({"low", "medium", "high", "critical"})

_ALLOWED_SCHEMES: frozenset[str] = frozenset({"http", "https"})

_DOMAIN_PATTERN: re.Pattern[str] = re.compile(
    r"^(?:[a-zA-Z0-9](?:[a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}$"
)

_CONFIDENCE_MIN: float = 0.0
_CONFIDENCE_MAX: float = 1.0


# ---------------------------------------------------------------------------
# Validation error — structured, never a raw string
# ---------------------------------------------------------------------------


@dataclass(frozen=True, slots=True)
class FieldError:
    """A single field-level validation failure."""

    field_path: str
    message: str

    def __str__(self) -> str:
        return f"{self.field_path}: {self.message}"


class ValidationError(ValueError):
    """Raised when a schema validation fails.

    Contains all field errors collected in a single pass so callers
    see every violation at once.
    """

    def __init__(self, schema_name: str, errors: list[FieldError]) -> None:
        self.schema_name = schema_name
        self.errors: list[FieldError] = list(errors)
        detail = "; ".join(str(e) for e in errors)
        super().__init__(f"{schema_name} validation failed — {detail}")

    def field_paths(self) -> set[str]:
        return {e.field_path for e in self.errors}


# ---------------------------------------------------------------------------
# Internal validation helpers
# ---------------------------------------------------------------------------


def _check_nonempty_str(
    errors: list[FieldError], path: str, value: object
) -> str | None:
    if not isinstance(value, str):
        errors.append(FieldError(path, f"expected str, got {type(value).__name__}"))
        return None
    stripped = value.strip()
    if not stripped:
        errors.append(FieldError(path, "must not be empty or whitespace-only"))
        return None
    return stripped


def _check_str_or_none(
    errors: list[FieldError], path: str, value: object
) -> str | None:
    if value is None:
        return None
    return _check_nonempty_str(errors, path, value)


def _check_float_in_range(
    errors: list[FieldError],
    path: str,
    value: object,
    lo: float,
    hi: float,
) -> float | None:
    if isinstance(value, bool):
        errors.append(FieldError(path, f"expected float, got bool"))
        return None
    if isinstance(value, int):
        value = float(value)
    if not isinstance(value, float):
        errors.append(FieldError(path, f"expected float, got {type(value).__name__}"))
        return None
    if not (lo <= value <= hi):
        errors.append(FieldError(path, f"must be in [{lo}, {hi}], got {value}"))
        return None
    return value


def _check_str_list(
    errors: list[FieldError], path: str, value: object
) -> list[str] | None:
    if not isinstance(value, list):
        errors.append(FieldError(path, f"expected list, got {type(value).__name__}"))
        return None
    result: list[str] = []
    for idx, item in enumerate(value):
        item_path = f"{path}[{idx}]"
        if not isinstance(item, str):
            errors.append(FieldError(item_path, f"expected str, got {type(item).__name__}"))
        else:
            result.append(item)
    return result if not any(p.startswith(path + "[") for p in (e.field_path for e in errors)) else None


def _check_str_set(
    errors: list[FieldError], path: str, value: object
) -> set[str] | None:
    raw = _check_str_list(errors, path, value if isinstance(value, list) else (list(value) if isinstance(value, (set, frozenset)) else value))
    return set(raw) if raw is not None else None


def _check_bool(
    errors: list[FieldError], path: str, value: object
) -> bool | None:
    if not isinstance(value, bool):
        errors.append(FieldError(path, f"expected bool, got {type(value).__name__}"))
        return None
    return value


def _check_str_to_str_dict(
    errors: list[FieldError], path: str, value: object
) -> dict[str, str] | None:
    if not isinstance(value, dict):
        errors.append(FieldError(path, f"expected dict, got {type(value).__name__}"))
        return None
    result: dict[str, str] = {}
    bad = False
    for k, v in value.items():
        kp = f"{path}.{k}"
        if not isinstance(k, str) or not isinstance(v, str):
            errors.append(FieldError(kp, f"expected str→str mapping, got {type(k).__name__}→{type(v).__name__}"))
            bad = True
        else:
            result[k] = v
    return result if not bad else None


# ---------------------------------------------------------------------------
# EndpointSchema
# ---------------------------------------------------------------------------


@dataclass(slots=True)
class EndpointSchema:
    """Validated schema for an HTTP endpoint."""

    url: str
    method: str
    params: set[str] = field(default_factory=set)
    headers: dict[str, str] = field(default_factory=dict)

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "EndpointSchema":
        """Validate a raw dict and return an EndpointSchema.

        Raises
        ------
        ValidationError
            If any field fails validation.
        TypeError
            If *data* is not a dict.
        """
        if not isinstance(data, dict):
            raise TypeError(f"EndpointSchema.from_dict expects dict, got {type(data).__name__}")

        errors: list[FieldError] = []

        url = _check_nonempty_str(errors, "url", data.get("url"))
        if url is not None:
            parsed = urlparse(url)
            if parsed.scheme not in _ALLOWED_SCHEMES:
                errors.append(FieldError("url", f"scheme must be one of {sorted(_ALLOWED_SCHEMES)}, got {parsed.scheme!r}"))
                url = None
            elif not parsed.netloc:
                errors.append(FieldError("url", "URL must contain a valid host"))
                url = None

        method = _check_nonempty_str(errors, "method", data.get("method"))
        if method is not None:
            method = method.upper()
            if method not in _ALLOWED_HTTP_METHODS:
                errors.append(FieldError("method", f"must be one of {sorted(_ALLOWED_HTTP_METHODS)}, got {method!r}"))
                method = None

        params_raw = data.get("params", [])
        params = _check_str_set(errors, "params", params_raw)

        headers_raw = data.get("headers", {})
        headers = _check_str_to_str_dict(errors, "headers", headers_raw)

        if errors:
            raise ValidationError("EndpointSchema", errors)

        assert url is not None
        assert method is not None
        return cls(
            url=url,
            method=method,
            params=params or set(),
            headers=headers or {},
        )

    @classmethod
    def from_model(cls, endpoint: Endpoint) -> "EndpointSchema":
        """Create a schema from an already-constructed domain Endpoint."""
        if not isinstance(endpoint, Endpoint):
            raise TypeError(f"Expected Endpoint, got {type(endpoint).__name__}")
        return cls.from_dict(endpoint.to_dict())

    def to_model(self) -> Endpoint:
        """Convert the validated schema back to a domain Endpoint."""
        return Endpoint(
            url=self.url,
            method=self.method,
            params=set(self.params),
            headers=dict(self.headers),
        )

    def to_dict(self) -> dict[str, Any]:
        return {
            "url": self.url,
            "method": self.method,
            "params": sorted(self.params),
            "headers": dict(sorted(self.headers.items())),
        }


# ---------------------------------------------------------------------------
# VulnerabilitySchema
# ---------------------------------------------------------------------------


@dataclass(slots=True)
class VulnerabilitySchema:
    """Validated schema for a discovered vulnerability."""

    vuln_type: str
    endpoint: EndpointSchema
    severity: str
    payloads: list[str] = field(default_factory=list)
    evidence: list[str] = field(default_factory=list)
    confidence: float = 0.0

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "VulnerabilitySchema":
        """Validate a raw dict and return a VulnerabilitySchema.

        Raises
        ------
        ValidationError
            If any field fails validation.
        TypeError
            If *data* is not a dict.
        """
        if not isinstance(data, dict):
            raise TypeError(f"VulnerabilitySchema.from_dict expects dict, got {type(data).__name__}")

        errors: list[FieldError] = []

        vuln_type = _check_nonempty_str(errors, "vuln_type", data.get("vuln_type"))

        severity = _check_nonempty_str(errors, "severity", data.get("severity"))
        if severity is not None:
            severity = severity.lower()
            if severity not in _ALLOWED_SEVERITIES:
                errors.append(FieldError("severity", f"must be one of {sorted(_ALLOWED_SEVERITIES)}, got {severity!r}"))
                severity = None

        confidence = _check_float_in_range(
            errors, "confidence", data.get("confidence", 0.0),
            _CONFIDENCE_MIN, _CONFIDENCE_MAX,
        )

        payloads = _check_str_list(errors, "payloads", data.get("payloads", []))
        evidence = _check_str_list(errors, "evidence", data.get("evidence", []))

        # Validate nested endpoint
        endpoint: EndpointSchema | None = None
        endpoint_raw = data.get("endpoint")
        if not isinstance(endpoint_raw, dict):
            errors.append(FieldError("endpoint", f"expected dict, got {type(endpoint_raw).__name__}"))
        else:
            try:
                endpoint = EndpointSchema.from_dict(endpoint_raw)
            except ValidationError as exc:
                for fe in exc.errors:
                    errors.append(FieldError(f"endpoint.{fe.field_path}", fe.message))

        if errors:
            raise ValidationError("VulnerabilitySchema", errors)

        assert vuln_type is not None
        assert severity is not None
        assert confidence is not None
        assert endpoint is not None
        return cls(
            vuln_type=vuln_type,
            endpoint=endpoint,
            severity=severity,
            payloads=payloads or [],
            evidence=evidence or [],
            confidence=confidence,
        )

    @classmethod
    def from_model(cls, vuln: Vulnerability) -> "VulnerabilitySchema":
        """Create a schema from an already-constructed domain Vulnerability."""
        if not isinstance(vuln, Vulnerability):
            raise TypeError(f"Expected Vulnerability, got {type(vuln).__name__}")
        return cls.from_dict(vuln.to_dict())

    def to_model(self) -> Vulnerability:
        """Convert the validated schema back to a domain Vulnerability."""
        return Vulnerability(
            vuln_type=self.vuln_type,
            endpoint=self.endpoint.to_model(),
            severity=self.severity,
            payloads=list(self.payloads),
            evidence=list(self.evidence),
            confidence=self.confidence,
        )

    def to_dict(self) -> dict[str, Any]:
        return {
            "vuln_type": self.vuln_type,
            "endpoint": self.endpoint.to_dict(),
            "severity": self.severity,
            "payloads": list(self.payloads),
            "evidence": list(self.evidence),
            "confidence": self.confidence,
        }


# ---------------------------------------------------------------------------
# ScopeRulesSchema
# ---------------------------------------------------------------------------


@dataclass(slots=True)
class ScopeRulesSchema:
    """Validated schema for scope constraints."""

    allowed_domains: set[str] = field(default_factory=set)
    blocked_domains: set[str] = field(default_factory=set)
    allow_subdomains: bool = True

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "ScopeRulesSchema":
        if not isinstance(data, dict):
            raise TypeError(f"ScopeRulesSchema.from_dict expects dict, got {type(data).__name__}")

        errors: list[FieldError] = []

        allowed = _check_str_set(errors, "allowed_domains", data.get("allowed_domains", []))
        blocked = _check_str_set(errors, "blocked_domains", data.get("blocked_domains", []))
        allow_sub = _check_bool(errors, "allow_subdomains", data.get("allow_subdomains", True))

        if allowed is not None:
            for domain in allowed:
                if not _DOMAIN_PATTERN.match(domain):
                    errors.append(FieldError("allowed_domains", f"invalid domain format: {domain!r}"))
        if blocked is not None:
            for domain in blocked:
                if not _DOMAIN_PATTERN.match(domain):
                    errors.append(FieldError("blocked_domains", f"invalid domain format: {domain!r}"))

        if errors:
            raise ValidationError("ScopeRulesSchema", errors)

        return cls(
            allowed_domains=allowed or set(),
            blocked_domains=blocked or set(),
            allow_subdomains=allow_sub if allow_sub is not None else True,
        )

    def to_model(self) -> ScopeRules:
        return ScopeRules(
            allowed_domains=set(self.allowed_domains),
            blocked_domains=set(self.blocked_domains),
            allow_subdomains=self.allow_subdomains,
        )

    def to_dict(self) -> dict[str, Any]:
        return {
            "allowed_domains": sorted(self.allowed_domains),
            "blocked_domains": sorted(self.blocked_domains),
            "allow_subdomains": self.allow_subdomains,
        }


# ---------------------------------------------------------------------------
# TargetSchema
# ---------------------------------------------------------------------------


@dataclass(slots=True)
class TargetSchema:
    """Validated schema for a scan Target."""

    domain: str
    subdomains: set[str] = field(default_factory=set)
    endpoints: list[EndpointSchema] = field(default_factory=list)
    parameters: dict[str, set[str]] = field(default_factory=dict)
    scope_rules: ScopeRulesSchema = field(default_factory=ScopeRulesSchema)

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "TargetSchema":
        """Validate a raw dict and return a TargetSchema.

        Raises
        ------
        ValidationError
            If any field fails validation.
        TypeError
            If *data* is not a dict.
        """
        if not isinstance(data, dict):
            raise TypeError(f"TargetSchema.from_dict expects dict, got {type(data).__name__}")

        errors: list[FieldError] = []

        domain = _check_nonempty_str(errors, "domain", data.get("domain"))
        if domain is not None:
            domain = domain.lower()
            if not _DOMAIN_PATTERN.match(domain):
                errors.append(FieldError("domain", f"invalid domain format: {domain!r}"))
                domain = None

        subdomains: set[str] = set()
        sub_raw = data.get("subdomains", [])
        sub_list = _check_str_set(errors, "subdomains", sub_raw)
        if sub_list is not None:
            for sub in sub_list:
                if not _DOMAIN_PATTERN.match(sub.lower()):
                    errors.append(FieldError("subdomains", f"invalid subdomain format: {sub!r}"))
                else:
                    subdomains.add(sub.lower())

        endpoints: list[EndpointSchema] = []
        eps_raw = data.get("endpoints", [])
        if not isinstance(eps_raw, list):
            errors.append(FieldError("endpoints", f"expected list, got {type(eps_raw).__name__}"))
        else:
            for idx, ep_raw in enumerate(eps_raw):
                ep_path = f"endpoints[{idx}]"
                if not isinstance(ep_raw, dict):
                    errors.append(FieldError(ep_path, f"expected dict, got {type(ep_raw).__name__}"))
                    continue
                try:
                    endpoints.append(EndpointSchema.from_dict(ep_raw))
                except ValidationError as exc:
                    for fe in exc.errors:
                        errors.append(FieldError(f"{ep_path}.{fe.field_path}", fe.message))

        parameters: dict[str, set[str]] = {}
        params_raw = data.get("parameters", {})
        if not isinstance(params_raw, dict):
            errors.append(FieldError("parameters", f"expected dict, got {type(params_raw).__name__}"))
        else:
            for param_name, param_values in params_raw.items():
                ppath = f"parameters.{param_name}"
                if not isinstance(param_name, str):
                    errors.append(FieldError(ppath, "parameter name must be a string"))
                    continue
                values = _check_str_set(errors, ppath, param_values if isinstance(param_values, list) else list(param_values) if isinstance(param_values, set) else param_values)
                if values is not None:
                    parameters[param_name] = values

        scope_schema = ScopeRulesSchema()
        scope_raw = data.get("scope_rules", {})
        if scope_raw:
            if not isinstance(scope_raw, dict):
                errors.append(FieldError("scope_rules", f"expected dict, got {type(scope_raw).__name__}"))
            else:
                try:
                    scope_schema = ScopeRulesSchema.from_dict(scope_raw)
                except ValidationError as exc:
                    for fe in exc.errors:
                        errors.append(FieldError(f"scope_rules.{fe.field_path}", fe.message))

        if errors:
            raise ValidationError("TargetSchema", errors)

        assert domain is not None
        return cls(
            domain=domain,
            subdomains=subdomains,
            endpoints=endpoints,
            parameters=parameters,
            scope_rules=scope_schema,
        )

    @classmethod
    def from_model(cls, target: Target) -> "TargetSchema":
        """Create a schema from an already-constructed domain Target."""
        if not isinstance(target, Target):
            raise TypeError(f"Expected Target, got {type(target).__name__}")
        return cls.from_dict(target.to_dict())

    def to_model(self) -> Target:
        """Convert the validated schema back to a domain Target."""
        target = Target(
            domain=self.domain,
            subdomains=set(self.subdomains),
            endpoints={ep.to_model() for ep in self.endpoints},
            parameters={k: set(v) for k, v in self.parameters.items()},
            scope_rules=self.scope_rules.to_model(),
        )
        return target

    def to_dict(self) -> dict[str, Any]:
        return {
            "domain": self.domain,
            "subdomains": sorted(self.subdomains),
            "endpoints": [ep.to_dict() for ep in self.endpoints],
            "parameters": {k: sorted(v) for k, v in sorted(self.parameters.items())},
            "scope_rules": self.scope_rules.to_dict(),
        }


# ---------------------------------------------------------------------------
# Public validation entry-points (module-level convenience functions)
# ---------------------------------------------------------------------------


def validate_endpoint(data: dict[str, Any]) -> EndpointSchema:
    """Validate raw dict and return EndpointSchema or raise ValidationError."""
    schema = EndpointSchema.from_dict(data)
    LOGGER.debug("validate_endpoint OK: %s %s", schema.method, schema.url)
    return schema


def validate_vulnerability(data: dict[str, Any]) -> VulnerabilitySchema:
    """Validate raw dict and return VulnerabilitySchema or raise ValidationError."""
    schema = VulnerabilitySchema.from_dict(data)
    LOGGER.debug("validate_vulnerability OK: %s at %s", schema.vuln_type, schema.endpoint.url)
    return schema


def validate_target(data: dict[str, Any]) -> TargetSchema:
    """Validate raw dict and return TargetSchema or raise ValidationError."""
    schema = TargetSchema.from_dict(data)
    LOGGER.debug("validate_target OK: domain=%s endpoints=%d", schema.domain, len(schema.endpoints))
    return schema
