from __future__ import annotations

import logging
import re
from dataclasses import dataclass
from urllib.parse import urlparse, urlunparse

from data.models import Endpoint, Target


LOGGER = logging.getLogger(__name__)

DOMAIN_PATTERN = re.compile(
    r"^(?=.{1,253}$)(?!-)([a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?)(\.[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?)+$"
)


class ValidationError(ValueError):
    """Raised when user-supplied target or URL data is invalid."""


@dataclass(slots=True)
class InputValidator:
    default_scheme: str

    def validate_domain(self, domain: str) -> str:
        normalized = domain.strip().lower().rstrip(".")
        if not normalized:
            raise ValidationError("Domain cannot be empty")

        if not DOMAIN_PATTERN.fullmatch(normalized):
            raise ValidationError(f"Invalid domain format: {domain}")

        return normalized

    def normalize_url(self, url: str) -> str:
        candidate = url.strip()
        if not candidate:
            raise ValidationError("URL cannot be empty")

        parsed = urlparse(candidate)
        if not parsed.scheme:
            parsed = urlparse(f"{self.default_scheme}://{candidate}")

        if not parsed.hostname:
            raise ValidationError(f"URL must include a valid host: {url}")

        validated_host = self.validate_domain(parsed.hostname)
        normalized_path = parsed.path or "/"

        normalized = parsed._replace(
            scheme=parsed.scheme.lower(),
            netloc=validated_host,
            path=normalized_path,
            fragment="",
        )
        return urlunparse(normalized)

    def reject_invalid_target(self, target: Target) -> Target:
        validated_domain = self.validate_domain(target.domain)
        target.domain = validated_domain

        validated_subdomains: set[str] = set()
        for subdomain in target.subdomains:
            validated_subdomain = self.validate_domain(subdomain)
            if validated_subdomain == validated_domain or validated_subdomain.endswith(f".{validated_domain}"):
                validated_subdomains.add(validated_subdomain)
                continue
            raise ValidationError(
                f"Subdomain '{subdomain}' does not belong to target domain '{validated_domain}'"
            )

        normalized_endpoints: set[Endpoint] = set()
        for endpoint in target.endpoints:
            normalized_url = self.normalize_url(endpoint.url)
            host = urlparse(normalized_url).hostname
            if host is None:
                raise ValidationError(f"Endpoint URL has no valid host: {endpoint.url}")

            if host != validated_domain and not host.endswith(f".{validated_domain}"):
                raise ValidationError(
                    f"Endpoint host '{host}' is out of target scope '{validated_domain}'"
                )

            normalized_endpoints.add(
                Endpoint(
                    url=normalized_url,
                    method=endpoint.method,
                    params=set(endpoint.params),
                    headers=dict(endpoint.headers),
                )
            )

        target.subdomains = validated_subdomains
        target.endpoints = normalized_endpoints
        LOGGER.debug("Validated target domain=%s subdomains=%d endpoints=%d", target.domain, len(target.subdomains), len(target.endpoints))
        return target