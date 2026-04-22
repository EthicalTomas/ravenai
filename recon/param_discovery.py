"""recon/param_discovery.py

Parameter discovery engine to identify injection surfaces.

Functionality
-------------
* Extracts parameters from HTML forms and input tags.
* Identifies parameters from URL query strings and fragments.
* Probes for hidden parameters using a wordlist (e.g., debug, admin, test).
* Updates Endpoint objects with discovered parameter names.

Integration
-----------
Used after EndpointDiscovery to expand the attack surface before FuzzingEngine
is invoked.
"""

from __future__ import annotations

import logging
import re
from dataclasses import dataclass
from typing import Any, Iterable

from data.models import Endpoint, Target
from utils.http_client import HTTPClient


LOGGER = logging.getLogger(__name__)


@dataclass(slots=True)
class ParameterDiscoverer:
    client: HTTPClient
    wordlist: list[str]
    max_probes_per_endpoint: int = 50

    def discover_params(self, target: Target) -> Target:
        """Analyze all endpoints in a Target and discover new parameters."""
        LOGGER.info("Starting parameter discovery for domain: %s", target.domain)

        total_discovered = 0
        for endpoint in sorted(target.endpoints, key=lambda e: (e.url, e.method)):
            discovered = self._analyze_endpoint(endpoint)
            
            if discovered:
                # Store in the target mapping (url -> set of params)
                target.add_parameter_values(endpoint.url, discovered)
                
                # Update the endpoint's parameter set directly for fuzzers
                endpoint.params.update(discovered)
                total_discovered += len(discovered)

        LOGGER.info(
            "Parameter discovery complete. Discovered %d new parameter(s) across %d endpoint(s)",
            total_discovered,
            len(target.endpoints),
        )
        return target

    def _analyze_endpoint(self, endpoint: Endpoint) -> set[str]:
        """Discovery logic for a single endpoint (parsing + probing)."""
        discovered: set[str] = set()

        # 1. Static Analysis: Fetch the page and look for forms/inputs
        try:
            response = self.client.request(
                method="GET",
                url=endpoint.url,
            )
            if response.status_code == 200:
                discovered.update(self._parse_html_params(response.text))
        except Exception:
            LOGGER.debug("Failed to fetch endpoint for static param analysis: %s", endpoint.url)

        # 2. Brute-Force: Probe for common hidden parameters
        # Only for GET requests where multiple params are often accepted
        if endpoint.method == "GET":
            brute_discovered = self._probe_hidden_params(endpoint)
            discovered.update(brute_discovered)

        return discovered

    def _parse_html_params(self, html_content: str) -> set[str]:
        """Extract parameter names from common HTML attributes."""
        params: set[str] = set()

        # Simple regex markers for names in forms and inputs
        patterns = [
            r'name=["\'](.*?)["\']',
            r'id=["\'](.*?)["\']',
            r'\b(\w+)=',  # generic key= pattern in JS or fragments
        ]

        for pattern in patterns:
            matches = re.findall(pattern, html_content)
            for match in matches:
                # Basic sanitization
                clean = str(match).strip()
                if clean and len(clean) < 32 and re.match(r'^\w+$', clean):
                    params.add(clean)

        return params

    def _probe_hidden_params(self, endpoint: Endpoint) -> set[str]:
        """Send a single probe request with multiple wordlist entries to detect reflection."""
        discovered: set[str] = set()
        
        # We chunk the wordlist to avoid overly long URLs
        chunk_size = 10
        chunks = [
            self.wordlist[i : i + chunk_size]
            for i in range(0, min(len(self.wordlist), self.max_probes_per_endpoint), chunk_size)
        ]

        for chunk in chunks:
            test_params = {param: f"probe_{param}" for param in chunk}
            try:
                response = self.client.request(
                    method="GET",
                    url=endpoint.url,
                    params=test_params,
                )
                
                # If a probe value is reflected in the response, the parameter is likely active
                if response and response.status_code == 200:
                    for param, value in test_params.items():
                        if value in response.text:
                            discovered.add(param)
                            LOGGER.debug("Discovered hidden parameter '%s' via reflection", param)
            except Exception:
                break

        return discovered
