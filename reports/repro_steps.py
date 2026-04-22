from __future__ import annotations

import logging
from dataclasses import dataclass
from data.models import Vulnerability, Endpoint

LOGGER = logging.getLogger(__name__)

@dataclass(slots=True)
class ReproductionStepGenerator:
    """Generates deterministic, step-by-step reproduction guides for vulnerabilities."""

    def generate_steps(self, vulnerability: Vulnerability) -> list[str]:
        """Produce a list of structured steps to reproduce the given vulnerability."""
        vuln_type = vulnerability.vuln_type.lower()
        endpoint = vulnerability.endpoint
        payload = vulnerability.payloads[0] if vulnerability.payloads else "NO_PAYLOAD_AVAILABLE"
        evidence = vulnerability.evidence[0] if vulnerability.evidence else "NO_EVIDENCE_AVAILABLE"

        if "xss" in vuln_type:
            return self._xss_steps(endpoint, payload, evidence)
        elif "sqli" in vuln_type:
            return self._sqli_steps(endpoint, payload, evidence)
        elif "idor" in vuln_type:
            return self._idor_steps(endpoint, payload, evidence)
        elif "ssrf" in vuln_type:
            return self._ssrf_steps(endpoint, payload, evidence)
        elif "auth" in vuln_type or "bypass" in vuln_type:
            return self._auth_bypass_steps(endpoint, payload, evidence)
        
        return self._generic_steps(endpoint, payload, evidence)

    def _xss_steps(self, endpoint: Endpoint, payload: str, evidence: str) -> list[str]:
        return [
            f"1. Navigate to the target endpoint: {endpoint.method} {endpoint.url}",
            f"2. Inject the XSS payload into the affected parameter: {payload}",
            "3. Observe the application response in a browser or proxy.",
            f"4. Verify that the payload is reflected or executed, as seen in evidence: {evidence}"
        ]

    def _sqli_steps(self, endpoint: Endpoint, payload: str, evidence: str) -> list[str]:
        return [
            f"1. Target the vulnerable endpoint: {endpoint.method} {endpoint.url}",
            f"2. Submit the SQL injection payload: {payload}",
            "3. Analyze the response for database error signatures or timing anomalies.",
            f"4. Confirm the presence of the vulnerability using the captured evidence: {evidence}"
        ]

    def _idor_steps(self, endpoint: Endpoint, payload: str, evidence: str) -> list[str]:
        return [
            f"1. Authenticate as a low-privileged user and navigate to: {endpoint.url}",
            f"2. Modify the resource identifier or parameter to: {payload}",
            f"3. Submit the {endpoint.method} request.",
            f"4. Verify that the server returns data belonging to another entity, as shown in evidence: {evidence}"
        ]

    def _ssrf_steps(self, endpoint: Endpoint, payload: str, evidence: str) -> list[str]:
        return [
            f"1. Access the endpoint: {endpoint.method} {endpoint.url}",
            f"2. Provide the SSRF payload (target internal URL or metadata service): {payload}",
            "3. Observe the response for content from the internal target.",
            f"4. Confirm the server-side request was successful based on evidence: {evidence}"
        ]

    def _auth_bypass_steps(self, endpoint: Endpoint, payload: str, evidence: str) -> list[str]:
        return [
            f"1. Attempt to access the sensitive endpoint without valid credentials: {endpoint.method} {endpoint.url}",
            f"2. Apply the bypass technique or payload: {payload}",
            "3. Observe that the server grants access to the restricted resource.",
            f"4. Validate the bypass using the captured evidence: {evidence}"
        ]

    def _generic_steps(self, endpoint: Endpoint, payload: str, evidence: str) -> list[str]:
        return [
            f"1. Send an HTTP {endpoint.method} request to {endpoint.url}",
            f"2. Use the observed payload: {payload}",
            "3. Analyze the response behavior and compare with historical patterns.",
            f"4. Confirm the finding using the evidence: {evidence}"
        ]
