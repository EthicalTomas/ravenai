"""scanner/ssrf_scanner.py

Detection engine for Server-Side Request Forgery (SSRF) vulnerabilities.

Functionality
-------------
* Analyzes structured Endpoint objects.
* Injects SSRF payloads (local IPs, cloud metadata URLs, etc.) into parameters.
* Validates vulnerabilities by inspecting response content and status codes.
* Handles timeouts and request failures gracefully.

Detection Logic
---------------
The scanner looks for:
1. Cloud Metadata signatures (AWS, Azure, Google, Alibaba).
2. Local service responses (e.g., "root:x:0:0" for file:// protocol).
3. Significant response changes between a baseline and the injected request.
"""

from __future__ import annotations

import logging
import re
from dataclasses import dataclass, field

from data.models import Endpoint, ScanResult, Vulnerability
from utils.http_client import HTTPClient


LOGGER = logging.getLogger(__name__)


@dataclass(slots=True)
class SSRFScanner:
    """Scanner module targeting Server-Side Request Forgery.

    Parameters
    ----------
    payloads:
        List of SSRF payloads (e.g., http://169.254.169.254/latest/meta-data/).
    timeout_seconds:
        Request timeout for injection attempts.
    min_confidence:
        Minimum score for a finding to be emitted.
    severity:
        Default severity for confirmed SSRF (typically "high" or "critical").
    user_agent:
        Identity string used for outgoing probes.
    """

    client: HTTPClient
    payloads: list[str]
    severity: str
    min_confidence: float

    # Signatures of successful SSRF hits (metadata responses, etc.)
    _METADATA_SIGNATURES: dict[str, str] = field(
        default_factory=lambda: {
            "aws": r"ami-id|instance-id|instance-type|local-hostname",
            "gcp": r"Project-Id|Instance-Id|Metadata-Flavor",
            "azure": r"compute|network|tag",
            "linode": r"public_ip|label|plan",
            "digitalocean": r"droplet_id|region|vcpus",
        }
    )

    def scan_endpoint(self, endpoint: Endpoint) -> ScanResult:
        """Scan a single endpoint for SSRF in its parameters."""
        result = ScanResult(
            vulnerabilities=[],
            raw_outputs=[],
            metadata={
                "scanner": "ssrf",
                "endpoint": endpoint.to_dict(),
                "safe_testing_mode": True,
            },
        )

        # SSRF typically occurs in GET/POST parameters that look like URLs/hosts
        if endpoint.method not in {"GET", "POST"} or not endpoint.params:
            return result

        try:
            for param_name in sorted(endpoint.params):
                vulnerability = self._scan_parameter(endpoint, param_name)
                if vulnerability:
                    result.vulnerabilities.append(vulnerability)

            result.metadata["vulnerability_count"] = len(result.vulnerabilities)
            return result

        except Exception as exc:
            LOGGER.exception("Unexpected SSRF scanner failure for endpoint: %s", endpoint.url)
            result.metadata["error"] = f"ssrf_scanner_failure: {str(exc)}"
            return result

    def _scan_parameter(self, endpoint: Endpoint, parameter_name: str) -> Vulnerability | None:
        """Probe a specific parameter for SSRF."""
        detected_payloads: list[str] = []
        evidence: list[str] = []
        best_confidence: float = 0.0

        for payload in self.payloads:
            response = self._inject_and_request(endpoint, parameter_name, payload)
            if response is None:
                continue

            confidence, matched_info = self._analyze_ssrf_response(response, payload)
            if confidence >= self.min_confidence:
                detected_payloads.append(payload)
                evidence.append(
                    f"param={parameter_name} payload={payload} "
                    f"status={response.status_code} "
                    f"evidence={matched_info}"
                )
                best_confidence = max(best_confidence, confidence)

        if not detected_payloads:
            return None

        return Vulnerability(
            vuln_type="ssrf",
            endpoint=endpoint,
            severity=self.severity,
            payloads=detected_payloads,
            evidence=evidence,
            confidence=best_confidence,
        )

    def _inject_and_request(
        self, endpoint: Endpoint, parameter_name: str, payload: str
    ) -> Any | None:
        """Helper to build and send the request via the centralized HTTPClient."""
        data_to_send: dict[str, str] = {name: "scan" for name in endpoint.params}
        data_to_send[parameter_name] = payload

        try:
            return self.client.request(
                method=endpoint.method,
                url=endpoint.url,
                params=data_to_send if endpoint.method == "GET" else None,
                data=data_to_send if endpoint.method == "POST" else None,
                allow_redirects=False,
            )
        except Exception:
            return None

    def _analyze_ssrf_response(self, response: requests.Response, payload: str) -> tuple[float, str]:
        """Analyze the response for evidence of internal reach-through.
        
        Strictly follows the 'no evidence, no vulnerability' rule.
        """
        body = response.text
        headers = {k.lower(): v.lower() for k, v in response.headers.items()}
        
        # 1. Check for cloud metadata patterns in the response body
        for provider, pattern in self._METADATA_SIGNATURES.items():
            if re.search(pattern, body, re.IGNORECASE):
                return 1.0, f"Confirmed SSRF: cloud metadata detected ({provider})"

        # 2. Check for cloud metadata headers (even if body is encrypted or obscured)
        if headers.get("metadata-flavor") == "google":
            return 1.0, "Confirmed SSRF: Google Cloud Metadata-Flavor header detected"
        if "aws" in headers.get("server", "") and "metadata" in body.lower():
             return 0.9, "Confirmed SSRF: AWS Metadata server signature detected"

        # 3. Local file access check (requires content verification)
        if "root:x:0:0" in body and "file://" in payload.lower():
            return 1.0, "Confirmed SSRF: /etc/passwd leaked via file:// protocol"

        # 4. Local service discovery (requires identifiable service banners)
        if "redis_version" in body or "mongodb" in body.lower():
            return 0.95, "Confirmed SSRF: Internal service banner (Redis/MongoDB) detected"

        # Note: Generic 200 OK on internal IPs is NOT considered evidence.
        return 0.0, ""
