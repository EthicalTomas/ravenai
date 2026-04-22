"""scanner/nuclei_wrapper.py

Wrapper for the ProjectDiscovery Nuclei vulnerability scanner.

Functionality
-------------
* Executes the nuclei binary against target URLs.
* Parses JSON results into structured Vulnerability objects.
* Supports filtering by severity and template tags.
* Error handling for missing binary or template issues.
"""

from __future__ import annotations

import json
import logging
import subprocess
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from data.models import Endpoint, ScanResult, Vulnerability


LOGGER = logging.getLogger(__name__)


@dataclass(slots=True)
class NucleiScanner:
    """A wrapper for the Nuclei template-based vulnerability scanner.

    Parameters
    ----------
    binary_path:
        Path to the nuclei executable (e.g., /usr/local/bin/nuclei).
    templates_path:
        Path to the directory containing Nuclei templates (e.g., ~/nuclei-templates).
    severity_filter:
        Comma-separated list of severities to scan for (e.g., high,critical).
    timeout_seconds:
        Network timeout for probe requests.
    """

    binary_path: str = "nuclei"
    templates_path: str | None = None
    severity_filter: str = "medium,high,critical"
    timeout_seconds: float = 10.0

    def scan_endpoint(self, endpoint: Endpoint) -> ScanResult:
        """Scan a single endpoint using Nuclei and return findings."""
        result = ScanResult(
            vulnerabilities=[],
            raw_outputs=[],
            metadata={
                "scanner": "nuclei",
                "endpoint": endpoint.to_dict(),
                "safe_testing_mode": True,
            },
        )

        try:
            # Build CLI command for Nuclei
            command = self._build_command(endpoint.url)
            
            # Execute - discarding raw output except for parsing
            process = subprocess.run(
                command,
                capture_output=True,
                text=True,
                timeout=self.timeout_seconds * 10,  # template-based scans take longer
            )

            # Parse results from stdout (Nuclei emits one JSON object per line)
            if process.stdout:
                findings = self._parse_json_outputs(process.stdout, endpoint)
                result.vulnerabilities.extend(findings)
            
            result.metadata["vulnerability_count"] = len(result.vulnerabilities)

        except subprocess.TimeoutExpired:
            LOGGER.error("Nuclei scan timed out for endpoint %s", endpoint.url)
            result.metadata["error"] = "nuclei_timeout"
        except FileNotFoundError:
            LOGGER.error("Nuclei binary not found at %s", self.binary_path)
            result.metadata["error"] = "nuclei_binary_not_found"
        except Exception as exc:
            LOGGER.error("Nuclei scan failed for %s", endpoint.url)
            result.metadata["error"] = f"nuclei_wrapper_failure: {type(exc).__name__}"

        return result

    def _build_command(self, url: str) -> list[str]:
        """Construct the CLI command for the nuclei process."""
        cmd = [
            self.binary_path,
            "-target", url,
            "-severity", self.severity_filter,
            "-jsonL",  # One JSON object per line for easier parsing
            "-silent", # Suppress headers
            "-no-update-check",
        ]

        if self.templates_path:
            cmd.extend(["-t", self.templates_path])

        return cmd

    def _parse_json_outputs(self, stdout: str, endpoint: Endpoint) -> list[Vulnerability]:
        """Convert Nuclei JSON strings into structured Vulnerability records."""
        findings: list[Vulnerability] = []
        
        for line in stdout.splitlines():
            line = line.strip()
            if not line:
                continue

            try:
                data = json.loads(line)
                
                # Extract descriptive text from the template
                info = data.get("info", {})
                vuln_name = info.get("name", "Unknown finding")
                vuln_id = data.get("template-id", "unknown-id")
                
                findings.append(
                    Vulnerability(
                        vuln_type=f"nuclei/{vuln_id}",
                        endpoint=endpoint,
                        severity=data.get("info", {}).get("severity", "medium").lower(),
                        payloads=[], # Nuclei hides exact payload by default in JSONL
                        evidence=[
                            f"matched_name={vuln_name}",
                            f"template_id={vuln_id}",
                            f"matcher_name={data.get('matcher-name', 'unknown')}",
                        ],
                        confidence=0.8, # Nuclei findings are typically high-precision
                    )
                )
            except json.JSONDecodeError:
                LOGGER.warning("Failed to parse Nuclei output line: %s", line)
                continue

        return findings
