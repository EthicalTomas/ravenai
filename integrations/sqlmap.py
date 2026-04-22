from __future__ import annotations

import logging
import subprocess
from dataclasses import dataclass, field
from typing import Any

from data.models import Endpoint, ScanResult, Vulnerability


LOGGER = logging.getLogger(__name__)


@dataclass(slots=True)
class SqlmapWrapper:
	binary_path: str
	timeout_seconds: float
	severity: str
	confidence_on_detection: float
	extra_args: list[str] = field(default_factory=list)

	def scan_endpoint(self, endpoint: Endpoint) -> ScanResult:
		metadata: dict[str, Any] = {
			"tool": "sqlmap",
			"endpoint": endpoint.to_dict(),
		}
		if not endpoint.params:
			metadata["skipped"] = "endpoint_has_no_parameters"
			return ScanResult(vulnerabilities=[], raw_outputs=[], metadata=metadata)

		vulnerabilities: list[Vulnerability] = []
		raw_outputs: list[str] = []
		exit_codes: dict[str, int] = {}

		for param in sorted(endpoint.params):
			command = [
				self.binary_path,
				"-u",
				endpoint.url,
				"-p",
				param,
				"--batch",
				"--smart",
				"--random-agent",
				"--level",
				"1",
				"--risk",
				"1",
			]
			command.extend(self.extra_args)

			completed = self._run_command(command)
			exit_codes[param] = completed.returncode
			if completed.stdout:
				raw_outputs.append(completed.stdout)
			if completed.stderr:
				raw_outputs.append(completed.stderr)

			parsed = self._parse_output(endpoint=endpoint, parameter_name=param, output_text=completed.stdout)
			vulnerabilities.extend(parsed)

		metadata["exit_codes"] = exit_codes
		metadata["vulnerability_count"] = len(vulnerabilities)
		return ScanResult(vulnerabilities=vulnerabilities, raw_outputs=raw_outputs, metadata=metadata)

	def _run_command(self, command: list[str]) -> subprocess.CompletedProcess[str]:
		LOGGER.debug("Running sqlmap command: %s", " ".join(command))
		try:
			return subprocess.run(
				command,
				check=False,
				capture_output=True,
				text=True,
				timeout=self.timeout_seconds,
			)
		except FileNotFoundError:
			LOGGER.exception("sqlmap binary not found: %s", self.binary_path)
			return subprocess.CompletedProcess(args=command, returncode=127, stdout="", stderr="binary not found")
		except subprocess.TimeoutExpired:
			LOGGER.exception("sqlmap command timed out")
			return subprocess.CompletedProcess(args=command, returncode=124, stdout="", stderr="command timed out")

	def _parse_output(self, endpoint: Endpoint, parameter_name: str, output_text: str) -> list[Vulnerability]:
		lowered = output_text.lower()
		indicators = [
			"parameter",
			"is vulnerable",
			"sql injection",
			"back-end dbms",
		]
		if not all(indicator in lowered for indicator in indicators[:2]) and "sql injection" not in lowered:
			return []

		evidence_lines = [
			line.strip()
			for line in output_text.splitlines()
			if "injection" in line.lower() or "vulnerable" in line.lower()
		]
		evidence = evidence_lines[:5] if evidence_lines else [f"sqlmap indicates injection on parameter {parameter_name}"]

		return [
			Vulnerability(
				vuln_type="sqli",
				endpoint=endpoint,
				severity=self.severity,
				payloads=[f"parameter={parameter_name}"],
				evidence=evidence,
				confidence=max(0.0, min(1.0, self.confidence_on_detection)),
			)
		]
