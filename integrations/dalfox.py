from __future__ import annotations

import json
import logging
import subprocess
from dataclasses import dataclass, field
from typing import Any

from data.models import Endpoint, ScanResult, Vulnerability


LOGGER = logging.getLogger(__name__)


@dataclass(slots=True)
class DalfoxWrapper:
	binary_path: str
	timeout_seconds: float
	severity: str
	min_confidence: float
	extra_args: list[str] = field(default_factory=list)

	def scan_endpoint(self, endpoint: Endpoint) -> ScanResult:
		command = [
			self.binary_path,
			"url",
			endpoint.url,
			"--format",
			"jsonl",
			"--silence",
			"--no-spinner",
			"--skip-bav",
		]
		command.extend(self.extra_args)

		completed = self._run_command(command)
		vulnerabilities = self._parse_output(endpoint=endpoint, stdout=completed.stdout)
		metadata: dict[str, Any] = {
			"tool": "dalfox",
			"endpoint": endpoint.to_dict(),
			"exit_code": completed.returncode,
			"vulnerability_count": len(vulnerabilities),
		}

		return ScanResult(
			vulnerabilities=vulnerabilities,
			raw_outputs=[text for text in [completed.stdout, completed.stderr] if text],
			metadata=metadata,
		)

	def _run_command(self, command: list[str]) -> subprocess.CompletedProcess[str]:
		LOGGER.debug("Running dalfox command: %s", " ".join(command))
		try:
			return subprocess.run(
				command,
				check=False,
				capture_output=True,
				text=True,
				timeout=self.timeout_seconds,
			)
		except FileNotFoundError:
			LOGGER.exception("dalfox binary not found: %s", self.binary_path)
			return subprocess.CompletedProcess(args=command, returncode=127, stdout="", stderr="binary not found")
		except subprocess.TimeoutExpired:
			LOGGER.exception("dalfox command timed out")
			return subprocess.CompletedProcess(args=command, returncode=124, stdout="", stderr="command timed out")

	def _parse_output(self, endpoint: Endpoint, stdout: str) -> list[Vulnerability]:
		vulnerabilities: list[Vulnerability] = []

		for line in stdout.splitlines():
			line = line.strip()
			if not line:
				continue

			finding = self._parse_line(line)
			if finding is None:
				continue

			confidence = max(self.min_confidence, finding.get("confidence", 0.65))
			payload = str(finding.get("payload", ""))
			evidence = str(finding.get("evidence", "dalfox reported potential xss"))

			vulnerabilities.append(
				Vulnerability(
					vuln_type="xss",
					endpoint=endpoint,
					severity=self.severity,
					payloads=[payload] if payload else [],
					evidence=[evidence],
					confidence=min(1.0, float(confidence)),
				)
			)

		return vulnerabilities

	def _parse_line(self, line: str) -> dict[str, Any] | None:
		try:
			payload = json.loads(line)
			return {
				"payload": payload.get("payload", ""),
				"evidence": payload.get("type", "dalfox finding"),
				"confidence": 0.75,
			}
		except json.JSONDecodeError:
			lowered = line.lower()
			if "xss" not in lowered and "payload" not in lowered:
				return None
			return {
				"payload": line,
				"evidence": "dalfox text finding",
				"confidence": 0.6,
			}
