from __future__ import annotations

import json
import logging
import subprocess
import tempfile
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from data.models import Endpoint, ScanResult, Vulnerability


LOGGER = logging.getLogger(__name__)


@dataclass(slots=True)
class FfufWrapper:
	binary_path: str
	wordlist_path: Path
	timeout_seconds: float
	matcher_codes: set[int]
	extra_args: list[str] = field(default_factory=list)

	def scan_endpoint(self, endpoint: Endpoint) -> ScanResult:
		metadata: dict[str, Any] = {
			"tool": "ffuf",
			"endpoint": endpoint.to_dict(),
			"wordlist_path": str(self.wordlist_path),
		}
		if "FUZZ" not in endpoint.url:
			metadata["skipped"] = "endpoint_url_missing_fuzz_token"
			return ScanResult(vulnerabilities=[], raw_outputs=[], metadata=metadata)

		with tempfile.NamedTemporaryFile(mode="w", suffix=".json", delete=False) as output_file:
			output_path = Path(output_file.name)

		command = [
			self.binary_path,
			"-u",
			endpoint.url,
			"-w",
			str(self.wordlist_path),
			"-of",
			"json",
			"-o",
			str(output_path),
		]

		if self.matcher_codes:
			command.extend(["-mc", ",".join(str(code) for code in sorted(self.matcher_codes))])
		command.extend(self.extra_args)

		completed = self._run_command(command)
		raw_outputs = [completed.stdout, completed.stderr]

		vulnerabilities = self._parse_ffuf_json(output_path=output_path, endpoint=endpoint)
		metadata["exit_code"] = completed.returncode
		metadata["vulnerability_count"] = len(vulnerabilities)

		return ScanResult(
			vulnerabilities=vulnerabilities,
			raw_outputs=[output for output in raw_outputs if output],
			metadata=metadata,
		)

	def _run_command(self, command: list[str]) -> subprocess.CompletedProcess[str]:
		LOGGER.debug("Running ffuf command: %s", " ".join(command))
		try:
			return subprocess.run(
				command,
				check=False,
				capture_output=True,
				text=True,
				timeout=self.timeout_seconds,
			)
		except FileNotFoundError:
			LOGGER.exception("ffuf binary not found: %s", self.binary_path)
			return subprocess.CompletedProcess(args=command, returncode=127, stdout="", stderr="binary not found")
		except subprocess.TimeoutExpired:
			LOGGER.exception("ffuf command timed out")
			return subprocess.CompletedProcess(args=command, returncode=124, stdout="", stderr="command timed out")

	def _parse_ffuf_json(self, output_path: Path, endpoint: Endpoint) -> list[Vulnerability]:
		vulnerabilities: list[Vulnerability] = []
		try:
			payload = json.loads(output_path.read_text(encoding="utf-8"))
		except (FileNotFoundError, json.JSONDecodeError):
			LOGGER.exception("Failed to parse ffuf output JSON: %s", output_path)
			return vulnerabilities
		finally:
			if output_path.exists():
				output_path.unlink()

		results = payload.get("results", [])
		for item in results:
			discovered_url = str(item.get("url", endpoint.url))
			status_code = int(item.get("status", 0))
			payload_used = str(item.get("input", {}).get("FUZZ", ""))

			discovered_endpoint = Endpoint(
				url=discovered_url,
				method=endpoint.method,
				params=set(endpoint.params),
				headers=dict(endpoint.headers),
			)
			vulnerabilities.append(
				Vulnerability(
					vuln_type="content_discovery",
					endpoint=discovered_endpoint,
					severity="low",
					payloads=[payload_used] if payload_used else [],
					evidence=[f"ffuf status={status_code}"],
					confidence=self._confidence_from_status(status_code),
				)
			)

		return vulnerabilities

	def _confidence_from_status(self, status_code: int) -> float:
		if status_code >= 500:
			return 0.4
		if status_code >= 400:
			return 0.5
		if status_code >= 300:
			return 0.6
		if status_code >= 200:
			return 0.7
		return 0.3
