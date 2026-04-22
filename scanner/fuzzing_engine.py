from __future__ import annotations

from concurrent.futures import Future, ThreadPoolExecutor, as_completed
import logging
from dataclasses import dataclass
from typing import Protocol

from data.models import Endpoint, ScanResult, Target, Vulnerability


LOGGER = logging.getLogger(__name__)


class EndpointScanner(Protocol):
	def scan_endpoint(self, endpoint: Endpoint) -> ScanResult:
		"""Scan a single endpoint and return a structured ScanResult."""


@dataclass(slots=True)
class FuzzingEngine:
	scanners: list[EndpointScanner]
	max_workers: int
	focus_mode: bool = False

	def scan_target(self, target: Target) -> ScanResult:
		if self.max_workers <= 0:
			raise ValueError("max_workers must be greater than 0")

		# 1. Filter endpoints for Focus Mode
		endpoints_to_scan = list(target.endpoints)
		if self.focus_mode:
			LOGGER.info("Focus Scanning Mode active. Filtering low-value endpoints.")
			# Prioritize high-value targets (admin, api, auth)
			# Skip low-priority targets (static assets, etc.)
			endpoints_to_scan = [
				ep for ep in endpoints_to_scan 
				if ep.priority >= 0.5 or any(kw in ep.url.lower() for kw in {"admin", "api", "auth", "token"})
			]
			LOGGER.info("Focus Mode reduced target set from %d to %d", len(target.endpoints), len(endpoints_to_scan))

		# Sort by priority desc then by url
		endpoints_to_scan.sort(key=lambda ep: ep.priority, reverse=True)

		aggregated_vulnerabilities: list[Vulnerability] = []
		aggregated_outputs: list[str] = []
		errors: list[dict[str, str]] = []
		metadata: dict[str, object] = {
			"scanner_count": len(self.scanners),
			"endpoint_count": len(endpoints_to_scan),
			"focus_mode": self.focus_mode,
			"errors": errors,
			"max_workers": self.max_workers,
		}

		futures: dict[Future[ScanResult], tuple[str, str]] = {}
		with ThreadPoolExecutor(max_workers=self.max_workers) as executor:
			for endpoint in endpoints_to_scan:
				for scanner in self.scanners:
					scanner_name = scanner.__class__.__name__
					future = executor.submit(scanner.scan_endpoint, endpoint)
					futures[future] = (scanner_name, endpoint.url)

			for future in as_completed(futures):
				scanner_name, endpoint_url = futures[future]
				try:
					result = future.result()
					aggregated_vulnerabilities.extend(result.vulnerabilities)
					aggregated_outputs.extend(result.raw_outputs)
				except Exception as error:
					LOGGER.exception(
						"Scanner %s failed on endpoint %s",
						scanner_name,
						endpoint_url,
					)
					errors.append(
						{
							"scanner": scanner_name,
							"endpoint": endpoint_url,
							"error": str(error),
						}
					)

		metadata["vulnerability_count"] = len(aggregated_vulnerabilities)
		return ScanResult(
			vulnerabilities=aggregated_vulnerabilities,
			raw_outputs=aggregated_outputs,
			metadata=metadata,
		)
