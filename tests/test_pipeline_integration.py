from __future__ import annotations

import tempfile
import types
import unittest
from pathlib import Path
from unittest.mock import patch

import sys

if "yaml" not in sys.modules:
	yaml_module = types.ModuleType("yaml")

	def _safe_load(_: object) -> dict[str, object]:
		return {}

	yaml_module.safe_load = _safe_load
	sys.modules["yaml"] = yaml_module

if "bs4" not in sys.modules:
	bs4_module = types.ModuleType("bs4")

	class _BeautifulSoup:  # pragma: no cover - import shim for environments without bs4
		def __init__(self, html: str, parser: str) -> None:
			self._html = html

		def find_all(self, *args: object, **kwargs: object) -> list[object]:
			return []

	bs4_module.BeautifulSoup = _BeautifulSoup
	sys.modules["bs4"] = bs4_module

from data.models import Endpoint, ScanResult, Vulnerability
from core.config import (
    Settings,
    ReconConfig,
    ScannerConfig,
    AIConfig,
    AnalysisConfig,
    ReportConfig,
    LoggingConfig, # Added LoggingConfig as it's used in the new config structure
)
from core.pipeline import ReportBundle
from main import (  # noqa: E402
    build_engine,
    configure_logging,
	run_pipeline,
)


class TestFullPipelineIntegration(unittest.TestCase):
	def test_full_pipeline_runs_end_to_end(self) -> None:
		with tempfile.TemporaryDirectory() as temp_dir_str:
			temp_dir = Path(temp_dir_str)
			report_output = temp_dir / "reports"

			logging_config = LoggingConfig(level="INFO")
			recon_config = ReconConfig(
				candidate_subdomains={"www"},
				seed_schemes={"https"},
				crawler_max_pages=5,
				crawler_user_agent="raven-ai-tests",
				crawler_allowed_schemes={"https"},
				headless_enabled=False,
				max_browsers=1,
				crawl_depth=1,
				js_analysis_enabled=False,
			)
			scanner_config = ScannerConfig(
				max_workers=2,
				user_agent="raven-ai-tests",
				xss_reflection_markers=["script"],
				xss_min_confidence=0.6,
				xss_severity="medium",
				sqli_error_signatures=["sql syntax", "mysql"],
				sqli_min_confidence=0.6,
				sqli_severity="high",
				replay_enabled=True,
			)
			ai_config = AIConfig(
				provider_name="test-provider",
				model="test-model",
				api_key="test-key",
				base_url=None,
				constraints=["existing findings only"],
				min_confidence=0.5,
				max_payloads_per_vuln=5,
				allowed_severities={"low", "medium", "high", "critical"},
				prompts={
					"payload_generator": "Enhance payloads for {vuln_type} at {endpoint_url}: {existing_payloads}",
					"response_analyzer": "Analyze evidence for {vuln_type} at {endpoint_url}",
					"vuln_classifier": "Classify {vuln_type} at {endpoint_url} severity={current_severity}",
				},
			)
			analysis_config = AnalysisConfig(
				severity_weights={"low": 1.0, "medium": 2.0, "high": 3.0, "critical": 4.0},
				exploit_chaining_enabled=True,
				prioritization_enabled=True,
				token_extraction_enabled=True
			)
			report_config = ReportConfig(
				templates_dir=Path("reports/templates"),
				output_dir=report_output,
				template_map={"xss": "xss.md", "sqli": "sqli.md"},
			)

			from core.config import ScanControls, VectorSpaceConfig, ScopeConfig
			
			config = Settings(
				target_domain="example.com",
				logging=logging_config,
				scope=ScopeConfig(
					allowed_domains={"example.com"},
					blocked_domains=set(),
					allow_subdomains=True
				),
				recon=recon_config,
				scanner=scanner_config,
				ai=ai_config,
				analysis=analysis_config,
				report=report_config,
				scan_controls=ScanControls(
					depth=3,
					rate_limits={"global": 0.03},
					enabled_modules={"xss": True, "sqli": True},
					timeouts={"request": 10.0},
					bug_bounty_mode=True
				),
				vector_space=VectorSpaceConfig(
					dimension=128, 
					backend_preference="numpy", 
					min_similarity=0.8,
					top_k_default=5,
					dedup_enabled=True
				)
			)

			def _mock_subdomain_discover(self: object, target: object) -> object:
				target.subdomains.add("www.example.com")
				return target

			def _mock_endpoint_discover(self: object, target: object) -> object:
				target.add_endpoint(Endpoint(url="https://example.com/search", method="GET", params={"q"}))
				return target

			def _mock_scan_target(self: object, target: object) -> ScanResult:
				endpoint = Endpoint(url="https://example.com/search", method="GET", params={"q"})
				vuln = Vulnerability(
					vuln_type="xss",
					endpoint=endpoint,
					severity="medium",
					payloads=["<script>alert(1)</script>"],
					evidence=["reflected payload"],
					confidence=0.8,
				)
				return ScanResult(vulnerabilities=[vuln], raw_outputs=[], metadata={"source": "mock"})

			with (
				patch("recon.subdomain.SubdomainDiscoverer.discover", _mock_subdomain_discover),
				patch("recon.endpoint_discovery.EndpointDiscovery.discover", _mock_endpoint_discover),
				patch("scanner.fuzzing_engine.FuzzingEngine.scan_target", _mock_scan_target),
			):
				result = run_pipeline(config)

			self.assertIsInstance(result, ReportBundle)
			self.assertGreaterEqual(len(result.scan_result.vulnerabilities), 1)
			self.assertGreaterEqual(len(result.exported_reports), 1)
			self.assertTrue((report_output / "index.md").exists())


if __name__ == "__main__":
	unittest.main()