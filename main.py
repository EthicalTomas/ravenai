from __future__ import annotations

import argparse
import logging
from pathlib import Path

try:
	import yaml
except ImportError as import_error:
	raise RuntimeError("PyYAML is required to run this project") from import_error

from ai.llm_client import CallableLLMClient, LLMClient, LLMRequest, LLMResponse
from ai.payload_generator import PayloadGenerator
from ai.response_analyzer import ResponseAnalyzer
from ai.vuln_classifier import VulnerabilityClassifier
from analysis.correlator import Correlator
from analysis.deduplicator import Deduplicator
from analysis.exploit_chain import ExploitChainBuilder
from analysis.exploit_executor import ExploitExecutor
from analysis.risk_scoring import RiskScorer
from core.config import AIConfig, LoggingConfig, Settings, load_settings
from core.engine import Engine
from core.pipeline import (
	AIStage,
	AnalysisStage,
	ReconStage,
	ReportBundle,
	ReportStage,
	ScanStage,
)
from data.models import Target
from recon.crawler import BasicCrawler
from recon.endpoint_discovery import EndpointDiscovery
from recon.headless_crawler import HeadlessCrawler
from recon.js_analyzer import JSAnalyzer
from recon.subdomain import SubdomainDiscoverer
from reports.exporter import ReportExporter
from reports.report_builder import ReportBuilder
from scanner.auth_scanner import AuthScanner
from scanner.fuzzing_engine import FuzzingEngine
from scanner.idor_scanner import IDORScanner
from scanner.sqli_scanner import SQLiScanner
from scanner.xss_scanner import XSSScanner
from utils.http_client import HTTPClient, HTTPClientConfig


LOGGER = logging.getLogger(__name__)
SUPPORTED_MODES = {"full", "recon", "scan", "ai", "analysis", "report"}
_PAYLOAD_CACHE: dict[str, list[str]] | None = None


def load_runtime_config(settings_path: Path) -> Settings:
	"""Load settings using the centralized core/config loader."""
	return load_settings(settings_path)


def build_llm_client(config: AIConfig) -> LLMClient:
	provider = config.provider_name.lower()

	if provider == "openai":
		from ai.llm_client import OpenAIClient

		return OpenAIClient(
			api_key=config.api_key or "",
			model=config.model,
			base_url=config.base_url or "https://api.openai.com/v1",
		)
	if provider == "openrouter":
		from ai.llm_client import OpenRouterClient

		return OpenRouterClient(
			api_key=config.api_key or "",
			model=config.model,
			base_url=config.base_url or "https://openrouter.ai/api/v1",
		)
	if provider == "local":
		from ai.llm_client import LocalOllamaClient

		return LocalOllamaClient(
			model=config.model,
			base_url=config.base_url or "http://localhost:11434",
		)

	def _completion(request: LLMRequest) -> LLMResponse:
		vulnerability = request.context.get("vulnerability")
		if not isinstance(vulnerability, dict):
			return LLMResponse(content="No structured vulnerability context supplied.", confidence=0.0)

		if "output_format" in request.context:
			severity = str(vulnerability.get("severity", "medium"))
			confidence = float(vulnerability.get("confidence", 0.5))
			return LLMResponse(content=f"severity={severity}\nconfidence={confidence}", confidence=confidence)

		if "payloads" in request.prompt.lower() or "enhance payloads" in str(
			request.context.get("instruction", "")
		).lower():
			existing_payloads = vulnerability.get("payloads", [])
			if isinstance(existing_payloads, list):
				content = "\n".join(f"- {payload}" for payload in existing_payloads)
			else:
				content = ""
			return LLMResponse(content=content, confidence=float(vulnerability.get("confidence", 0.5)))

		vuln_type = str(vulnerability.get("vuln_type", "unknown"))
		endpoint = vulnerability.get("endpoint", {})
		endpoint_url = str(endpoint.get("url", "")) if isinstance(endpoint, dict) else ""
		content = f"Existing {vuln_type} evidence observed at {endpoint_url}."
		return LLMResponse(content=content, confidence=float(vulnerability.get("confidence", 0.5)))

	return CallableLLMClient(provider_name=provider, completion_callable=_completion)


def configure_logging(logging_config: LoggingConfig) -> None:
	level_name = logging_config.level.upper()
	level = getattr(logging, level_name, None)
	if not isinstance(level, int):
		raise ValueError(f"Invalid logging level configured: {logging_config.level}")

	logging.basicConfig(level=level, format="%(asctime)s %(levelname)s %(name)s %(message)s")


def _require_mode(mode: str) -> str:
	normalized = mode.lower()
	if normalized not in SUPPORTED_MODES:
		raise ValueError(f"Unsupported mode: {mode}")
	return normalized


def _timeout_from(config: Settings, default: float, *keys: str) -> float:
	for key in keys:
		value = config.scan_controls.timeouts.get(key)
		if isinstance(value, (int, float)):
			return float(value)
	return default


def _load_all_payloads() -> dict[str, list[str]]:
	global _PAYLOAD_CACHE
	if _PAYLOAD_CACHE is not None:
		return _PAYLOAD_CACHE

	path = Path("configs/payloads.yaml")
	if not path.exists():
		_PAYLOAD_CACHE = {}
		return _PAYLOAD_CACHE

	try:
		with path.open("r", encoding="utf-8") as file:
			data = yaml.safe_load(file)
	except Exception:
		_PAYLOAD_CACHE = {}
		return _PAYLOAD_CACHE

	if not isinstance(data, dict):
		_PAYLOAD_CACHE = {}
		return _PAYLOAD_CACHE

	normalized: dict[str, list[str]] = {}
	for vuln_type, values in data.items():
		if not isinstance(vuln_type, str) or not isinstance(values, dict):
			continue
		payloads = values.get("payloads", [])
		if isinstance(payloads, list):
			normalized[vuln_type] = [str(item) for item in payloads]
	_PAYLOAD_CACHE = normalized
	return _PAYLOAD_CACHE


def _load_payloads(vuln_type: str) -> list[str]:
	return list(_load_all_payloads().get(vuln_type, []))


def build_engine(config: Settings, mode: str = "full", output_dir_override: Path | None = None) -> Engine:
	mode = _require_mode(mode)

	llm_client = build_llm_client(config.ai)
	http_client = HTTPClient(
		HTTPClientConfig(
			timeout_seconds=_timeout_from(config, 10.0, "request", "http_seconds"),
			user_agent=config.scanner.user_agent,
		)
	)

	subdomain_discoverer = SubdomainDiscoverer(
		candidate_labels=config.recon.candidate_subdomains,
		dns_timeout_seconds=_timeout_from(config, 2.0, "dns", "dns_seconds"),
	)
	crawler = BasicCrawler(client=http_client, max_pages=config.recon.crawler_max_pages)
	headless_crawler = HeadlessCrawler() if config.recon.headless_enabled else None
	js_analyzer = JSAnalyzer() if config.recon.js_analysis_enabled else None
	endpoint_discovery = EndpointDiscovery(
		crawler=crawler,
		headless_crawler=headless_crawler,
		js_analyzer=js_analyzer,
		seed_schemes=config.recon.seed_schemes,
	)

	prioritizer = None
	if config.analysis.prioritization_enabled:
		from analysis.prioritizer import EndpointPrioritizer

		prioritizer = EndpointPrioritizer()

	engine = Engine()
	engine.add_stage(
		ReconStage(
			subdomain_discoverer=subdomain_discoverer,
			endpoint_discovery=endpoint_discovery,
			prioritizer=prioritizer,
		)
	)
	if mode == "recon":
		return engine

	xss_scanner = XSSScanner(
		client=http_client,
		payloads=_load_payloads("xss"),
		reflection_markers=config.scanner.xss_reflection_markers,
		min_confidence=config.scanner.xss_min_confidence,
		severity=config.scanner.xss_severity,
	)
	sqli_scanner = SQLiScanner(
		client=http_client,
		payloads=_load_payloads("sqli"),
		error_signatures=config.scanner.sqli_error_signatures,
		min_confidence=config.scanner.sqli_min_confidence,
		severity=config.scanner.sqli_severity,
	)
	fuzzing_engine = FuzzingEngine(
		scanners=[xss_scanner, sqli_scanner, IDORScanner(client=http_client), AuthScanner(client=http_client)],
		max_workers=config.scanner.max_workers,
		focus_mode=config.scan_controls.bug_bounty_mode,
	)
	engine.add_stage(ScanStage(fuzzing_engine=fuzzing_engine))
	if mode == "scan":
		return engine

	engine.add_stage(
		AIStage(
			payload_generator=PayloadGenerator(
				llm_client=llm_client,
				prompt_template=config.ai.prompts.get("payload_generator", ""),
				constraints=list(config.ai.constraints),
				max_payloads_per_vuln=config.ai.max_payloads_per_vuln,
				min_ai_confidence=config.ai.min_confidence,
			),
			response_analyzer=ResponseAnalyzer(
				llm_client=llm_client,
				prompt_template=config.ai.prompts.get("response_analyzer", ""),
				constraints=list(config.ai.constraints),
				min_ai_confidence=config.ai.min_confidence,
			),
			vulnerability_classifier=VulnerabilityClassifier(
				llm_client=llm_client,
				prompt_template=config.ai.prompts.get("vuln_classifier", ""),
				constraints=list(config.ai.constraints),
				allowed_severities=config.ai.allowed_severities,
				min_ai_confidence=config.ai.min_confidence,
			),
		)
	)
	if mode == "ai":
		return engine

	engine.add_stage(
		AnalysisStage(
			deduplicator=Deduplicator(),
			risk_scorer=RiskScorer(severity_weights=config.analysis.severity_weights),
			correlator=Correlator(),
			exploit_chain_builder=ExploitChainBuilder(severity_weights=config.analysis.severity_weights),
			exploit_executor=ExploitExecutor(client=http_client),
		)
	)
	if mode == "analysis":
		return engine

	engine.add_stage(
		ReportStage(
			report_builder=ReportBuilder(
				templates_dir=config.report.templates_dir,
				template_map=config.report.template_map,
			),
			report_exporter=ReportExporter(output_dir=output_dir_override or config.report.output_dir),
		)
	)
	return engine


def run_pipeline(config: Settings) -> ReportBundle:
	engine = build_engine(config, mode="full")
	target = Target(domain=config.target_domain)
	result = engine.run(target)
	if not isinstance(result, ReportBundle):
		raise TypeError("Pipeline did not return ReportBundle")
	return result


def main() -> int:
	parser = argparse.ArgumentParser(description="Raven AI bug hunting pipeline")
	parser.add_argument("--target", help="Target domain to scan (overrides config)")
	parser.add_argument(
		"--mode",
		default="full",
		choices=sorted(SUPPORTED_MODES),
		help="Pipeline execution mode",
	)
	parser.add_argument("--output", help="Override report output directory")
	args = parser.parse_args()

	config = load_runtime_config(Path("configs/settings.yaml"))
	configure_logging(config.logging)

	target_domain = args.target or config.target_domain
	output_dir_override = Path(args.output) if args.output else None

	LOGGER.info("Starting pipeline mode=%s for domain=%s", args.mode, target_domain)
	engine = build_engine(config, mode=args.mode, output_dir_override=output_dir_override)
	result = engine.run(Target(domain=target_domain))
	if isinstance(result, ReportBundle):
		LOGGER.info("Pipeline complete with %d reports.", len(result.exported_reports))
	else:
		LOGGER.info("Pipeline complete for mode=%s.", args.mode)
	return 0


if __name__ == "__main__":
	main()
