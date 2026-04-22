from __future__ import annotations

import argparse
import logging
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from ai.llm_client import CallableLLMClient, LLMClient, LLMRequest, LLMResponse
from ai.payload_generator import AIInsight, PayloadGenerator
from ai.response_analyzer import ResponseAnalyzer
from ai.vuln_classifier import VulnerabilityClassifier
from analysis.correlator import CorrelationMap, Correlator
from analysis.deduplicator import Deduplicator
from analysis.exploit_chain import AttackGraph, ExploitChainBuilder
from analysis.risk_scoring import RiskScorer
from core.engine import Engine
from core.pipeline import (
    AIBundle,
    AnalysisBundle,
    AnalysisStage,
    AIStage,
    Pipeline,
    ReconBundle,
    ReconStage,
    ReportBundle,
    ReportStage,
    ScanBundle,
    ScanStage,
)
from data.models import ScanResult, Target, Vulnerability
from recon.crawler import BasicCrawler
from recon.endpoint_discovery import EndpointDiscovery
from recon.headless_crawler import HeadlessCrawler
from recon.js_analyzer import JSAnalyzer
from recon.subdomain import SubdomainDiscoverer
from reports.exporter import ExportedReport, ReportExporter
from reports.report_builder import ReportBuilder, VulnerabilityReport
from scanner.fuzzing_engine import FuzzingEngine
from scanner.sqli_scanner import SQLiScanner
from scanner.xss_scanner import XSSScanner
from analysis.exploit_executor import ExploitExecutor
from utils.http_client import HTTPClient


LOGGER = logging.getLogger(__name__)


try:
	import yaml
except ImportError as import_error:
	raise RuntimeError("PyYAML is required to run this project") from import_error


from core.config import Settings, load_settings, AIConfig
from core.engine import Engine
from data.models import Target
from utils.http_client import HTTPClient


LOGGER = logging.getLogger(__name__)


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
			base_url=config.base_url or "https://api.openai.com/v1"
		)
	elif provider == "openrouter":
		from ai.llm_client import OpenRouterClient
		return OpenRouterClient(
			api_key=config.api_key or "",
			model=config.model,
			base_url=config.base_url or "https://openrouter.ai/api/v1"
		)
	elif provider == "local":
		from ai.llm_client import LocalOllamaClient
		return LocalOllamaClient(
			model=config.model,
			base_url=config.base_url or "http://localhost:11434"
		)
	
	# Fallback to deterministic mockup for testing
	def _completion(request: LLMRequest) -> LLMResponse:
		vulnerability = request.context.get("vulnerability")
		if not isinstance(vulnerability, dict):
			return LLMResponse(content="No structured vulnerability context supplied.", confidence=0.0)

		if "output_format" in request.context:
			severity = str(vulnerability.get("severity", "medium"))
			confidence = float(vulnerability.get("confidence", 0.5))
			return LLMResponse(
				content=f"severity={severity}\nconfidence={confidence}",
				confidence=confidence,
			)

		if "payloads" in request.prompt.lower() or "enhance payloads" in str(request.context.get("instruction", "")).lower():
			existing_payloads = vulnerability.get("payloads", [])
			if isinstance(existing_payloads, list):
				content = "\n".join(f"- {payload}" for payload in existing_payloads)
			else:
				content = ""
			return LLMResponse(content=content, confidence=float(vulnerability.get("confidence", 0.5)))

		vuln_type = str(vulnerability.get("vuln_type", "unknown"))
		endpoint = vulnerability.get("endpoint", {})
		endpoint_url = ""
		if isinstance(endpoint, dict):
			endpoint_url = str(endpoint.get("url", ""))
		content = f"Existing {vuln_type} evidence observed at {endpoint_url}."
		return LLMResponse(content=content, confidence=float(vulnerability.get("confidence", 0.5)))

	return CallableLLMClient(provider_name=provider, completion_callable=_completion)
	provider = config.provider_name.lower()
	
	if provider == "openai":
		from ai.llm_client import OpenAIClient
		return OpenAIClient(
			api_key=config.api_key or "",
			model=config.model,
			base_url=config.base_url or "https://api.openai.com/v1"
		)
	elif provider == "openrouter":
		from ai.llm_client import OpenRouterClient
		return OpenRouterClient(
			api_key=config.api_key or "",
			model=config.model,
			base_url=config.base_url or "https://openrouter.ai/api/v1"
		)
	elif provider == "local":
		from ai.llm_client import LocalOllamaClient
		return LocalOllamaClient(
			model=config.model,
			base_url=config.base_url or "http://localhost:11434"
		)
	
	# Fallback to deterministic mockup for testing
	def _completion(request: LLMRequest) -> LLMResponse:
		vulnerability = request.context.get("vulnerability")
		if not isinstance(vulnerability, dict):
			return LLMResponse(content="No structured vulnerability context supplied.", confidence=0.0)

		if "output_format" in request.context:
			severity = str(vulnerability.get("severity", "medium"))
			confidence = float(vulnerability.get("confidence", 0.5))
			return LLMResponse(
				content=f"severity={severity}\nconfidence={confidence}",
				confidence=confidence,
			)

		if "payloads" in request.prompt.lower() or "enhance payloads" in str(request.context.get("instruction", "")).lower():
			existing_payloads = vulnerability.get("payloads", [])
			if isinstance(existing_payloads, list):
				content = "\n".join(f"- {payload}" for payload in existing_payloads)
			else:
				content = ""
			return LLMResponse(content=content, confidence=float(vulnerability.get("confidence", 0.5)))

		vuln_type = str(vulnerability.get("vuln_type", "unknown"))
		endpoint = vulnerability.get("endpoint", {})
		endpoint_url = ""
		if isinstance(endpoint, dict):
			endpoint_url = str(endpoint.get("url", ""))
		content = f"Existing {vuln_type} evidence observed at {endpoint_url}."
		return LLMResponse(content=content, confidence=float(vulnerability.get("confidence", 0.5)))

	return CallableLLMClient(provider_name=provider_name, completion_callable=_completion)


def configure_logging(logging_config: LoggingConfig) -> None:
	level_name = logging_config.level.upper()
	level = getattr(logging, level_name, None)
	if not isinstance(level, int):
		raise ValueError(f"Invalid logging level configured: {logging_config.level}")

	logging.basicConfig(
		level=level,
		format="%(asctime)s %(levelname)s %(name)s %(message)s",
	)


def build_engine(config: Settings) -> Engine:
	llm_client = build_llm_client(config.ai)
	
	from utils.http_client import HTTPClient, HTTPClientConfig
	http_client = HTTPClient(HTTPClientConfig(
		timeout_seconds=config.scan_controls.timeouts.get("request", 10.0),
		user_agent=config.scanner.user_agent
	))

	subdomain_discoverer = SubdomainDiscoverer(
		candidate_labels=config.recon.candidate_subdomains,
		dns_timeout_seconds=config.scan_controls.timeouts.get("dns", 2.0),
	)
	crawler = BasicCrawler(
		client=http_client,
		max_pages=config.recon.crawler_max_pages,
	)
	headless_crawler = HeadlessCrawler() if config.recon.headless_enabled else None
	js_analyzer = JSAnalyzer() if config.recon.js_analysis_enabled else None
	
	endpoint_discovery = EndpointDiscovery(
		crawler=crawler, 
		headless_crawler=headless_crawler,
		js_analyzer=js_analyzer,
		seed_schemes=config.recon.seed_schemes
	)

	# Recon Prioritizer
	prioritizer = None
	if config.analysis.prioritization_enabled:
		from analysis.prioritizer import EndpointPrioritizer
		prioritizer = EndpointPrioritizer()

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
	
	from scanner.idor_scanner import IDORScanner
	from scanner.auth_scanner import AuthScanner
	
	idor_scanner = IDORScanner(client=http_client)
	auth_scanner = AuthScanner(client=http_client)

	fuzzing_engine = FuzzingEngine(
		scanners=[xss_scanner, sqli_scanner, idor_scanner, auth_scanner],
		max_workers=config.scanner.max_workers,
		focus_mode=config.scan_controls.bug_bounty_mode
	)

	payload_generator = PayloadGenerator(
		llm_client=llm_client,
		prompt_template=config.ai.prompts.get("payload_generator", ""),
		constraints=list(config.ai.constraints),
		max_payloads_per_vuln=config.ai.max_payloads_per_vuln,
		min_ai_confidence=config.ai.min_confidence,
	)
	response_analyzer = ResponseAnalyzer(
		llm_client=llm_client,
		prompt_template=config.ai.prompts.get("response_analyzer", ""),
		constraints=list(config.ai.constraints),
		min_ai_confidence=config.ai.min_confidence,
	)
	vulnerability_classifier = VulnerabilityClassifier(
		llm_client=llm_client,
		prompt_template=config.ai.prompts.get("vuln_classifier", ""),
		constraints=list(config.ai.constraints),
		allowed_severities=config.ai.allowed_severities,
		min_ai_confidence=config.ai.min_confidence,
	)

	deduplicator = Deduplicator()
	risk_scorer = RiskScorer(severity_weights=config.analysis.severity_weights)
	correlator = Correlator()
	exploit_chain_builder = ExploitChainBuilder(severity_weights=config.analysis.severity_weights)

	# Exploit Executor integration
	exploit_executor = ExploitExecutor(client=http_client)

	report_builder = ReportBuilder(
		templates_dir=config.report.templates_dir,
		template_map=config.report.template_map,
	)
	report_exporter = ReportExporter(output_dir=config.report.output_dir)

	engine = Engine()
	engine.add_stage(ReconStage(
		subdomain_discoverer=subdomain_discoverer, 
		endpoint_discovery=endpoint_discovery,
		prioritizer=prioritizer
	))
	engine.add_stage(ScanStage(fuzzing_engine=fuzzing_engine))
	engine.add_stage(
		AIStage(
			payload_generator=payload_generator,
			response_analyzer=response_analyzer,
			vulnerability_classifier=vulnerability_classifier,
		)
	)
	engine.add_stage(
		AnalysisStage(
			deduplicator=deduplicator,
			risk_scorer=risk_scorer,
			correlator=correlator,
			exploit_chain_builder=exploit_chain_builder,
			exploit_executor=exploit_executor,
		)
	)
	engine.add_stage(ReportStage(report_builder=report_builder, report_exporter=report_exporter))

	return engine


def _load_payloads(vuln_type: str) -> list[str]:
	"""Helper to load payloads from configs/payloads.yaml."""
	path = Path("configs/payloads.yaml")
	if not path.exists():
		return []
	try:
		with path.open("r") as f:
			data = yaml.safe_load(f)
			return data.get(vuln_type, {}).get("payloads", [])
	except Exception:
		return []


def run_pipeline(config: Settings) -> ReportBundle:
	engine = build_engine(config)
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
		choices=["full", "recon", "scan", "ai", "analysis", "report"],
		help="Pipeline execution mode",
	)
	parser.add_argument("--output", help="Override report output directory")
	args = parser.parse_args()

	settings_path = Path("configs/settings.yaml")
	config = load_runtime_config(settings_path)

	# Overrides
	target_domain = args.target if args.target else config.target_domain
	output_dir = Path(args.output) if args.output else config.report.output_dir

	# We create a new Settings object with overrides if necessary
	# Dataclasses are frozen, so we use replace or similar if needed, 
	# but for simplicity we just use the loaded config and handle overrides in target creation.
	
	configure_logging(config.logging)

	LOGGER.info("Starting pipeline mode=%s for domain=%s", args.mode, target_domain)

	# Update target domain in config for this run
	# Since Settings is frozen, we just use the local target_domain variable
	
	engine = build_engine(config)
	target = Target(domain=target_domain)
	
	result = engine.run(target)
	
	LOGGER.info("Pipeline complete.")
	return 0


if __name__ == "__main__":
	main()
