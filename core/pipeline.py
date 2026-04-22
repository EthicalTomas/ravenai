"""core/pipeline.py

Pipeline orchestration and stage definitions for the Raven AI security engine.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass, field
from typing import Any

from ai.payload_generator import AIInsight, PayloadGenerator
from ai.response_analyzer import ResponseAnalyzer
from ai.vuln_classifier import VulnerabilityClassifier
from analysis.correlator import CorrelationMap, Correlator
from analysis.deduplicator import Deduplicator
from analysis.exploit_chain import AttackGraph, ExploitChainBuilder
from analysis.exploit_executor import ExploitExecutor
from analysis.risk_scoring import RiskScorer
from core.engine import Engine, Stage
from data.models import ScanResult, Target, Vulnerability
from recon.crawler import BasicCrawler
from recon.endpoint_discovery import EndpointDiscovery
from recon.headless_crawler import HeadlessCrawler
from recon.js_analyzer import JSAnalyzer
from recon.subdomain import SubdomainDiscoverer
from analysis.prioritizer import EndpointPrioritizer
from reports.exporter import ExportedReport, ReportExporter
from reports.report_builder import ReportBuilder, VulnerabilityReport


LOGGER = logging.getLogger(__name__)


@dataclass(slots=True)
class ReconBundle:
	target: Target


@dataclass(slots=True)
class ScanBundle:
	target: Target
	scan_result: ScanResult


@dataclass(slots=True)
class AIBundle:
	target: Target
	scan_result: ScanResult
	insights: list[AIInsight] = field(default_factory=list)


@dataclass(slots=True)
class AnalysisBundle:
	target: Target
	scan_result: ScanResult
	insights: list[AIInsight]
	correlation_map: CorrelationMap
	attack_graph: AttackGraph


@dataclass(slots=True)
class ReportBundle:
	target: Target
	scan_result: ScanResult
	insights: list[AIInsight]
	reports: list[VulnerabilityReport]
	exported_reports: list[ExportedReport]


class ReconStage(Stage):
	def __init__(
		self, 
		subdomain_discoverer: SubdomainDiscoverer, 
		endpoint_discovery: EndpointDiscovery,
		prioritizer: EndpointPrioritizer | None = None
	) -> None:
		super().__init__(name="ReconStage")
		self._subdomain_discoverer = subdomain_discoverer
		self._endpoint_discovery = endpoint_discovery
		self._prioritizer = prioritizer

	def execute(self, data: object) -> ReconBundle:
		if not isinstance(data, Target):
			raise TypeError("ReconStage expects Target input")

		LOGGER.info("Recon stage started")
		target = self._subdomain_discoverer.discover(data)
		
		# EndpointDiscovery now coordinates HeadlessCrawler and JSAnalyzer internally if configured
		target = self._endpoint_discovery.discover(target)
		
		# 3. Prioritization
		if self._prioritizer:
			LOGGER.info("Prioritizing discovered endpoints")
			self._prioritizer.prioritize(target.endpoints)
		
		LOGGER.info("Recon stage completed with %d endpoints", len(target.endpoints))
		return ReconBundle(target=target)


class ScanStage(Stage):
	def __init__(self, fuzzing_engine: FuzzingEngine) -> None:
		super().__init__(name="ScanStage")
		self._fuzzing_engine = fuzzing_engine

	def execute(self, data: object) -> ScanBundle:
		if not isinstance(data, ReconBundle):
			raise TypeError("ScanStage expects ReconBundle input")

		LOGGER.info("Scan stage started")
		scan_result = self._fuzzing_engine.scan_target(data.target)
		LOGGER.info("Scan stage completed with %d findings", len(scan_result.vulnerabilities))
		return ScanBundle(target=data.target, scan_result=scan_result)


class AIStage(Stage):
	def __init__(
		self,
		payload_generator: PayloadGenerator,
		response_analyzer: ResponseAnalyzer,
		vulnerability_classifier: VulnerabilityClassifier,
	) -> None:
		super().__init__(name="AIStage")
		self._payload_generator = payload_generator
		self._response_analyzer = response_analyzer
		self._vulnerability_classifier = vulnerability_classifier

	def execute(self, data: object) -> AIBundle:
		if not isinstance(data, ScanBundle):
			raise TypeError("AIStage expects ScanBundle input")

		LOGGER.info("AI stage started")
		if not data.scan_result.vulnerabilities:
			LOGGER.info("AI stage skipped because no findings were produced by scanning")
			return AIBundle(target=data.target, scan_result=data.scan_result, insights=[])

		grouped = self._group_by_endpoint(data.scan_result.vulnerabilities)
		enriched_vulnerabilities: list[Vulnerability] = []
		insights: list[AIInsight] = []

		for endpoint_key in sorted(grouped):
			endpoint_vulnerabilities = grouped[endpoint_key]
			endpoint = endpoint_vulnerabilities[0].endpoint
			endpoint_result = ScanResult(
				vulnerabilities=endpoint_vulnerabilities,
				raw_outputs=list(data.scan_result.raw_outputs),
				metadata=dict(data.scan_result.metadata),
			)

			classified = self._vulnerability_classifier.classify(endpoint=endpoint, scan_result=endpoint_result)
			classified_result = ScanResult(
				vulnerabilities=classified,
				raw_outputs=list(endpoint_result.raw_outputs),
				metadata=dict(endpoint_result.metadata),
			)

			enhanced, payload_insights = self._payload_generator.enhance(
				endpoint=endpoint,
				scan_result=classified_result,
			)
			enhanced_result = ScanResult(
				vulnerabilities=enhanced,
				raw_outputs=list(classified_result.raw_outputs),
				metadata=dict(classified_result.metadata),
			)

			analysis_insights = self._response_analyzer.analyze(endpoint=endpoint, scan_result=enhanced_result)

			enriched_vulnerabilities.extend(enhanced)
			insights.extend(payload_insights)
			insights.extend(analysis_insights)

		metadata = dict(data.scan_result.metadata)
		metadata["ai_insight_count"] = len(insights)
		enriched_scan_result = ScanResult(
			vulnerabilities=enriched_vulnerabilities,
			raw_outputs=list(data.scan_result.raw_outputs),
			metadata=metadata,
		)

		LOGGER.info("AI stage completed with %d insights", len(insights))
		return AIBundle(target=data.target, scan_result=enriched_scan_result, insights=insights)

	def _group_by_endpoint(self, vulnerabilities: list[Vulnerability]) -> dict[tuple[str, str], list[Vulnerability]]:
		grouped: dict[tuple[str, str], list[Vulnerability]] = {}
		for vulnerability in vulnerabilities:
			key = (vulnerability.endpoint.method, vulnerability.endpoint.url)
			if key not in grouped:
				grouped[key] = []
			grouped[key].append(vulnerability)
		return grouped


class AnalysisStage(Stage):
	def __init__(
		self,
		deduplicator: Deduplicator,
		risk_scorer: RiskScorer,
		correlator: Correlator,
		exploit_chain_builder: ExploitChainBuilder,
		exploit_executor: ExploitExecutor | None = None,
	) -> None:
		super().__init__(name="AnalysisStage")
		self._deduplicator = deduplicator
		self._risk_scorer = risk_scorer
		self._correlator = correlator
		self._exploit_chain_builder = exploit_chain_builder
		self._exploit_executor = exploit_executor

	def execute(self, data: object) -> AnalysisBundle:
		if not isinstance(data, AIBundle):
			raise TypeError("AnalysisStage expects AIBundle input")

		LOGGER.info("Analysis stage started")
		
		# 1. Deduplication
		deduplicated = self._deduplicator.deduplicate(data.scan_result)
		
		# 2. Validation & Filtering (Require Proof)
		from analysis.correlator import VulnerabilityValidator
		validator = VulnerabilityValidator()
		verified, retest_candidates = validator.validate_and_filter(deduplicated.vulnerabilities)
		
		# 3. Active Re-testing
		final_vulnerabilities = list(verified)
		if self._exploit_executor and retest_candidates:
			LOGGER.info("Attempting active re-test for %d candidates", len(retest_candidates))
			for candidate in retest_candidates:
				if self._exploit_executor.validate_vulnerability(candidate):
					final_vulnerabilities.append(candidate)
		
		# 4. Final Processing (Correlation & Scoring)
		validated_result = ScanResult(
			vulnerabilities=final_vulnerabilities,
			raw_outputs=list(deduplicated.raw_outputs),
			metadata=dict(deduplicated.metadata)
		)
		
		scored = self._risk_scorer.score(validated_result)
		correlation_map = self._correlator.correlate(scored)
		attack_graph = self._exploit_chain_builder.build(correlation_map)
		
		# 5. Exploit Chaining
		if self._exploit_executor:
			LOGGER.info("Starting logical exploit chaining execution")
			chained_graph = self._exploit_executor.execute_chains(scored.vulnerabilities, data.target.endpoints)
			attack_graph = chained_graph

		LOGGER.info("Analysis stage completed with %d verified findings", len(final_vulnerabilities))
		return AnalysisBundle(
			target=data.target,
			scan_result=scored,
			insights=list(data.insights),
			correlation_map=correlation_map,
			attack_graph=attack_graph,
		)


class ReportStage(Stage):
	def __init__(self, report_builder: ReportBuilder, report_exporter: ReportExporter) -> None:
		super().__init__(name="ReportStage")
		self._report_builder = report_builder
		self._report_exporter = report_exporter

	def execute(self, data: object) -> ReportBundle:
		if not isinstance(data, AnalysisBundle):
			raise TypeError("ReportStage expects AnalysisBundle input")

		LOGGER.info("Report stage started")
		reports = self._report_builder.build(data.scan_result.vulnerabilities)
		exported = self._report_exporter.export_markdown(reports)
		LOGGER.info("Report stage completed with %d markdown reports", len(exported))

		return ReportBundle(
			target=data.target,
			scan_result=data.scan_result,
			insights=list(data.insights),
			reports=reports,
			exported_reports=exported,
		)


class Pipeline:
	def __init__(self, engine: Engine | None = None) -> None:
		self._engine = engine or Engine()

	def add_stage(self, stage: Stage) -> None:
		self._engine.add_stage(stage)
		LOGGER.debug("Pipeline registered stage '%s'", stage.name)

	def run(self, target: Target) -> object:
		LOGGER.info("Pipeline execution started")
		result = self._engine.run(target)
		LOGGER.info("Pipeline execution completed")
		return result
