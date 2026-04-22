from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Any


try:
	import yaml
except ImportError as import_error:
	raise RuntimeError("PyYAML is required to load configuration") from import_error


@dataclass(frozen=True, slots=True)
class LoggingConfig:
	level: str


@dataclass(frozen=True, slots=True)
class ScopeConfig:
	allowed_domains: set[str]
	blocked_domains: set[str]
	allow_subdomains: bool


@dataclass(frozen=True, slots=True)
class ScanControls:
	depth: int
	rate_limits: dict[str, float]
	enabled_modules: dict[str, bool]
	timeouts: dict[str, float]
	bug_bounty_mode: bool


@dataclass(frozen=True, slots=True)
class ReconConfig:
	candidate_subdomains: set[str]
	seed_schemes: set[str]
	crawler_max_pages: int
	crawler_user_agent: str
	crawler_allowed_schemes: set[str]
	headless_enabled: bool
	max_browsers: int
	crawl_depth: int
	js_analysis_enabled: bool


@dataclass(frozen=True, slots=True)
class ScannerConfig:
	max_workers: int
	user_agent: str
	xss_reflection_markers: list[str]
	xss_min_confidence: float
	xss_severity: str
	sqli_error_signatures: list[str]
	sqli_min_confidence: float
	sqli_severity: str
	replay_enabled: bool = True

@dataclass(frozen=True, slots=True)
class VectorSpaceConfig:
	dimension: int
	backend_preference: str
	min_similarity: float
	top_k_default: int
	dedup_enabled: bool


@dataclass(frozen=True, slots=True)
class AIConfig:
	provider_name: str
	model: str
	api_key: str | None
	base_url: str | None
	constraints: list[str]
	min_confidence: float
	max_payloads_per_vuln: int
	allowed_severities: set[str]
	prompts: dict[str, str]


@dataclass(frozen=True, slots=True)
class AnalysisConfig:
	severity_weights: dict[str, float]
	exploit_chaining_enabled: bool
	prioritization_enabled: bool = True
	token_extraction_enabled: bool = True


@dataclass(frozen=True, slots=True)
class ReportConfig:
	templates_dir: Path
	output_dir: Path
	template_map: dict[str, str]


@dataclass(frozen=True, slots=True)
class Settings:
	target_domain: str
	logging: LoggingConfig
	scope: ScopeConfig
	scan_controls: ScanControls
	recon: ReconConfig
	scanner: ScannerConfig
	ai: AIConfig
	analysis: AnalysisConfig
	vector_space: VectorSpaceConfig
	report: ReportConfig


def load_settings(path: Path) -> Settings:
	raw = _load_yaml_mapping(path)

	target_domain = _require_string(raw, "target.domain")
	logging_config = LoggingConfig(level=_require_string(raw, "logging.level"))
	scope_config = ScopeConfig(
		allowed_domains=_require_string_set(raw, "scope.allowed_domains"),
		blocked_domains=_require_string_set(raw, "scope.blocked_domains"),
		allow_subdomains=_require_bool(raw, "scope.allow_subdomains"),
	)
	scan_controls = ScanControls(
		depth=_require_int(raw, "scan.depth"),
		rate_limits=_require_float_mapping(raw, "scan.rate_limits"),
		enabled_modules=_require_bool_mapping(raw, "scan.enabled_modules"),
		timeouts=_require_float_mapping(raw, "scan.timeouts"),
		bug_bounty_mode=_require_bool(raw, "scan.bug_bounty_mode"),
	)
	recon_config = ReconConfig(
		candidate_subdomains=_require_string_set(raw, "recon.candidate_subdomains"),
		seed_schemes=_require_string_set(raw, "recon.seed_schemes"),
		crawler_max_pages=_require_int(raw, "recon.crawler.max_pages"),
		crawler_user_agent=_require_string(raw, "recon.crawler.user_agent"),
		crawler_allowed_schemes=_require_string_set(raw, "recon.crawler.allowed_schemes"),
		headless_enabled=_require_bool(raw, "recon.headless_enabled"),
		max_browsers=_require_int(raw, "recon.max_browsers"),
		crawl_depth=_require_int(raw, "recon.crawl_depth"),
		js_analysis_enabled=_require_bool(raw, "recon.js_analysis_enabled"),
	)
	scanner_config = ScannerConfig(
		max_workers=_require_int(raw, "scanner.max_workers"),
		user_agent=_require_string(raw, "scanner.user_agent"),
		xss_reflection_markers=_require_string_list(raw, "scanner.xss.reflection_markers"),
		xss_min_confidence=_require_float(raw, "scanner.xss.min_confidence"),
		xss_severity=_require_string(raw, "scanner.xss.severity"),
		sqli_error_signatures=_require_string_list(raw, "scanner.sqli.error_signatures"),
		sqli_min_confidence=_require_float(raw, "scanner.sqli.min_confidence"),
		sqli_severity=_require_string(raw, "scanner.sqli.severity"),
		replay_enabled=_require_bool(raw, "scanner.replay_enabled"),
	)
	ai_config = AIConfig(
		provider_name=_require_string(raw, "ai.provider_name"),
		model=_require_string(raw, "ai.model"),
		api_key=_optional_string(raw, "ai.api_key"),
		base_url=_optional_string(raw, "ai.base_url"),
		constraints=_require_string_list(raw, "ai.constraints"),
		min_confidence=_require_float(raw, "ai.min_confidence"),
		max_payloads_per_vuln=_require_int(raw, "ai.max_payloads_per_vuln"),
		allowed_severities=_require_string_set(raw, "ai.allowed_severities"),
		prompts=_require_string_mapping(raw, "ai.prompts"),
	)
	analysis_config = AnalysisConfig(
		severity_weights=_require_float_mapping(raw, "analysis.severity_weights"),
		exploit_chaining_enabled=_require_bool(raw, "analysis.exploit_chaining_enabled"),
		prioritization_enabled=_require_bool(raw, "analysis.prioritization_enabled"),
		token_extraction_enabled=_require_bool(raw, "analysis.token_extraction_enabled"),
	)
	vector_space_config = VectorSpaceConfig(
		dimension=_require_int(raw, "vector_space.dimension"),
		backend_preference=_require_string(raw, "vector_space.backend_preference"),
		min_similarity=_require_float(raw, "vector_space.min_similarity"),
		top_k_default=_require_int(raw, "vector_space.top_k_default"),
		dedup_enabled=_require_bool(raw, "vector_space.dedup_enabled"),
	)
	report_config = ReportConfig(
		templates_dir=Path(_require_string(raw, "report.templates_dir")),
		output_dir=Path(_require_string(raw, "report.output_dir")),
		template_map=_require_string_mapping(raw, "report.template_map"),
	)

	_validate_settings(
		target_domain=target_domain,
		scope=scope_config,
		scan_controls=scan_controls,
		recon=recon_config,
		scanner=scanner_config,
		ai=ai_config,
	)

	return Settings(
		target_domain=target_domain,
		logging=logging_config,
		scope=scope_config,
		scan_controls=scan_controls,
		recon=recon_config,
		scanner=scanner_config,
		ai=ai_config,
		analysis=analysis_config,
		vector_space=vector_space_config,
		report=report_config,
	)


def _validate_settings(
	target_domain: str,
	scope: ScopeConfig,
	scan_controls: ScanControls,
	recon: ReconConfig,
	scanner: ScannerConfig,
	ai: AIConfig,
) -> None:
	if scan_controls.depth <= 0:
		raise ValueError("scan.depth must be greater than 0")
	if recon.crawler_max_pages <= 0:
		raise ValueError("recon.crawler.max_pages must be greater than 0")
	if scanner.max_workers <= 0:
		raise ValueError("scanner.max_workers must be greater than 0")
	if ai.max_payloads_per_vuln <= 0:
		raise ValueError("ai.max_payloads_per_vuln must be greater than 0")

	if target_domain not in scope.allowed_domains:
		raise ValueError("target.domain must be included in scope.allowed_domains")


def _load_yaml_mapping(path: Path) -> dict[str, Any]:
	if not path.exists():
		raise FileNotFoundError(f"Config file not found: {path}")

	loaded = yaml.safe_load(path.read_text(encoding="utf-8"))
	if loaded is None:
		return {}
	if not isinstance(loaded, dict):
		raise ValueError(f"Config root must be a mapping: {path}")
	return loaded


def _lookup(config: dict[str, Any], dotted_key: str) -> Any:
	current: Any = config
	for segment in dotted_key.split("."):
		if not isinstance(current, dict) or segment not in current:
			raise ValueError(f"Missing required config key: {dotted_key}")
		current = current[segment]
	return current


def _require_string(config: dict[str, Any], key: str) -> str:
	value = _lookup(config, key)
	if not isinstance(value, str) or not value.strip():
		raise ValueError(f"Config key must be a non-empty string: {key}")
	return value.strip()


def _optional_string(config: dict[str, Any], key: str) -> str | None:
	try:
		value = _lookup(config, key)
		if value is None:
			return None
		if not isinstance(value, str):
			return str(value)
		return value.strip() or None
	except ValueError:
		return None


def _require_int(config: dict[str, Any], key: str) -> int:
	value = _lookup(config, key)
	if not isinstance(value, int):
		raise ValueError(f"Config key must be an integer: {key}")
	return value


def _require_float(config: dict[str, Any], key: str) -> float:
	value = _lookup(config, key)
	if isinstance(value, int):
		return float(value)
	if not isinstance(value, float):
		raise ValueError(f"Config key must be a float: {key}")
	return value


def _require_bool(config: dict[str, Any], key: str) -> bool:
	value = _lookup(config, key)
	if not isinstance(value, bool):
		raise ValueError(f"Config key must be a boolean: {key}")
	return value


def _require_string_list(config: dict[str, Any], key: str) -> list[str]:
	value = _lookup(config, key)
	if not isinstance(value, list) or any(not isinstance(item, str) for item in value):
		raise ValueError(f"Config key must be a list of strings: {key}")
	return [item.strip() for item in value if item.strip()]


def _require_string_set(config: dict[str, Any], key: str) -> set[str]:
	return set(_require_string_list(config, key))


def _require_string_mapping(config: dict[str, Any], key: str) -> dict[str, str]:
	value = _lookup(config, key)
	if not isinstance(value, dict):
		raise ValueError(f"Config key must be a mapping[str, str]: {key}")

	parsed: dict[str, str] = {}
	for raw_key, raw_value in value.items():
		if not isinstance(raw_key, str) or not isinstance(raw_value, str):
			raise ValueError(f"Config key must be a mapping[str, str]: {key}")
		parsed[raw_key.strip()] = raw_value.strip()
	return parsed


def _require_float_mapping(config: dict[str, Any], key: str) -> dict[str, float]:
	value = _lookup(config, key)
	if not isinstance(value, dict):
		raise ValueError(f"Config key must be a mapping[str, float]: {key}")

	parsed: dict[str, float] = {}
	for raw_key, raw_value in value.items():
		if not isinstance(raw_key, str):
			raise ValueError(f"Config key must be a mapping[str, float]: {key}")
		if isinstance(raw_value, int):
			parsed[raw_key.strip()] = float(raw_value)
		elif isinstance(raw_value, float):
			parsed[raw_key.strip()] = raw_value
		else:
			raise ValueError(f"Config key must be a mapping[str, float]: {key}")
	return parsed


def _require_bool_mapping(config: dict[str, Any], key: str) -> dict[str, bool]:
	value = _lookup(config, key)
	if not isinstance(value, dict):
		raise ValueError(f"Config key must be a mapping[str, bool]: {key}")

	parsed: dict[str, bool] = {}
	for raw_key, raw_value in value.items():
		if not isinstance(raw_key, str) or not isinstance(raw_value, bool):
			raise ValueError(f"Config key must be a mapping[str, bool]: {key}")
		parsed[raw_key.strip()] = raw_value
	return parsed
