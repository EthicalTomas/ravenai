"""ai/code_analyzer.py

Static + AI-assisted source code analyzer.

Design
------
Two-phase pipeline, strictly following the guardrail rules:

Phase 1 — Deterministic static scan (regex over known-bad patterns).
    Only patterns that appear in the *known risk registry* are flagged.
    No speculation, no hallucination.

Phase 2 — LLM enrichment (only for findings confirmed in Phase 1).
    The LLM is handed each static finding and asked to assess it — it may
    *increase* confidence or *add context*, but it cannot *introduce* new
    findings not already identified by the static scanner.

Output: list[AIInsight]  — structured, never raw strings.

Detects
-------
* Insecure patterns     — eval(), exec(), os.system(), subprocess.shell=True,
                          pickle.loads(), yaml.load() without Loader, MD5/SHA1
                          for security contexts, random (not secrets), …
* Hardcoded secrets     — assignment to names containing key/secret/token/
                          password/passwd/pwd/api_key/private_key with a
                          string literal value.
* Missing validation    — reading request.args / request.form / request.json
                          without any sanitize / validate / escape call nearby.
"""

from __future__ import annotations

import dataclasses
import logging
import re
from dataclasses import dataclass, field
from enum import Enum, auto
from typing import Iterator

from ai.llm_client import LLMClient, LLMRequest, LLMResponse
from data.models import Allnsight

LOGGER = logging.getLogger(__name__)

# Public alias used throughout the pipeline
AIInsight = Allnsight


# ---------------------------------------------------------------------------
# Finding category (structured enum — no raw strings on the boundary)
# ---------------------------------------------------------------------------


class FindingCategory(Enum):
    INSECURE_PATTERN = auto()
    HARDCODED_SECRET = auto()
    MISSING_VALIDATION = auto()
    LOGIC_VULNERABILITY = auto()
    AUTH_VULNERABILITY = auto()


# ---------------------------------------------------------------------------
# Static finding (intermediate structured object — never escapes this module)
# ---------------------------------------------------------------------------


@dataclass(frozen=True, slots=True)
class StaticFinding:
    """A single pattern hit produced by the deterministic scanner."""

    category: FindingCategory
    rule_id: str
    description: str
    line_number: int
    matched_text: str
    base_confidence: float

    def to_dict(self) -> dict[str, object]:
        return {
            "category": self.category.name,
            "rule_id": self.rule_id,
            "description": self.description,
            "line_number": self.line_number,
            "matched_text": self.matched_text,
            "base_confidence": self.base_confidence,
        }


# ---------------------------------------------------------------------------
# Rule registry — all pattern knowledge lives here, not scattered in code
# ---------------------------------------------------------------------------


@dataclass(frozen=True, slots=True)
class _Rule:
    rule_id: str
    category: FindingCategory
    pattern: re.Pattern[str]
    description: str
    base_confidence: float


def _compile_rules(raw_rules: list[dict[str, object]]) -> list[_Rule]:
    """Build a compiled rule list from a list of dicts (from config or defaults)."""
    compiled: list[_Rule] = []
    for entry in raw_rules:
        compiled.append(
            _Rule(
                rule_id=str(entry["rule_id"]),
                category=FindingCategory[str(entry["category"])],
                pattern=re.compile(str(entry["pattern"]), re.MULTILINE),
                description=str(entry["description"]),
                base_confidence=float(str(entry["base_confidence"])),
            )
        )
    return compiled


# Default built-in rules — can be overridden via CodeAnalyzerConfig
_DEFAULT_RULE_DICTS: list[dict[str, object]] = [
    # ── Insecure patterns ──────────────────────────────────────────────────
    {
        "rule_id": "SEC001",
        "category": "INSECURE_PATTERN",
        "pattern": r"\beval\s*\(",
        "description": "Use of eval() allows arbitrary code execution.",
        "base_confidence": 0.9,
    },
    {
        "rule_id": "SEC002",
        "category": "INSECURE_PATTERN",
        "pattern": r"\bexec\s*\(",
        "description": "Use of exec() allows arbitrary code execution.",
        "base_confidence": 0.9,
    },
    {
        "rule_id": "SEC003",
        "category": "INSECURE_PATTERN",
        "pattern": r"\bos\.system\s*\(",
        "description": "os.system() passes commands to the shell unsafely.",
        "base_confidence": 0.85,
    },
    {
        "rule_id": "SEC004",
        "category": "INSECURE_PATTERN",
        "pattern": r"subprocess\.[a-zA-Z_]+\([^)]*shell\s*=\s*True",
        "description": "subprocess called with shell=True enables shell injection.",
        "base_confidence": 0.88,
    },
    {
        "rule_id": "SEC005",
        "category": "INSECURE_PATTERN",
        "pattern": r"\bpickle\.loads?\s*\(",
        "description": "pickle.load/loads deserialises untrusted data unsafely.",
        "base_confidence": 0.85,
    },
    {
        "rule_id": "SEC006",
        "category": "INSECURE_PATTERN",
        "pattern": r"\byaml\.load\s*\([^,)]+\)",
        "description": "yaml.load() without an explicit Loader is unsafe.",
        "base_confidence": 0.80,
    },
    {
        "rule_id": "SEC007",
        "category": "INSECURE_PATTERN",
        "pattern": r"\bhashlib\.(?:md5|sha1)\s*\(",
        "description": "MD5/SHA-1 are cryptographically weak for security purposes.",
        "base_confidence": 0.75,
    },
    {
        "rule_id": "SEC008",
        "category": "INSECURE_PATTERN",
        "pattern": r"\brandom\.(?:random|randint|choice|choices|sample|shuffle)\s*\(",
        "description": "random module is not cryptographically secure; use secrets instead.",
        "base_confidence": 0.70,
    },
    {
        "rule_id": "SEC009",
        "category": "INSECURE_PATTERN",
        "pattern": r"\brender_template_string\s*\(",
        "description": "render_template_string with user input risks Server-Side Template Injection.",
        "base_confidence": 0.80,
    },
    {
        "rule_id": "SEC010",
        "category": "INSECURE_PATTERN",
        "pattern": r"\bSHA256Managed\b|\bMD5CryptoServiceProvider\b",
        "description": "Weak or context-inappropriate cryptographic primitive detected.",
        "base_confidence": 0.75,
    },
    # ── Hardcoded secrets ──────────────────────────────────────────────────
    {
        "rule_id": "SEC020",
        "category": "HARDCODED_SECRET",
        "pattern": (
            r'(?i)(?:password|passwd|pwd|secret|api_key|apikey|token|private_key|'
            r'access_key|auth_key)\s*=\s*["\'][^"\']{4,}["\']'
        ),
        "description": "Hardcoded credential or secret detected in source code.",
        "base_confidence": 0.85,
    },
    {
        "rule_id": "SEC021",
        "category": "HARDCODED_SECRET",
        "pattern": r'(?i)(?:BEGIN\s+(?:RSA|EC|OPENSSH|PGP)\s+PRIVATE\s+KEY)',
        "description": "Private key material embedded in source code.",
        "base_confidence": 0.98,
    },
    {
        "rule_id": "SEC022",
        "category": "HARDCODED_SECRET",
        "pattern": r'(?i)(?:AWS|AMAZON)\s*(?:ACCESS\s*KEY\s*ID|SECRET)\s*=\s*["\'][A-Z0-9/+]{16,}["\']',
        "description": "Hardcoded AWS credential detected.",
        "base_confidence": 0.95,
    },
    # ── Missing input validation ───────────────────────────────────────────
    {
        "rule_id": "SEC030",
        "category": "MISSING_VALIDATION",
        "pattern": r'request\.(?:args|form|json|data|values|files)\[',
        "description": (
            "User-controlled input accessed via direct subscript — "
            "validate and sanitize before use."
        ),
        "base_confidence": 0.65,
    },
    {
        "rule_id": "SEC031",
        "category": "MISSING_VALIDATION",
        "pattern": r'request\.(?:args|form|json|data|values)\.get\(',
        "description": (
            "User-controlled input fetched with .get() — "
            "ensure output encoding and validation are applied."
        ),
        "base_confidence": 0.60,
    },
    {
        "rule_id": "SEC032",
        "category": "MISSING_VALIDATION",
        "pattern": r'\binput\s*\(',
        "description": "input() reads raw user data; validate before use in any logic.",
        "base_confidence": 0.60,
    },
    # ── Logic & Auth vulnerabilities ───────────────────────────────────────
    {
        "rule_id": "LOG001",
        "category": "LOGIC_VULNERABILITY",
        "pattern": r"\b[A-Z][a-zA-Z_]+\.objects\.get\s*\(\s*id\s*=",
        "description": "Direct object lookup by ID without apparent ownership check (potential IDOR).",
        "base_confidence": 0.65,
    },
    {
        "rule_id": "LOG002",
        "category": "LOGIC_VULNERABILITY",
        "pattern": r"\bfilter\s*\(\s*id\s*=[^,)]+\)\.first\s*\(",
        "description": "Direct filter by ID without apparent ownership check (potential IDOR).",
        "base_confidence": 0.60,
    },
    {
        "rule_id": "AUT001",
        "category": "AUTH_VULNERABILITY",
        "pattern": r"@(?:app|bp)\.route\s*\([^)]+\)\n\s*def\s+[a-zA-Z0-9_]+\s*\([^)]*\):(?!\n\s+(?:@|login_required|auth))",
        "description": "Route definition lacks immediate authentication decorator.",
        "base_confidence": 0.55,
    },
    {
        "rule_id": "AUT002",
        "category": "AUTH_VULNERABILITY",
        "pattern": r"\ballow_anonymous\b|auth\s*=\s*None",
        "description": "Explicitly allowing anonymous access or disabling auth in a sensitive context.",
        "base_confidence": 0.70,
    },
]

_DEFAULT_RULES: list[_Rule] = _compile_rules(_DEFAULT_RULE_DICTS)


# ---------------------------------------------------------------------------
# Analyzer configuration (all values from config — nothing hardcoded here)
# ---------------------------------------------------------------------------


@dataclass(frozen=True, slots=True)
class CodeAnalyzerConfig:
    """Runtime configuration for :class:`CodeAnalyzer`.

    Attributes
    ----------
    min_static_confidence:
        Static findings below this threshold are dropped before LLM enrichment.
    min_llm_confidence:
        LLM response confidence below this is discarded; static finding is
        kept with its original base_confidence.
    constraints:
        Forwarded verbatim to every LLMRequest.
    prompt_template:
        Must contain ``{rule_id}``, ``{description}``, ``{matched_text}``,
        ``{line_number}`` format placeholders.
    max_enrichment_calls:
        Cap on LLM calls per analysis invocation to respect rate limits.
    """

    min_static_confidence: float
    min_llm_confidence: float
    constraints: list[str]
    prompt_template: str
    max_enrichment_calls: int
    user_roles: list[str]


# ---------------------------------------------------------------------------
# Public CodeAnalyzer
# ---------------------------------------------------------------------------


class CodeAnalyzer:
    """Two-phase static + AI code analyzer.

    Phase 1: regex-based deterministic scan over ``_DEFAULT_RULES`` (or a
             custom rule set from config).
    Phase 2: for each confirmed finding, one LLM call refines severity
             reasoning. The LLM cannot introduce new findings.

    Parameters
    ----------
    llm_client:
        Any :class:`~ai.llm_client.LLMClient` implementation.
    config:
        :class:`CodeAnalyzerConfig` loaded from YAML.
    rules:
        Optional custom rule list.  Defaults to ``_DEFAULT_RULES``.
    """

    def __init__(
        self,
        llm_client: LLMClient,
        config: CodeAnalyzerConfig,
        rules: list[_Rule] | None = None,
    ) -> None:
        self._llm_client = llm_client
        self._config = config
        self._rules: list[_Rule] = rules if rules is not None else _DEFAULT_RULES

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def analyze(self, code: str) -> list[AIInsight]:
        """Analyze *code* and return structured AI insights.

        Parameters
        ----------
        code:
            Raw source code string.  May be any language, though the default
            rule set targets Python.

        Returns
        -------
        list[AIInsight]
            One insight per confirmed finding, potentially enriched by the LLM.
            Empty list when no known-risk patterns are detected.
        """
        if not code or not code.strip():
            LOGGER.debug("CodeAnalyzer received empty code string; returning no findings")
            return []

        lines = code.splitlines()
        static_findings = list(self._static_scan(code=code, lines=lines))

        if not static_findings:
            LOGGER.info("CodeAnalyzer: no known-risk patterns detected in source code")
            return []

        LOGGER.info(
            "CodeAnalyzer: static scan produced %d finding(s) before LLM enrichment",
            len(static_findings),
        )

        insights: list[AIInsight] = []
        llm_calls_remaining = self._config.max_enrichment_calls

        for finding in static_findings:
            if llm_calls_remaining > 0:
                insight = self._enrich_with_llm(finding)
                llm_calls_remaining -= 1
            else:
                LOGGER.debug(
                    "LLM call cap reached; converting static finding %s without enrichment",
                    finding.rule_id,
                )
                insight = self._finding_to_insight(finding, confidence=finding.base_confidence)

            insights.append(insight)

        LOGGER.info(
            "CodeAnalyzer: produced %d insight(s) from source code analysis", len(insights)
        )
        return insights

    # ------------------------------------------------------------------
    # Phase 1 — deterministic static scan
    # ------------------------------------------------------------------

    def _static_scan(self, code: str, lines: list[str]) -> Iterator[StaticFinding]:
        """Yield one StaticFinding per pattern match above the confidence floor."""
        for rule in self._rules:
            for match in rule.pattern.finditer(code):
                if rule.base_confidence < self._config.min_static_confidence:
                    continue

                line_number = code[: match.start()].count("\n") + 1
                matched_text = self._safe_match_text(
                    match=match.group(0), lines=lines, line_number=line_number
                )

                yield StaticFinding(
                    category=rule.category,
                    rule_id=rule.rule_id,
                    description=rule.description,
                    line_number=line_number,
                    matched_text=matched_text,
                    base_confidence=rule.base_confidence,
                )
                LOGGER.debug(
                    "Static finding: rule=%s line=%d text=%r",
                    rule.rule_id,
                    line_number,
                    matched_text[:60],
                )

    def _safe_match_text(
        self, match: str, lines: list[str], line_number: int
    ) -> str:
        """Return the full source line for context, falling back to the regex match."""
        idx = line_number - 1
        if 0 <= idx < len(lines):
            return lines[idx].strip()
        return match.strip()

    # ------------------------------------------------------------------
    # Phase 2 — LLM enrichment (only deepens existing findings)
    # ------------------------------------------------------------------

    def _enrich_with_llm(self, finding: StaticFinding) -> AIInsight:
        """Call the LLM to add reasoning context to a confirmed static finding."""
        request = self._build_llm_request(finding)

        try:
            response: LLMResponse = self._llm_client.generate(request)
        except Exception as exc:  # noqa: BLE001 — never crash the pipeline
            LOGGER.warning(
                "LLM enrichment failed for finding %s: %s; using static description",
                finding.rule_id,
                exc,
            )
            return self._finding_to_insight(finding, confidence=finding.base_confidence)

        if response.confidence < self._config.min_llm_confidence:
            LOGGER.debug(
                "LLM confidence %.2f below threshold for %s; using static description",
                response.confidence,
                finding.rule_id,
            )
            return self._finding_to_insight(finding, confidence=finding.base_confidence)

        enriched_confidence = max(finding.base_confidence, response.confidence)
        prefix = f"[{finding.category.name}] {finding.rule_id} (line {finding.line_number})"
        enriched_description = f"{prefix}: {self._merge_descriptions(finding.description, response.content)} — matched: {finding.matched_text[:120]}"

        LOGGER.debug(
            "LLM enriched finding %s: confidence %.2f → %.2f",
            finding.rule_id,
            finding.base_confidence,
            enriched_confidence,
        )
        return AIInsight(
            description=enriched_description,
            confidence=enriched_confidence,
            related_vuln=None,
        )

    def _build_llm_request(self, finding: StaticFinding) -> LLMRequest:
        """Construct an LLMRequest that gives the LLM full context on the finding."""
        prompt = self._config.prompt_template.format(
            rule_id=finding.rule_id,
            description=finding.description,
            matched_text=finding.matched_text,
            line_number=finding.line_number,
            user_roles=", ".join(self._config.user_roles),
        )
        context: dict[str, object] = {
            "finding": finding.to_dict(),
            "instruction": (
                "Assess the risk of this confirmed static finding. "
                "Do NOT introduce new findings. "
                "Only provide deeper reasoning for the one finding supplied."
            ),
            "safe_analysis_mode": True,
        }
        return LLMRequest(
            prompt=prompt,
            context=context,
            constraints=list(self._config.constraints),
            temperature=0.0,
            max_tokens=256,
        )

    @staticmethod
    def _merge_descriptions(static_description: str, llm_content: str) -> str:
        """Combine the static description with LLM elaboration."""
        llm_text = llm_content.strip()
        if not llm_text:
            return static_description
        return f"{static_description} | LLM analysis: {llm_text}"

    @staticmethod
    def _finding_to_insight(finding: StaticFinding, confidence: float) -> AIInsight:
        """Convert a StaticFinding to an AIInsight with no LLM involvement."""
        return AIInsight(
            description=(
                f"[{finding.category.name}] {finding.rule_id} "
                f"(line {finding.line_number}): {finding.description} "
                f"— matched: {finding.matched_text[:120]}"
            ),
            confidence=confidence,
            related_vuln=None,
        )


# ---------------------------------------------------------------------------
# Config loader — reads the ``ai.code_analyzer`` YAML sub-mapping
# ---------------------------------------------------------------------------


def build_code_analyzer_config(raw: dict[str, object]) -> CodeAnalyzerConfig:
    """Build a :class:`CodeAnalyzerConfig` from a raw YAML mapping.

    Expected YAML shape (under ``ai.code_analyzer:`` in settings.yaml)::

        code_analyzer:
          min_static_confidence: 0.6
          min_llm_confidence: 0.5
          max_enrichment_calls: 20
          prompt_template: >-
            Rule {rule_id}: {description}
            Matched at line {line_number}: {matched_text}
            Assess the risk of this finding without introducing new issues.
          constraints:
            - no hallucinated vulnerabilities
            - existing findings only
            - structured outputs only
    """
    if not isinstance(raw, dict):
        raise TypeError("ai.code_analyzer config must be a YAML mapping")

    return CodeAnalyzerConfig(
        min_static_confidence=_require_unit_float(raw, "min_static_confidence"),
        min_llm_confidence=_require_unit_float(raw, "min_llm_confidence"),
        constraints=_require_string_list(raw, "constraints"),
        prompt_template=_require_nonempty_string(raw, "prompt_template"),
        max_enrichment_calls=_require_positive_int(raw, "max_enrichment_calls"),
        user_roles=_require_string_list(raw, "user_roles"),
    )


# ---------------------------------------------------------------------------
# Private config parsing helpers
# ---------------------------------------------------------------------------


def _require_unit_float(mapping: dict[str, object], key: str) -> float:
    value = mapping.get(key)
    if isinstance(value, bool):
        raise TypeError(f"code_analyzer config '{key}' must be a float")
    if isinstance(value, int):
        value = float(value)
    if not isinstance(value, float):
        raise TypeError(f"code_analyzer config '{key}' must be a float, got {value!r}")
    if not 0.0 <= value <= 1.0:
        raise ValueError(f"code_analyzer config '{key}' must be in [0.0, 1.0], got {value}")
    return value


def _require_positive_int(mapping: dict[str, object], key: str) -> int:
    value = mapping.get(key)
    if isinstance(value, bool) or not isinstance(value, int):
        raise TypeError(f"code_analyzer config '{key}' must be an integer, got {value!r}")
    if value < 1:
        raise ValueError(f"code_analyzer config '{key}' must be >= 1, got {value}")
    return value


def _require_string_list(mapping: dict[str, object], key: str) -> list[str]:
    value = mapping.get(key)
    if not isinstance(value, list):
        raise TypeError(f"code_analyzer config '{key}' must be a list, got {value!r}")
    result: list[str] = []
    for item in value:
        if not isinstance(item, str) or not item.strip():
            raise ValueError(f"code_analyzer config '{key}' must be a list of non-empty strings")
        result.append(item.strip())
    return result


def _require_nonempty_string(mapping: dict[str, object], key: str) -> str:
    value = mapping.get(key)
    if not isinstance(value, str) or not value.strip():
        raise TypeError(f"code_analyzer config '{key}' must be a non-empty string, got {value!r}")
    return value.strip()
