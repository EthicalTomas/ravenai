from __future__ import annotations

import logging
from dataclasses import dataclass, field
from pathlib import Path

from data.models import Vulnerability


LOGGER = logging.getLogger(__name__)


@dataclass(slots=True)
class ReportSections:
	summary: list[str]
	reproduction_steps: list[str]
	impact: list[str]
	mitigation: list[str]

	def to_dict(self) -> dict[str, list[str]]:
		return {
			"summary": list(self.summary),
			"reproduction_steps": list(self.reproduction_steps),
			"impact": list(self.impact),
			"mitigation": list(self.mitigation),
		}


@dataclass(slots=True)
class VulnerabilityReport:
	vulnerability: Vulnerability
	title: str
	sections: ReportSections
	markdown: str

	def to_dict(self) -> dict[str, object]:
		return {
			"vulnerability": self.vulnerability.to_dict(),
			"title": self.title,
			"sections": self.sections.to_dict(),
			"markdown": self.markdown,
		}


@dataclass(slots=True)
class ReportBuilder:
	templates_dir: Path
	template_map: dict[str, str] = field(default_factory=dict)

	def build(self, vulnerabilities: list[Vulnerability]) -> list[VulnerabilityReport]:
		reports: list[VulnerabilityReport] = []

		for vulnerability in vulnerabilities:
			sections = self._build_sections(vulnerability)
			title = self._build_title(vulnerability)
			template = self._load_template(vulnerability.vuln_type)
			markdown = self._render_template(
				template=template,
				title=title,
				vulnerability=vulnerability,
				sections=sections,
			)
			reports.append(
				VulnerabilityReport(
					vulnerability=vulnerability,
					title=title,
					sections=sections,
					markdown=markdown,
				)
			)

		LOGGER.info("Built %d vulnerability reports", len(reports))
		return reports

	def _build_title(self, vulnerability: Vulnerability) -> str:
		endpoint = vulnerability.endpoint
		return f"{vulnerability.vuln_type.upper()} on {endpoint.method} {endpoint.url}"

	def _build_sections(self, vulnerability: Vulnerability) -> ReportSections:
		from reports.repro_steps import ReproductionStepGenerator
		generator = ReproductionStepGenerator()
		reproduction_steps = generator.generate_steps(vulnerability)
		
		summary = [
			f"Type: {vulnerability.vuln_type}",
			f"Severity: {vulnerability.severity}",
			f"Confidence: {vulnerability.confidence:.2f}",
			f"Endpoint: {vulnerability.endpoint.method} {vulnerability.endpoint.url}",
		]
		impact = [
			"The issue may allow unauthorized behavior depending on application context.",
			"Exploitability should be validated inside approved test scope.",
		]
		mitigation = [
			"Apply strict input validation and output encoding.",
			"Use parameterized queries and safe framework primitives where relevant.",
			"Add regression tests for the affected endpoint and parameters.",
		]

		return ReportSections(
			summary=summary,
			reproduction_steps=reproduction_steps,
			impact=impact,
			mitigation=mitigation,
		)

	def _load_template(self, vuln_type: str) -> str:
		mapped_template = self.template_map.get(vuln_type.lower(), f"{vuln_type.lower()}.md")
		candidate = self.templates_dir / mapped_template
		if not candidate.exists():
			candidate = self.templates_dir / "generic.md"
		return candidate.read_text(encoding="utf-8")

	def _render_template(
		self,
		template: str,
		title: str,
		vulnerability: Vulnerability,
		sections: ReportSections,
	) -> str:
		endpoint = vulnerability.endpoint
		summary_block = "\n".join(f"- {line}" for line in sections.summary)
		steps_block = "\n".join(f"- {line}" for line in sections.reproduction_steps)
		impact_block = "\n".join(f"- {line}" for line in sections.impact)
		mitigation_block = "\n".join(f"- {line}" for line in sections.mitigation)
		payloads_block = "\n".join(f"- {item}" for item in vulnerability.payloads) or "- None"
		evidence_block = "\n".join(f"- {item}" for item in vulnerability.evidence) or "- None"
		
		return template.format(
			title=title,
			vuln_type=vulnerability.vuln_type,
			severity=vulnerability.severity,
			confidence=f"{vulnerability.confidence:.2f}",
			endpoint_url=endpoint.url,
			endpoint_method=endpoint.method,
			summary=summary_block,
			reproduction_steps=steps_block,
			impact=impact_block,
			mitigation=mitigation_block,
			payloads=payloads_block,
			evidence=evidence_block,
		)
