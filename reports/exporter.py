from __future__ import annotations

import logging
import re
from dataclasses import dataclass
from pathlib import Path

from reports.report_builder import VulnerabilityReport


LOGGER = logging.getLogger(__name__)


@dataclass(slots=True)
class ExportedReport:
	title: str
	file_path: Path

	def to_dict(self) -> dict[str, str]:
		return {
			"title": self.title,
			"file_path": str(self.file_path),
		}


@dataclass(slots=True)
class ReportExporter:
	output_dir: Path

	def export_markdown(self, reports: list[VulnerabilityReport]) -> list[ExportedReport]:
		self.output_dir.mkdir(parents=True, exist_ok=True)

		exported: list[ExportedReport] = []
		for index, report in enumerate(reports, start=1):
			file_name = f"{index:03d}_{self._slugify(report.title)}.md"
			destination = self.output_dir / file_name
			destination.write_text(report.markdown, encoding="utf-8")
			exported.append(ExportedReport(title=report.title, file_path=destination))

		self._write_index(exported)
		LOGGER.info("Exported %d markdown reports to %s", len(exported), self.output_dir)
		return exported

	def _write_index(self, exported: list[ExportedReport]) -> None:
		lines = ["# Vulnerability Reports", ""]
		for report in exported:
			lines.append(f"- {report.title}: {report.file_path.name}")

		index_path = self.output_dir / "index.md"
		index_path.write_text("\n".join(lines) + "\n", encoding="utf-8")

	def _slugify(self, text: str) -> str:
		lowered = text.lower().strip()
		collapsed = re.sub(r"[^a-z0-9]+", "-", lowered)
		return collapsed.strip("-") or "report"
