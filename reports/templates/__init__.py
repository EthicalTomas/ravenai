"""reports/templates/__init__.py

Dynamic loading and access to report templates (HTML, Markdown, JSON).
"""

import logging
from pathlib import Path


LOGGER = logging.getLogger(__name__)


class TemplateLoader:
	"""Dynamic loader for report template files."""

	@staticmethod
	def get_template(name: str) -> str:
		"""Fetch the raw content of a template file by name."""
		try:
			template_path = Path(__file__).parent / name
			if not template_path.exists():
				LOGGER.error("Template not found: %s", name)
				return ""
			
			return template_path.read_text(encoding="utf-8")
		except Exception as exc:
			LOGGER.error("Failed to load template %s: %s", name, exc)
			return ""

	@staticmethod
	def list_templates() -> list[str]:
		"""List all available template files in the package."""
		return [p.name for p in Path(__file__).parent.glob("*") if p.is_file() and p.name != "__init__.py"]


__all__ = ["TemplateLoader"]
