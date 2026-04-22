"""analysis/execution_context.py

Stateful execution context for multi-step exploit sequences, managing 
variables, interaction history, and dynamic payload substitution.
"""

from __future__ import annotations

import logging
import re
from dataclasses import dataclass, field
from datetime import datetime
from typing import Any

from data.models import ScanResult, Endpoint


LOGGER = logging.getLogger(__name__)


@dataclass(slots=True)
class ExecutionStep:
	"""Captured metadata for a single step in an exploit sequence."""
	step_name: str
	endpoint: Endpoint
	request_payload: str
	response_status: int
	response_body: str
	logs: list[str] = field(default_factory=list)
	extracted_vars: dict[str, str] = field(default_factory=dict)
	intermediate_data: dict[str, Any] = field(default_factory=dict)
	timestamp: str = field(default_factory=lambda: datetime.now().isoformat())


@dataclass(slots=True)
class ExecutionContext:
	"""Manages state and variable substitution across multi-step exploits."""

	variables: dict[str, str] = field(default_factory=dict)
	history: list[ExecutionStep] = field(default_factory=list)
	secrets: dict[str, str] = field(default_factory=dict)

	def log_step_entry(self, message: str) -> None:
		"""Chronologically log a detail into the current execution flow."""
		LOGGER.info("[Context] %s", message)
		if self.history:
			self.history[-1].logs.append(message)

	def set_variable(self, name: str, value: str) -> None:
		"""Store a discovered variable for reuse in later steps."""
		self.variables[name] = value
		LOGGER.debug("Context updated: %s = %s", name, value[:10] + "..." if len(value) > 10 else value)

	def get_variable(self, name: str, default: str = "") -> str:
		"""Retrieve a variable from the context."""
		return self.variables.get(name, default)

	def record_step(self, step: ExecutionStep) -> None:
		"""Log a completed interaction step into the sequence history."""
		self.history.append(step)
		# Automatically merge any extracted vars into the context
		for name, val in step.extracted_vars.items():
			self.set_variable(name, val)

	def apply_templates(self, template: str) -> str:
		"""Substitute {var_name} placeholders with values from the context."""
		result = template
		for name, value in self.variables.items():
			result = result.replace(f"{{{name}}}", value)
		
		# Check for remaining unpopulated templates
		remaining = re.findall(r'\{([a-zA-Z0-9_]+)\}', result)
		if remaining:
			LOGGER.warning("Unpopulated templates in payload: %s", ", ".join(remaining))
			
		return result

	def clear(self) -> None:
		"""Reset the context state."""
		self.variables.clear()
		self.history.clear()
		self.secrets.clear()


@dataclass(slots=True)
class ExploitSequenceRunner:
	"""POC engine for running multi-step sequences using the ExecutionContext."""

	context: ExecutionContext = field(default_factory=ExecutionContext)

	def run_sequence_poc(self, name: str, steps: list[dict[str, Any]]) -> bool:
		"""Simple walkthrough of a sequence: trigger -> capture -> reuse."""
		LOGGER.info("Starting exploit sequence: %s", name)
		
		for i, defn in enumerate(steps):
			step_name = defn.get("name", f"step_{i}")
			
			# 1. Reuse: Apply templates from previous stages
			final_payload = self.context.apply_templates(defn.get("payload_template", ""))
			
			# 2. Trigger & Capture: Simulation of networking
			# In a real run, this would call HTTPClient
			LOGGER.info("[%s] Executing step with payload: %s", step_name, final_payload)
			
			# 3. Capture: Store findings back into context
			# Simulate finding a token in step 0
			if i == 0 and "token" in defn.get("expects_extraction", []):
				self.context.set_variable("token", "AIZA-SIMULATED-KEY-12345")
				
			# Success validation logic (POC)
			if i > 0 and "{token}" in defn.get("payload_template", ""):
				if not self.context.get_variable("token"):
					LOGGER.error("Sequence failed at step %d: required 'token' not found", i)
					return False
					
		return True
