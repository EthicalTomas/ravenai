from __future__ import annotations

import logging
from abc import ABC, abstractmethod
from typing import Any

from data.models import Target


LOGGER = logging.getLogger(__name__)


class Stage(ABC):
	name: str

	def __init__(self, name: str | None = None) -> None:
		self.name = name or self.__class__.__name__

	@abstractmethod
	def execute(self, data: object) -> object:
		"""Execute a unit of work using structured input and output objects."""


class StageExecutionError(RuntimeError):
	def __init__(self, stage_name: str, message: str) -> None:
		super().__init__(f"Stage '{stage_name}' failed: {message}")
		self.stage_name = stage_name


class Engine:
	def __init__(self) -> None:
		self._stages: list[Stage] = []

	def add_stage(self, stage: Stage) -> None:
		self._stages.append(stage)
		LOGGER.debug("Added stage '%s' to engine", stage.name)

	def run(self, target: Target) -> object:
		current_data: object = target
		LOGGER.info("Engine run started for domain '%s'", target.domain)

		for stage in self._stages:
			if isinstance(current_data, str):
				raise TypeError(
					f"Engine data flow cannot use raw strings before stage '{stage.name}'."
				)

			LOGGER.info("Running stage '%s'", stage.name)
			try:
				next_data = stage.execute(current_data)
			except Exception as error:
				LOGGER.exception("Unhandled exception while executing stage '%s'", stage.name)
				raise StageExecutionError(stage.name, str(error)) from error

			if isinstance(next_data, str):
				raise TypeError(
					f"Engine data flow cannot use raw strings after stage '{stage.name}'."
				)

			current_data = next_data
			LOGGER.info("Stage '%s' completed", stage.name)

		LOGGER.info("Engine run finished")
		return current_data
