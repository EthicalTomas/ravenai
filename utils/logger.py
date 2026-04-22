from __future__ import annotations

import json
import logging
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path


@dataclass(frozen=True, slots=True)
class LoggingSettings:
	level: str
	log_file_path: Path
	logger_name: str = "raven-ai"


class JsonFormatter(logging.Formatter):
	def format(self, record: logging.LogRecord) -> str:
		payload: dict[str, object] = {
			"timestamp": datetime.now(timezone.utc).isoformat(),
			"level": record.levelname,
			"logger": record.name,
			"message": record.getMessage(),
		}
		if record.exc_info is not None:
			payload["exception"] = self.formatException(record.exc_info)
		if record.stack_info is not None:
			payload["stack"] = record.stack_info
		return json.dumps(payload, ensure_ascii=True)


def setup_structured_logging(settings: LoggingSettings) -> logging.Logger:
	level_value = getattr(logging, settings.level.upper(), None)
	if not isinstance(level_value, int):
		raise ValueError(f"Unsupported logging level: {settings.level}")

	settings.log_file_path.parent.mkdir(parents=True, exist_ok=True)

	logger = logging.getLogger(settings.logger_name)
	logger.setLevel(level_value)
	logger.propagate = False

	for handler in list(logger.handlers):
		logger.removeHandler(handler)
		handler.close()

	console_handler = logging.StreamHandler()
	console_handler.setLevel(level_value)
	console_handler.setFormatter(
		logging.Formatter("%(asctime)s %(levelname)s %(name)s %(message)s")
	)

	file_handler = logging.FileHandler(settings.log_file_path, encoding="utf-8")
	file_handler.setLevel(level_value)
	file_handler.setFormatter(JsonFormatter())

	logger.addHandler(console_handler)
	logger.addHandler(file_handler)

	logger.debug("Structured logging configured", extra={"log_file": str(settings.log_file_path)})
	return logger
