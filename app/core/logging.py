import json
import logging
from datetime import datetime
from typing import Any, Dict


class JsonFormatter(logging.Formatter):
	def format(self, record: logging.LogRecord) -> str:
		payload: Dict[str, Any] = {
			"timestamp": datetime.utcnow().isoformat(),
			"level": record.levelname,
			"logger": record.name,
			"message": record.getMessage(),
		}
		if hasattr(record, "extra_payload") and isinstance(record.extra_payload, dict):
			payload.update(record.extra_payload)
		return json.dumps(payload, default=str)


def get_logger(name: str = "tip") -> logging.Logger:
	logger = logging.getLogger(name)
	if logger.handlers:
		return logger
	logger.setLevel(logging.INFO)
	handler = logging.StreamHandler()
	handler.setFormatter(JsonFormatter())
	logger.addHandler(handler)
	logger.propagate = False
	return logger


logger = get_logger("tip")
