import json
import logging
from contextvars import ContextVar
from datetime import datetime
from typing import Any, Dict


_request_id_ctx: ContextVar[str | None] = ContextVar("request_id", default=None)
_org_id_ctx: ContextVar[str | None] = ContextVar("org_id", default=None)


def set_log_context(*, request_id: str | None = None, org_id: str | None = None) -> dict[str, Any]:
	return {
		"request_id": _request_id_ctx.set(request_id),
		"org_id": _org_id_ctx.set(org_id),
	}


def reset_log_context(tokens: dict[str, Any] | None) -> None:
	if not tokens:
		return
	if "request_id" in tokens:
		_request_id_ctx.reset(tokens["request_id"])
	if "org_id" in tokens:
		_org_id_ctx.reset(tokens["org_id"])


def get_log_context() -> Dict[str, Any]:
	payload: Dict[str, Any] = {}
	request_id = _request_id_ctx.get()
	org_id = _org_id_ctx.get()
	if request_id:
		payload["request_id"] = request_id
	if org_id:
		payload["org_id"] = org_id
	return payload


class JsonFormatter(logging.Formatter):
	def format(self, record: logging.LogRecord) -> str:
		payload: Dict[str, Any] = {
			"timestamp": datetime.utcnow().isoformat(),
			"level": record.levelname,
			"logger": record.name,
			"message": record.getMessage(),
		}
		payload.update(get_log_context())
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
