import json
from typing import Any
from app.parsers.base import BaseParser, ParsedEvent


def flatten(value: dict[str, Any], prefix: str = "") -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, item in value.items():
        path = f"{prefix}.{key}" if prefix else key
        if isinstance(item, dict):
            result.update(flatten(item, path))
        else:
            result[path] = item
    return result


class JSONParser(BaseParser):
    name, priority, formats = "json", 100, ("json",)

    def can_parse(self, raw_event: str) -> float:
        if not raw_event.lstrip().startswith("{"):
            return 0.0
        try:
            return 1.0 if isinstance(json.loads(raw_event), dict) else 0.0
        except json.JSONDecodeError:
            return 0.55

    def parse(self, raw_event: str) -> ParsedEvent:
        data = json.loads(raw_event)
        if not isinstance(data, dict):
            raise ValueError("JSON event must be an object")
        return ParsedEvent(flatten(data), "json")
