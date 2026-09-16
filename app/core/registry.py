from app.parsers.base import BaseParser
from app.parsers.json_parser import JSONParser
from app.parsers.cef_parser import CEFParser
from app.parsers.syslog_parser import SyslogParser
from app.parsers.keyvalue_parser import KeyValueParser
from app.parsers.csv_parser import CSVParser
from app.parsers.fallback_parser import FallbackParser


class ParserRegistry:
    def __init__(self) -> None:
        self._parsers: list[BaseParser] = []

    def register(self, parser: BaseParser) -> None:
        if any(p.name == parser.name for p in self._parsers):
            raise ValueError(f"Parser already registered: {parser.name}")
        self._parsers.append(parser)
        self._parsers.sort(key=lambda p: (-p.priority, p.name))

    def select(self, raw_event: str) -> tuple[BaseParser, float]:
        candidates = [(p, p.can_parse(raw_event)) for p in self._parsers]
        candidates = [(p, score) for p, score in candidates if score > 0]
        if not candidates:
            raise ValueError("No parser registered")
        return max(candidates, key=lambda x: (x[1], x[0].priority, x[0].name))

    def list(self) -> list[BaseParser]:
        return list(self._parsers)


def default_registry() -> ParserRegistry:
    registry = ParserRegistry()
    for parser_type in (JSONParser, CEFParser, SyslogParser, KeyValueParser, CSVParser, FallbackParser):
        registry.register(parser_type())
    return registry
