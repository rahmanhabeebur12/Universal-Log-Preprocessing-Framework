from app.parsers.base import BaseParser, ParsedEvent


class FallbackParser(BaseParser):
    name, priority, formats = "fallback", 0, ("unknown",)

    def can_parse(self, raw_event: str) -> float:
        return 0.01

    def parse(self, raw_event: str) -> ParsedEvent:
        return ParsedEvent({}, "unknown", warnings=["No structured parser matched; original event retained"])
