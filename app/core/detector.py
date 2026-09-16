from dataclasses import dataclass
from app.core.registry import ParserRegistry
from app.parsers.base import BaseParser


@dataclass(frozen=True)
class Detection:
    detected_format: str
    confidence: float
    parser: BaseParser


def detect(raw_event: str, registry: ParserRegistry) -> Detection:
    parser, confidence = registry.select(raw_event)
    return Detection(parser.formats[0], confidence, parser)
