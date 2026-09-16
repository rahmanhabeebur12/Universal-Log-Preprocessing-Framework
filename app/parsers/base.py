from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from typing import Any


@dataclass
class ParsedEvent:
    attributes: dict[str, Any]
    format: str
    hints: dict[str, Any] = field(default_factory=dict)
    warnings: list[str] = field(default_factory=list)


class BaseParser(ABC):
    name: str
    version = "1.0.0"
    priority: int
    formats: tuple[str, ...]

    @abstractmethod
    def can_parse(self, raw_event: str) -> float:
        """Return a confidence in [0, 1]."""

    @abstractmethod
    def parse(self, raw_event: str) -> ParsedEvent:
        """Extract source fields without normalizing them."""
