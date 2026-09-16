import re
import shlex
from app.parsers.base import BaseParser, ParsedEvent


class KeyValueParser(BaseParser):
    name, priority, formats = "keyvalue", 75, ("keyvalue",)

    def can_parse(self, raw_event: str) -> float:
        count = len(re.findall(r"(?:^|\s)[\w.\-]+=", raw_event))
        return 0.9 if count >= 3 else (0.55 if count >= 2 else 0.0)

    def parse(self, raw_event: str) -> ParsedEvent:
        attrs: dict[str, str] = {}
        unparsed: list[str] = []
        for token in shlex.split(raw_event, posix=True):
            if "=" in token:
                key, value = token.split("=", 1)
                if key:
                    if key in attrs:
                        unparsed.append(f"duplicate {key}={value}")
                    else:
                        attrs[key] = value
                    continue
            unparsed.append(token)
        if unparsed:
            attrs["keyvalue.unparsed"] = " ".join(unparsed)
        return ParsedEvent(attrs, "keyvalue", warnings=["Unparsed key=value text retained"] if unparsed else [])
