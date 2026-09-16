import re
from app.parsers.base import BaseParser, ParsedEvent


def split_unescaped(value: str, sep: str, maxsplit: int = -1) -> list[str]:
    parts: list[str] = []
    current: list[str] = []
    splits = 0
    escaped = False
    for char in value:
        if char == sep and not escaped and (maxsplit < 0 or splits < maxsplit):
            parts.append("".join(current))
            current = []
            splits += 1
        else:
            current.append(char)
        if char == "\\":
            escaped = not escaped
        else:
            escaped = False
    parts.append("".join(current))
    return parts


class CEFParser(BaseParser):
    name, priority, formats = "cef", 95, ("cef",)

    def can_parse(self, raw_event: str) -> float:
        return 0.98 if re.search(r"(?:^|\s)CEF:\d+\|", raw_event) else 0.0

    def parse(self, raw_event: str) -> ParsedEvent:
        match = re.search(r"CEF:\d+\|", raw_event)
        if not match:
            raise ValueError("Missing CEF header")
        prefix = raw_event[:match.start()].strip()
        parts = split_unescaped(raw_event[match.start():], "|", 7)
        if len(parts) != 8:
            raise ValueError("CEF requires eight header components")
        keys = ["cef.version", "deviceVendor", "deviceProduct", "deviceVersion", "signatureId", "name", "severity"]
        attrs = dict(zip(keys, [p.replace("\\|", "|") for p in parts[:7]]))
        extension = parts[7]
        matches = list(re.finditer(r"(?<!\\)(?:^|\s)([A-Za-z][\w.]*)=", extension))
        for i, item in enumerate(matches):
            end = matches[i + 1].start() if i + 1 < len(matches) else len(extension)
            attrs[item.group(1)] = extension[item.end():end].strip().replace("\\=", "=").replace("\\|", "|")
        warnings = []
        if extension.strip() and not matches:
            attrs["cef.extension.unparsed"] = extension
            warnings.append("CEF extension has no recognizable key=value fields")
        if prefix:
            attrs["cef.prefix"] = prefix
        return ParsedEvent(attrs, "cef", warnings=warnings)
