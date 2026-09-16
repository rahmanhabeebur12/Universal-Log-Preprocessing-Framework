import ipaddress
import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any
from app.core.taxonomy import action, protocol

MAPPING_DIR = Path(__file__).resolve().parents[1] / "mappings"
INTEGER_FIELDS = {"source.port", "destination.port", "network.bytes", "network.packets", "http.status_code"}
IP_FIELDS = {"source.ip", "destination.ip", "observer.ip"}


def parse_timestamp(value: Any) -> str:
    text = str(value).strip()
    if text.isdigit() and len(text) in (10, 13):
        seconds = int(text) / (1000 if len(text) == 13 else 1)
        return datetime.fromtimestamp(seconds, timezone.utc).isoformat().replace("+00:00", "Z")
    try:
        dt = datetime.fromisoformat(text.replace("Z", "+00:00"))
    except ValueError:
        for pattern in ("%Y/%m/%d %H:%M:%S", "%Y-%m-%d %H:%M:%S"):
            try:
                dt = datetime.strptime(text, pattern)
                break
            except ValueError:
                continue
        else:
            raise ValueError("timestamp is ambiguous or invalid")
    if dt.tzinfo is None:
        raise ValueError("timestamp lacks timezone")
    return dt.astimezone(timezone.utc).isoformat().replace("+00:00", "Z")


def _convert(path: str, value: Any) -> Any:
    if value is None or value == "":
        raise ValueError("empty value")
    if path == "event.timestamp":
        return parse_timestamp(value)
    if path in IP_FIELDS:
        return str(ipaddress.ip_address(str(value)))
    if path in INTEGER_FIELDS:
        result = int(value)
        if result < 0 or (path.endswith(".port") and result > 65535):
            raise ValueError("out of range")
        return result
    if path == "event.action":
        return action(value)
    if path == "network.transport":
        return protocol(value)
    return str(value)


def normalize(attrs: dict[str, Any], vendor: str) -> tuple[dict[str, Any], dict[str, Any], dict[str, Any], list[str]]:
    with (MAPPING_DIR / "generic.json").open() as file:
        generic = json.load(file)
    vendor_file = {"Fortinet": "fortinet", "Cisco": "cisco", "Palo Alto Networks": "paloalto"}.get(vendor)
    overrides = {}
    if vendor_file:
        with (MAPPING_DIR / f"{vendor_file}.json").open() as file:
            overrides = json.load(file)
    mapped: dict[str, Any] = {}
    provenance: dict[str, Any] = {}
    consumed: set[str] = set()
    warnings: list[str] = []
    for path, aliases in generic.items():
        choices = list(dict.fromkeys(overrides.get(path, []) + aliases))
        present = [key for key in choices if key in attrs and attrs[key] not in (None, "")]
        if not present:
            continue
        key = present[0]
        try:
            mapped[path] = _convert(path, attrs[key])
            provenance[path] = {"source_field": key, "original_value": attrs[key]}
            consumed.add(key)
        except (ValueError, TypeError, OverflowError) as exc:
            warnings.append(f"Cannot normalize {key} as {path}: {exc}")
    # Explicitly retain aliases not selected, including conflicting duplicate meanings.
    unmapped = {key: value for key, value in attrs.items() if key not in consumed}
    return mapped, provenance, unmapped, warnings
