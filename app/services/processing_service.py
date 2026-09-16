import time
from datetime import datetime, timezone
from uuid import uuid4
from typing import Any
from app.core.detector import detect
from app.core.integrity import digest
from app.core.normalizer import normalize
from app.core.registry import ParserRegistry, default_registry
from app.core.taxonomy import identify_vendor
from app.models.event import UniversalEvent
from app.services.event_store import EventStore


class ProcessingService:
    def __init__(self, store: EventStore, registry: ParserRegistry | None = None):
        self.store = store
        self.registry = registry or default_registry()

    def process(self, raw_event: str) -> dict[str, Any]:
        start = time.perf_counter()
        detection = detect(raw_event, self.registry)
        warnings: list[str] = []
        try:
            parsed = detection.parser.parse(raw_event)
            attrs = parsed.attributes
            warnings.extend(parsed.warnings)
        except (ValueError, TypeError, UnicodeError) as exc:
            attrs = {}
            warnings.append(f"Parser failed: {exc}")
        vendor, vendor_confidence, evidence = identify_vendor(attrs, detection.detected_format)
        mapped, provenance, unmapped, norm_warnings = normalize(attrs, vendor)
        warnings.extend(norm_warnings)
        if "date" in attrs and "time" in attrs and "event.timestamp" not in mapped:
            from app.core.normalizer import parse_timestamp
            try:
                value = f'{attrs["date"]}T{attrs["time"]}'
                # FortiOS local wall time has no UTC offset; retain source and warn.
                parse_timestamp(value)
            except ValueError:
                warnings.append("date/time lack timezone; event timestamp retained as source attributes")
        if "timestamp" in attrs and detection.detected_format == "syslog" and "event.timestamp" not in mapped:
            warnings.append("Syslog timestamp lacks a year or timezone; original value retained")
        sha, byte_length = digest(raw_event)
        now = datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")
        status = "failed" if any(w.startswith("Parser failed") for w in warnings) else "partial" if warnings else "success"
        document: dict[str, Any] = {
            "schema": {"name": "ULPF Universal Security Event", "version": "1.0.0"},
            "event": {"id": str(uuid4()), "ingested_at": now, "timestamp": None, "category": None, "type": None,
                      "action": None, "outcome": None, "severity": None},
            "source": {}, "destination": {}, "network": {}, "user": {}, "device": {}, "observer": {},
            "rule": {}, "http": {}, "dns": {}, "message": None, "tags": [],
            "raw": {"data": raw_event, "sha256": sha, "byte_length": byte_length, "detected_format": detection.detected_format},
            "parser": {"name": detection.parser.name, "version": detection.parser.version},
            "provenance": provenance, "unmapped": unmapped, "parse_warnings": warnings,
            "metadata": {"normalization_status": status, "processing_time_ms": 0.0,
                         "format_confidence": detection.confidence, "vendor_confidence": vendor_confidence,
                         "vendor_evidence": evidence}
        }
        document["device"]["vendor"] = vendor
        for path, value in mapped.items():
            parts = path.split(".")
            if len(parts) == 1:
                document[parts[0]] = value
            else:
                document[parts[0]][parts[1]] = value
        document["metadata"]["processing_time_ms"] = round((time.perf_counter() - start) * 1000, 3)
        event = UniversalEvent.model_validate(document).model_dump(by_alias=True)
        self.store.save(event)
        return {"event_id": event["event"]["id"], "detected_format": detection.detected_format,
                "format_confidence": detection.confidence, "vendor": vendor,
                "parser": event["parser"], "processing_time_ms": event["metadata"]["processing_time_ms"],
                "normalized_event": event}
