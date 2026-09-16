import json
import sqlite3
from typing import Any
from app.core.integrity import digest


class EventStore:
    def __init__(self, connection: sqlite3.Connection):
        self.connection = connection

    def save(self, event: dict[str, Any]) -> None:
        e, m = event["event"], event["metadata"]
        self.connection.execute("""INSERT INTO events VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?)""", (
            e["id"], e["ingested_at"], event["raw"]["detected_format"], event["device"]["vendor"] or "Unknown",
            json.dumps(event, ensure_ascii=False), event["raw"]["data"], event["raw"]["sha256"],
            event["parser"]["name"], event["parser"]["version"], m["processing_time_ms"],
            m["normalization_status"], e["action"], e["severity"]
        ))
        self.connection.commit()

    def get(self, event_id: str) -> dict[str, Any] | None:
        row = self.connection.execute("SELECT normalized_json FROM events WHERE id=?", (event_id,)).fetchone()
        return json.loads(row[0]) if row else None

    def raw(self, event_id: str) -> dict[str, Any] | None:
        row = self.connection.execute("SELECT raw_event, sha256 FROM events WHERE id=?", (event_id,)).fetchone()
        return {"data": row[0], "sha256": row[1]} if row else None

    def verify_integrity(self, event_id: str) -> dict[str, Any] | None:
        row = self.raw(event_id)
        if row is None:
            return None
        calculated, _ = digest(row["data"])
        return {"verified": calculated == row["sha256"], "stored_hash": row["sha256"], "calculated_hash": calculated}

    def list(self, limit: int = 100, offset: int = 0, vendor: str | None = None, format: str | None = None,
             action: str | None = None, severity: str | None = None, search: str | None = None) -> list[dict[str, Any]]:
        clauses, args = [], []
        for column, value in (("vendor", vendor), ("detected_format", format), ("action", action), ("severity", severity)):
            if value is not None:
                clauses.append(f"{column}=?")
                args.append(value)
        if search:
            clauses.append("(raw_event LIKE ? OR normalized_json LIKE ?)")
            args.extend([f"%{search}%", f"%{search}%"])
        where = " WHERE " + " AND ".join(clauses) if clauses else ""
        rows = self.connection.execute("SELECT normalized_json FROM events" + where + " ORDER BY ingested_at DESC LIMIT ? OFFSET ?", (*args, limit, offset)).fetchall()
        return [json.loads(row[0]) for row in rows]

    def all_events(self) -> list[dict[str, Any]]:
        rows = self.connection.execute("SELECT normalized_json FROM events ORDER BY ingested_at, id").fetchall()
        return [json.loads(row[0]) for row in rows]

    def stats(self) -> dict[str, Any]:
        db = self.connection
        counts = lambda col: {row[0] or "unknown": row[1] for row in db.execute(f"SELECT {col}, COUNT(*) FROM events GROUP BY {col}")}
        status = counts("normalization_status")
        row = db.execute("SELECT COUNT(*), AVG(processing_time_ms), MAX(ingested_at) FROM events").fetchone()
        return {"total_processed": row[0], "successful": status.get("success", 0), "partial": status.get("partial", 0),
                "failed": status.get("failed", 0), "events_by_format": counts("detected_format"),
                "events_by_vendor": counts("vendor"), "events_by_action": counts("action"),
                "events_by_severity": counts("severity"), "average_processing_time_ms": row[1] or 0,
                "last_event_time": row[2]}
