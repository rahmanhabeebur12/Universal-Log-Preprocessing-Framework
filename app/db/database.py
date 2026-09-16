import sqlite3
from pathlib import Path

DEFAULT_DB = Path(__file__).resolve().parents[2] / "ulpf.db"


def connect(path: str | Path = DEFAULT_DB) -> sqlite3.Connection:
    connection = sqlite3.connect(str(path), check_same_thread=False)
    connection.row_factory = sqlite3.Row
    connection.execute("""CREATE TABLE IF NOT EXISTS events (
        id TEXT PRIMARY KEY, ingested_at TEXT NOT NULL, detected_format TEXT NOT NULL,
        vendor TEXT NOT NULL, normalized_json TEXT NOT NULL, raw_event TEXT NOT NULL,
        sha256 TEXT NOT NULL, parser_name TEXT NOT NULL, parser_version TEXT NOT NULL,
        processing_time_ms REAL NOT NULL, normalization_status TEXT NOT NULL,
        action TEXT, severity TEXT)""")
    connection.execute("CREATE INDEX IF NOT EXISTS events_filters ON events(vendor, detected_format, action, severity)")
    connection.commit()
    return connection
