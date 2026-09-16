import json
from collections.abc import Iterator
from app.services.event_store import EventStore


def ndjson(store: EventStore) -> Iterator[str]:
    for event in store.all_events():
        yield json.dumps(event, ensure_ascii=False, separators=(",", ":")) + "\n"
