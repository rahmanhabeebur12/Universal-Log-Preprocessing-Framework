from fastapi import APIRouter, Depends, HTTPException, Query
from fastapi.responses import StreamingResponse
from app.api.dependencies import get_store
from app.services.event_store import EventStore
from app.services.export_service import ndjson

router = APIRouter(prefix="/api/v1", tags=["events"])


@router.get("/events")
def list_events(limit: int = Query(100, ge=1, le=1000), offset: int = Query(0, ge=0), vendor: str | None = None,
                format: str | None = None, action: str | None = None, severity: str | None = None,
                search: str | None = None, store: EventStore = Depends(get_store)):
    return {"items": store.list(limit, offset, vendor, format, action, severity, search), "limit": limit, "offset": offset}


@router.get("/events/{event_id}")
def get_event(event_id: str, store: EventStore = Depends(get_store)):
    event = store.get(event_id)
    if event is None:
        raise HTTPException(404, detail="Event not found")
    return event


@router.get("/events/{event_id}/raw")
def get_raw(event_id: str, store: EventStore = Depends(get_store)):
    value = store.raw(event_id)
    if value is None:
        raise HTTPException(404, detail="Event not found")
    return value


@router.get("/events/{event_id}/integrity")
def integrity(event_id: str, store: EventStore = Depends(get_store)):
    value = store.verify_integrity(event_id)
    if value is None:
        raise HTTPException(404, detail="Event not found")
    return value


@router.get("/export/ndjson")
def export_ndjson(store: EventStore = Depends(get_store)):
    return StreamingResponse(ndjson(store), media_type="application/x-ndjson")


@router.get("/export/json")
def export_json(store: EventStore = Depends(get_store)):
    return store.all_events()
