from fastapi import APIRouter, Depends
from app.api.dependencies import get_store
from app.services.event_store import EventStore

router = APIRouter(prefix="/api/v1", tags=["stats"])


@router.get("/stats")
def stats(store: EventStore = Depends(get_store)):
    return store.stats()
