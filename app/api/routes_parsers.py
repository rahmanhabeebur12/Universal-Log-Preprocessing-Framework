from fastapi import APIRouter, Depends
from app.api.dependencies import get_processor
from app.services.processing_service import ProcessingService

router = APIRouter(prefix="/api/v1", tags=["parsers"])


@router.get("/parsers")
def parsers(processor: ProcessingService = Depends(get_processor)):
    return [{"name": p.name, "version": p.version, "formats_handled": p.formats, "priority": p.priority,
             "status": "active"} for p in processor.registry.list()]
