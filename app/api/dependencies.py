from fastapi import Request
from app.services.event_store import EventStore
from app.services.processing_service import ProcessingService


def get_store(request: Request) -> EventStore:
    return request.app.state.store


def get_processor(request: Request) -> ProcessingService:
    return request.app.state.processor
