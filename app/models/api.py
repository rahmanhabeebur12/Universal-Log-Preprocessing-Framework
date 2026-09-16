from pydantic import BaseModel, Field


class ProcessRequest(BaseModel):
    raw_event: str = Field(min_length=1, max_length=2_000_000)


class BatchRequest(BaseModel):
    raw_events: list[str] = Field(min_length=1, max_length=1000)
