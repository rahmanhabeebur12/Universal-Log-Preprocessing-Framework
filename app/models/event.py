from typing import Any, Literal
from pydantic import BaseModel, Field


class SchemaInfo(BaseModel):
    name: str = "ULPF Universal Security Event"
    version: str = "1.0.0"


class EventInfo(BaseModel):
    id: str
    ingested_at: str
    timestamp: str | None = None
    category: str | None = None
    type: str | None = None
    action: str | None = None
    outcome: str | None = None
    severity: str | None = None


class Endpoint(BaseModel):
    ip: str | None = None
    port: int | None = None
    hostname: str | None = None
    mac: str | None = None


class Network(BaseModel):
    transport: str | None = None
    protocol: str | None = None
    direction: str | None = None
    bytes: int | None = None
    packets: int | None = None
    community_id: str | None = None


class User(BaseModel):
    name: str | None = None
    domain: str | None = None


class Device(BaseModel):
    vendor: str | None = None
    product: str | None = None
    model: str | None = None
    hostname: str | None = None
    serial_number: str | None = None


class Observer(BaseModel):
    ip: str | None = None
    hostname: str | None = None


class Rule(BaseModel):
    id: str | None = None
    name: str | None = None
    category: str | None = None


class HTTP(BaseModel):
    method: str | None = None
    url: str | None = None
    status_code: int | None = None


class DNS(BaseModel):
    query: str | None = None
    record_type: str | None = None


class Raw(BaseModel):
    data: str
    sha256: str
    byte_length: int
    detected_format: str


class ParserInfo(BaseModel):
    name: str
    version: str


class Provenance(BaseModel):
    source_field: str
    original_value: Any


class Metadata(BaseModel):
    normalization_status: Literal["success", "partial", "failed"]
    processing_time_ms: float
    format_confidence: float
    vendor_confidence: float
    vendor_evidence: str


class UniversalEvent(BaseModel):
    schema_: SchemaInfo = Field(default_factory=SchemaInfo, alias="schema")
    event: EventInfo
    source: Endpoint = Field(default_factory=Endpoint)
    destination: Endpoint = Field(default_factory=Endpoint)
    network: Network = Field(default_factory=Network)
    user: User = Field(default_factory=User)
    device: Device = Field(default_factory=Device)
    observer: Observer = Field(default_factory=Observer)
    rule: Rule = Field(default_factory=Rule)
    http: HTTP = Field(default_factory=HTTP)
    dns: DNS = Field(default_factory=DNS)
    message: str | None = None
    tags: list[str] = Field(default_factory=list)
    raw: Raw
    parser: ParserInfo
    provenance: dict[str, Provenance] = Field(default_factory=dict)
    unmapped: dict[str, Any] = Field(default_factory=dict)
    parse_warnings: list[str] = Field(default_factory=list)
    metadata: Metadata
