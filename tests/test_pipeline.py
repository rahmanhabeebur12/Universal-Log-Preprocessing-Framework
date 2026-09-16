import hashlib
import json
from pathlib import Path
import pytest
from fastapi.testclient import TestClient
from app.main import app
from app.core.registry import default_registry
from app.core.normalizer import parse_timestamp

SAMPLES = Path(__file__).resolve().parents[1] / "samples"


@pytest.fixture
def client(tmp_path, monkeypatch):
    monkeypatch.setenv("ULPF_DB_PATH", str(tmp_path / "test.db"))
    with TestClient(app) as test_client:
        yield test_client


def sample(name):
    return (SAMPLES / name).read_text().strip()


@pytest.mark.parametrize("name,format", [("firewall.json", "json"), ("generic_cef.log", "cef"),
    ("cisco_asa.log", "syslog"), ("fortigate.log", "keyvalue"), ("paloalto.csv", "csv")])
def test_detection(name, format):
    parser, confidence = default_registry().select(sample(name))
    assert parser.formats[0] == format and confidence > 0.5


@pytest.mark.parametrize("name,vendor", [("cisco_asa.log", "Cisco"), ("fortigate.log", "Fortinet"),
    ("paloalto.csv", "Palo Alto Networks"), ("generic_cef.log", "Acme Security")])
def test_vendor_samples(client, name, vendor):
    response = client.post("/api/v1/process", json={"raw_event": sample(name)})
    assert response.status_code == 200
    result = response.json()
    assert result["vendor"] == vendor
    event = result["normalized_event"]
    assert event["raw"]["data"] == sample(name)
    assert event["source"]["ip"] is not None
    assert event["destination"]["ip"] is not None


def test_fortinet_normalization_and_provenance(client):
    event = client.post("/api/v1/process", json={"raw_event": sample("fortigate.log")}).json()["normalized_event"]
    assert event["event"]["action"] == "allow"
    assert event["network"]["transport"] == "tcp"
    assert event["network"]["bytes"] == 1247
    assert event["provenance"]["source.ip"] == {"source_field": "srcip", "original_value": "10.10.20.15"}
    assert event["unmapped"]["rcvdbyte"] == "8324"
    assert event["event"]["timestamp"] is None
    assert event["metadata"]["normalization_status"] == "partial"


def test_cisco_message(client):
    event = client.post("/api/v1/process", json={"raw_event": sample("cisco_asa.log")}).json()["normalized_event"]
    assert event["parser"]["name"] == "syslog"
    assert event["event"]["action"] == "allow"
    assert event["rule"]["id"] == "302013"


def test_generic_aliases_and_timestamp(client):
    event = client.post("/api/v1/process", json={"raw_event": sample("firewall.json")}).json()["normalized_event"]
    assert event["source"]["ip"] == "192.0.2.25"
    assert event["event"]["timestamp"] == "2026-09-16T12:34:56Z"
    assert event["unmapped"]["sensor_id"] == "edge-west-02"
    assert event["provenance"]["source.ip"]["source_field"] == "source.address"


def test_action_protocol_aliases(client):
    raw = '{"src":"192.0.2.1","dst":"198.51.100.2","act":"drop","proto":17}'
    event = client.post("/api/v1/process", json={"raw_event": raw}).json()["normalized_event"]
    assert event["event"]["action"] == "deny"
    assert event["network"]["transport"] == "udp"


def test_timestamp_handling(client):
    assert parse_timestamp("2026-09-16T18:04:56+05:30") == "2026-09-16T12:34:56Z"
    raw = '{"timestamp":"yesterday","srcip":"192.0.2.1"}'
    event = client.post("/api/v1/process", json={"raw_event": raw}).json()["normalized_event"]
    assert event["event"]["timestamp"] is None
    assert event["unmapped"]["timestamp"] == "yesterday"
    assert event["parse_warnings"]


def test_integrity_and_raw(client):
    raw = sample("generic_cef.log")
    response = client.post("/api/v1/process", json={"raw_event": raw}).json()
    event_id = response["event_id"]
    event = response["normalized_event"]
    expected = hashlib.sha256(raw.encode()).hexdigest()
    assert event["raw"]["sha256"] == expected
    assert event["raw"]["byte_length"] == len(raw.encode())
    assert client.get(f"/api/v1/events/{event_id}/raw").json()["data"] == raw
    assert client.get(f"/api/v1/events/{event_id}/integrity").json() == {
        "verified": True, "stored_hash": expected, "calculated_hash": expected}
    assert client.get(f"/api/v1/events/{event_id}").json() == event


def test_malformed_unknown_batch_and_stats(client):
    batch = client.post("/api/v1/process/batch", json={"raw_events": ["{bad json", "unstructured event", sample("firewall.json")]})
    assert batch.status_code == 200
    body = batch.json()
    assert body["total_received"] == 3
    assert body["failed"] == 1 and body["partial"] == 1 and body["successful"] == 1
    assert body["results"][1]["vendor"] == "Unknown"
    assert body["results"][0]["normalized_event"]["raw"]["data"] == "{bad json"
    assert client.get("/api/v1/stats").json()["total_processed"] == 3


def test_filters_exports_and_upload(client):
    response = client.post("/api/v1/upload", files={"file": ("events.log", sample("fortigate.log"), "text/plain")})
    assert response.status_code == 200 and response.json()["total_received"] == 1
    assert len(client.get("/api/v1/events", params={"vendor": "Fortinet"}).json()["items"]) == 1
    assert len(client.get("/api/v1/export/json").json()) == 1
    assert len(client.get("/api/v1/export/ndjson").text.strip().splitlines()) == 1
    assert len(client.get("/api/v1/parsers").json()) == 6
