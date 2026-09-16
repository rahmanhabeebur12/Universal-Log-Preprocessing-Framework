# ULPF

## Overview

Universal Log Pre-processing Framework (ULPF) is a local security-log preprocessing workstation. It ingests heterogeneous perimeter events, extracts source attributes, normalizes them into one universal event schema, and retains the evidence needed to explain each transformation.

## Problem

Firewall and network appliance logs use different formats and field names. A SIEM needs stable fields, while an investigator needs the original record and the source field behind each normalized value. ULPF provides all three in one event document.

## Architecture

**Implemented MVP:** FastAPI serves the API and built frontend from one origin. A stateless processing service uses a parser registry, vendor evidence, declarative mappings, and Pydantic validation. SQLite stores normalized and raw events. JSON and NDJSON export endpoints provide SIEM-ready output. See [ARCHITECTURE.md](ARCHITECTURE.md).

**Production scale path:** collectors → Kafka-compatible message bus → horizontally scalable stateless workers → normalized stream → SIEM, ClickHouse, Elasticsearch, a data lake, or an ML pipeline. These components are not implemented in the MVP.

## Core Pipeline

`raw event → ingestion → format detection → parser selection → source identification → extraction → normalization → validation → raw preservation and provenance → SQLite → export`

Detection uses confidence, then deterministic parser priority. Parse failures and unknown formats preserve raw input and produce explicit status and warnings.

## Universal Event Schema

Events contain `schema`, `event`, `source`, `destination`, `network`, `user`, `device`, `observer`, `rule`, `http`, `dns`, `message`, `tags`, `raw`, `parser`, `provenance`, `unmapped`, `parse_warnings`, and `metadata`. Missing source values remain null. `event.ingested_at` is generated separately from the original event timestamp.

## Supported Formats

JSON objects, CEF, common syslog and Cisco ASA connection messages, whitespace-delimited key/value records, header-and-row CSV, and safe fallback. Five realistic reference inputs are provided in `samples/` and the Live Processor.

## Lossless Processing

Every processed event stores the exact submitted event string in `raw.data`, its UTF-8 byte length, and SHA-256 hash. Source attributes not selected for canonical fields remain in `unmapped`, including invalid values and alternative aliases. The integrity endpoint recalculates the hash from stored raw data. File upload splits line-oriented inputs into records; per-record raw data excludes record separator newlines.

## Field Provenance

Each normalized field records the extracted source field and its original value. For example, FortiGate `srcip` and JSON `source.address` both map to `source.ip`, with their different origins visible in the workbench. Vendor mapping files take precedence over generic aliases.

## Parser Architecture

Every parser implements `BaseParser` with `name`, `version`, `priority`, `formats`, `can_parse`, and `parse`. Parsers extract source fields; the normalizer assigns canonical paths. To add a parser, implement the interface, register it in `default_registry()`, add any mapping preferences, and test with a realistic sample.

## API

| Endpoint | Purpose |
| --- | --- |
| `POST /api/v1/process` | Process one raw event |
| `POST /api/v1/process/batch` | Process a batch |
| `POST /api/v1/upload` | Upload `.log`, `.txt`, `.json`, or `.csv` |
| `GET /api/v1/events` | Browse, search, filter, and paginate stored events |
| `GET /api/v1/events/{id}` | Retrieve a normalized event |
| `GET /api/v1/events/{id}/raw` | Retrieve raw data and hash |
| `GET /api/v1/events/{id}/integrity` | Verify stored raw data |
| `GET /api/v1/parsers` | Read the actual parser registry |
| `GET /api/v1/stats` | Read stored-event counts and timings |
| `GET /api/v1/export/json` | Export normalized JSON |
| `GET /api/v1/export/ndjson` | Export newline-delimited JSON |

OpenAPI documentation remains at `/docs`.

## Development

Create Python and frontend dependencies first (`python3 -m venv .venv`, `.venv/bin/pip install -r requirements.txt`, `cd frontend && npm install`). Then use two terminals:

```sh
.venv/bin/uvicorn app.main:app --host 127.0.0.1 --port 8000 --reload
```

```sh
cd frontend
npm run dev
```

The Vite development UI is at `http://127.0.0.1:5173`; it proxies relative `/api` requests to FastAPI. Build assets are served directly by FastAPI at port 8000 when `frontend/dist` exists.

## Production / Container

```sh
docker build -t ulpf .
docker run --rm -p 8000:8000 ulpf
```

Open `http://127.0.0.1:8000`. The container runs only FastAPI; Node is used in the image build stage. For persistence across container recreation, mount a directory at `/data`, where the container stores `ulpf.db`. A source installation can also use `cd frontend && npm ci && npm run build` followed by `.venv/bin/uvicorn app.main:app --host 127.0.0.1 --port 8000` to serve the production bundle from one process.

## Air-gapped Deployment

The packaged ULPF runtime is self-contained and requires no external network services. Container dependencies are resolved during the image build stage; the resulting image can be transferred into and operated within an air-gapped environment. Source installation with pip/npm needs access to package repositories or local mirrors during installation. The runtime makes no intentional outbound requests and uses no CDN, external font, cloud API, or external database.

## Testing

```sh
.venv/bin/pytest -q
cd frontend && npm run build
cd frontend && npx playwright test
```

Browser integration tests need a running API and frontend, and a local Playwright Chromium installation. Set `ULPF_UI_URL=http://127.0.0.1:8000` to run them against FastAPI-served production assets; the default is Vite at port 5173.

## Current MVP Limitations

SQLite and synchronous processing are for local evaluation, not high-volume streams. Syslog parsing covers common patterns, not all vendor message IDs. Ambiguous timestamps are retained without inventing a timezone. Integrity checking is a hash comparison, not an authenticated signature against coordinated database tampering. Export currently reads all stored events into memory. Authentication and deployment controls are outside this MVP.
