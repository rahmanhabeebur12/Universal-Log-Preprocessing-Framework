# ULPF Architecture

## Implemented MVP

```text
Browser
  └─ FastAPI :8000
       ├─ built local frontend assets
       └─ /api/v1
            ├─ ingestion: single event, batch, file upload
            ├─ format detection and deterministic parser registry
            ├─ source identification and field extraction
            ├─ declarative normalization and Pydantic validation
            ├─ SQLite event repository
            └─ JSON / NDJSON export
```

The frontend uses relative `/api/v1` paths. FastAPI serves the production bundle and API from one origin. Vite is used only during frontend development. Runtime operation needs no Node process, cloud service, external database, font CDN, or external API.

Parsers implement a common interface and return source attributes. The processing service selects a parser using detection confidence and deterministic priority, identifies vendor evidence, then calls the normalizer. Generic and vendor mapping files assign canonical paths. The normalizer preserves unused or invalid parsed attributes in `unmapped`; it records `source_field` and `original_value` for each mapped field. Every event retains its submitted raw string, UTF-8 byte length, and SHA-256 hash. A dedicated endpoint recomputes the stored raw hash. The repository is the persistence boundary; the processing logic is independent of SQLite.

The workbench exposes the processing path, canonical values, provenance, unmapped attributes, raw input, warnings, and integrity. Event Explorer reads stored records. Parser Registry and Overview read the existing APIs. The Universal Schema view documents the current event model.

## Production Scale Path (not implemented)

```text
Collectors → Kafka-compatible message bus → horizontally scalable stateless
processing workers → normalized event stream → SIEM / ClickHouse /
Elasticsearch / Data Lake / ML pipeline
```

Scaling requires queueing and backpressure, partition strategy, retention, durable storage, authentication, authorization, operational monitoring, and deployment engineering. Kafka, collectors, distributed workers, and downstream analytics are not part of the MVP. SQLite and synchronous request processing are suitable for local evaluation rather than high-volume ingestion.
