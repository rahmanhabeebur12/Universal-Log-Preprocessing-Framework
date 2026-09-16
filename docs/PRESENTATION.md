# ULPF — Five-slide presentation

## Slide 1 — Problem + ULPF
- Perimeter security devices emit incompatible logs.
- ULPF converts them to one security event schema while retaining source evidence.

## Slide 2 — Processing architecture
- Ingest → detect format → select parser → extract → identify vendor → normalize → validate → store → export.
- Phase 1 uses FastAPI, a parser registry, and SQLite.

## Slide 3 — Schema, losslessness, provenance
- Canonical event, source, destination, network, device, rule, and related fields.
- Exact raw input, SHA-256, unmapped fields, and source-field provenance travel with every event.

## Slide 4 — Cross-vendor demonstration
- FortiGate `srcip` and JSON `source.address` both map to `source.ip`.
- Parsers extract; declarative mapping files normalize. New parsers register through a common interface.

## Slide 5 — Deployment and scale path
- One FastAPI container serves API and local frontend without runtime external services.
- Future path: collectors → message bus → stateless workers → normalized stream → SIEM or data platform.
