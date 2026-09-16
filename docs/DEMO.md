# Two-minute demo script

| Time | Action | Point to show |
| --- | --- | --- |
| 0:00–0:10 | Open ULPF at `http://127.0.0.1:8000`; enter Live Processor. | One local workstation, one origin. |
| 0:10–0:35 | Select FortiGate sample and process it. | `srcip`, `dstip`, `dstport`, `proto=6`, `action=accept` become canonical source, destination, port, TCP, and allow. |
| 0:35–0:55 | Open Field Traceability. | `source.ip ← srcip` and other exact source-field mappings. |
| 0:55–1:10 | Open Preserved Fields, then Raw & Integrity; verify SHA-256. | Unmapped fields remain; original input is intact. |
| 1:10–1:35 | Select JSON sample, process, open Traceability. | `source.ip ← source.address` reaches the same canonical field through a different parser. |
| 1:35–1:45 | Open Parser Registry. | Actual registered parsers and versions from the API. |
| 1:45–2:00 | Close with architecture statement. | Local FastAPI/SQLite MVP; collectors, message bus, and distributed workers are a future scale path. |
