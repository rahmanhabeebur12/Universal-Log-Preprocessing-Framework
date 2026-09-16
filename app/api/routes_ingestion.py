import csv
import io
import json
from fastapi import APIRouter, Depends, HTTPException, UploadFile
from app.api.dependencies import get_processor
from app.models.api import BatchRequest, ProcessRequest
from app.services.processing_service import ProcessingService

router = APIRouter(prefix="/api/v1", tags=["ingestion"])
MAX_UPLOAD = 5_000_000


@router.post("/process")
def process(payload: ProcessRequest, processor: ProcessingService = Depends(get_processor)):
    return processor.process(payload.raw_event)


@router.post("/process/batch")
def batch(payload: BatchRequest, processor: ProcessingService = Depends(get_processor)):
    results = []
    counts = {"successful": 0, "partial": 0, "failed": 0}
    for raw in payload.raw_events:
        try:
            if not raw or len(raw.encode("utf-8")) > 2_000_000:
                raise ValueError("Event is empty or too large")
            result = processor.process(raw)
            status = result["normalized_event"]["metadata"]["normalization_status"]
            counts["successful" if status == "success" else status] += 1
            results.append(result)
        except (ValueError, UnicodeError) as exc:
            counts["failed"] += 1
            results.append({"error": {"type": type(exc).__name__, "message": str(exc)}})
    return {"total_received": len(payload.raw_events), **counts, "results": results}


@router.post("/upload")
async def upload(file: UploadFile, processor: ProcessingService = Depends(get_processor)):
    suffix = (file.filename or "").lower().rsplit(".", 1)[-1]
    if suffix not in {"log", "txt", "json", "csv"}:
        raise HTTPException(415, detail="Allowed extensions: .log, .txt, .json, .csv")
    data = await file.read(MAX_UPLOAD + 1)
    if len(data) > MAX_UPLOAD:
        raise HTTPException(413, detail="Upload exceeds 5 MB")
    try:
        content = data.decode("utf-8")
    except UnicodeDecodeError:
        raise HTTPException(422, detail="Upload must be UTF-8")
    if suffix == "csv":
        rows = list(csv.reader(io.StringIO(content)))
        if len(rows) < 2:
            raise HTTPException(422, detail="CSV needs a header and data rows")
        events = [io.StringIO() for _ in rows[1:]]
        for output, row in zip(events, rows[1:]):
            writer = csv.writer(output, lineterminator="\n")
            writer.writerow(rows[0])
            writer.writerow(row)
        raw_events = [output.getvalue().rstrip("\n") for output in events]
    elif suffix == "json":
        try:
            obj = json.loads(content)
            raw_events = [json.dumps(item, ensure_ascii=False) for item in obj] if isinstance(obj, list) else [content]
        except json.JSONDecodeError:
            raw_events = [line for line in content.splitlines() if line.strip()]
    else:
        raw_events = [line for line in content.splitlines() if line.strip()]
    if len(raw_events) > 1000:
        raise HTTPException(413, detail="Upload exceeds 1000 events")
    return batch(BatchRequest(raw_events=raw_events), processor)
