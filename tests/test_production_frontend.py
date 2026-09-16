from pathlib import Path
import re
import pytest
from fastapi.testclient import TestClient
from app.main import app

DIST = Path(__file__).resolve().parents[1] / "frontend" / "dist"


@pytest.mark.skipif(not (DIST / "index.html").is_file(), reason="production frontend has not been built")
def test_fastapi_serves_frontend_and_keeps_api_routes(tmp_path, monkeypatch):
    monkeypatch.setenv("ULPF_DB_PATH", str(tmp_path / "production.db"))
    with TestClient(app) as client:
        root = client.get("/")
        assert root.status_code == 200
        assert "text/html" in root.headers["content-type"]
        assert "ULPF / Security Event Workstation" in root.text
        asset = re.search(r'src="([^"]+\.js)"', root.text)
        assert asset is not None
        assert client.get(asset.group(1)).status_code == 200
        assert client.get("/samples/fortigate.log").status_code == 200
        assert client.get("/docs").status_code == 200
        assert client.get("/api/v1/parsers").status_code == 200
        assert client.get("/api/v1/stats").status_code == 200
        assert client.get("/api/v1/does-not-exist").status_code == 404
