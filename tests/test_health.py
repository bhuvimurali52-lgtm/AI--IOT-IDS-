"""Health endpoint tests for the FastAPI application."""

from fastapi.testclient import TestClient

from app.main import app

client = TestClient(app)


def test_health_endpoint() -> None:
    """Verify GET /health returns the expected Phase 1 payload."""
    response = client.get("/health")
    assert response.status_code == 200
    assert response.json() == {
        "status": "ok",
        "service": "iot-ids",
    }
