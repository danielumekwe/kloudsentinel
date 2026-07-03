from __future__ import annotations

from fastapi.testclient import TestClient


def test_liveness_returns_ok(client: TestClient) -> None:
    response = client.get("/api/v1/health")
    assert response.status_code == 200
    body = response.json()
    assert body["status"] == "ok"
    assert body["uptime_seconds"] >= 0


def test_readiness_reports_database_ok(client: TestClient) -> None:
    response = client.get("/api/v1/health/ready")
    assert response.status_code == 200
    body = response.json()
    assert body["status"] == "ready"
    assert body["checks"]["database"] == "ok"


def test_request_id_header_is_set(client: TestClient) -> None:
    response = client.get("/api/v1/health")
    assert "X-Request-ID" in response.headers
