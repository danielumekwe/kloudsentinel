from __future__ import annotations

from fastapi.testclient import TestClient


def test_oversized_request_body_is_rejected(client: TestClient) -> None:
    """MaxBodySizeMiddleware must reject a request whose declared
    Content-Length exceeds the cap before any route/dependency code
    (including CSRF/session lookups) touches it — otherwise a client can
    force the server to buffer an arbitrarily large body in memory."""
    oversized_password = "x" * (2 * 1024 * 1024)

    response = client.post(
        "/dashboard/login", data={"username": "admin", "password": oversized_password}
    )

    assert response.status_code == 413


def test_normal_sized_request_is_not_affected(client: TestClient) -> None:
    response = client.post("/dashboard/login", data={"username": "admin", "password": "wrong"})

    assert response.status_code == 401
