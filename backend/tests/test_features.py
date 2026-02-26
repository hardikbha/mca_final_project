"""Smoke tests for feature endpoints."""

import pytest
from httpx import AsyncClient


async def _get_admin_token(client: AsyncClient) -> str:
    resp = await client.post("/api/v1/auth/login", json={
        "identifier": "hardik",
        "password": "1234",
    })
    return resp.json()["access_token"]


@pytest.mark.asyncio
async def test_feature_catalog(client: AsyncClient):
    token = await _get_admin_token(client)
    resp = await client.get(
        "/api/v1/features/catalog",
        headers={"Authorization": f"Bearer {token}"},
    )
    assert resp.status_code == 200
    data = resp.json()
    assert "features" in data
    assert len(data["features"]) == 5


@pytest.mark.asyncio
async def test_pipeline_state(client: AsyncClient):
    token = await _get_admin_token(client)
    resp = await client.get(
        "/api/v1/features/state",
        headers={"Authorization": f"Bearer {token}"},
    )
    assert resp.status_code == 200
    data = resp.json()
    assert data["has_document"] is False


@pytest.mark.asyncio
async def test_final_report_missing_steps(client: AsyncClient):
    token = await _get_admin_token(client)
    resp = await client.post(
        "/api/v1/features/final-report",
        json={"email": "test@example.com"},
        headers={"Authorization": f"Bearer {token}"},
    )
    assert resp.status_code == 400
    assert "Missing" in resp.json()["detail"]
