"""Smoke tests for document endpoints."""

import pytest
from httpx import AsyncClient


async def _get_token(client: AsyncClient) -> str:
    resp = await client.post("/api/v1/auth/login", json={
        "identifier": "hardik",
        "password": "1234",
    })
    return resp.json()["access_token"]


@pytest.mark.asyncio
async def test_list_documents_empty(client: AsyncClient):
    token = await _get_token(client)
    resp = await client.get(
        "/api/v1/documents/my",
        headers={"Authorization": f"Bearer {token}"},
    )
    assert resp.status_code == 200
    assert isinstance(resp.json(), list)


@pytest.mark.asyncio
async def test_upload_no_file(client: AsyncClient):
    token = await _get_token(client)
    resp = await client.post(
        "/api/v1/documents/upload",
        headers={"Authorization": f"Bearer {token}"},
        data={"document_type": "pan"},
    )
    assert resp.status_code == 422
