"""Smoke tests for auth endpoints."""

import pytest
from httpx import AsyncClient


@pytest.mark.asyncio
async def test_register_user(client: AsyncClient):
    resp = await client.post("/api/v1/auth/register", json={
        "full_name": "Test User",
        "email": "test@example.com",
        "phone": "9876543210",
        "password": "securepass123",
    })
    assert resp.status_code == 201
    data = resp.json()
    assert "access_token" in data
    assert data["user"]["email"] == "test@example.com"


@pytest.mark.asyncio
async def test_register_duplicate(client: AsyncClient):
    payload = {
        "full_name": "Dup User",
        "email": "dup@example.com",
        "phone": "9876543211",
        "password": "pass1234",
    }
    resp1 = await client.post("/api/v1/auth/register", json=payload)
    assert resp1.status_code == 201
    resp2 = await client.post("/api/v1/auth/register", json=payload)
    assert resp2.status_code == 409


@pytest.mark.asyncio
async def test_login_hardik(client: AsyncClient):
    resp = await client.post("/api/v1/auth/login", json={
        "identifier": "hardik",
        "password": "1234",
    })
    assert resp.status_code == 200
    data = resp.json()
    assert "access_token" in data
    assert data["user"]["role"] == "admin"


@pytest.mark.asyncio
async def test_login_invalid(client: AsyncClient):
    resp = await client.post("/api/v1/auth/login", json={
        "identifier": "nobody@nowhere.com",
        "password": "wrong",
    })
    assert resp.status_code == 401


@pytest.mark.asyncio
async def test_get_me(client: AsyncClient):
    login = await client.post("/api/v1/auth/login", json={
        "identifier": "hardik",
        "password": "1234",
    })
    token = login.json()["access_token"]
    resp = await client.get("/api/v1/auth/me", headers={"Authorization": f"Bearer {token}"})
    assert resp.status_code == 200
    assert resp.json()["full_name"] == "hardik"


@pytest.mark.asyncio
async def test_get_me_no_token(client: AsyncClient):
    resp = await client.get("/api/v1/auth/me")
    assert resp.status_code in (401, 403)
