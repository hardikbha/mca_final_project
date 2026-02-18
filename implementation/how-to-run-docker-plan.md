# Docker Run Plan (Demo and Viva Friendly)

Use Docker Compose to keep demo setup repeatable.

## 1) Compose services to include

- `frontend` (React)
- `backend` (FastAPI)
- `ml-service` (PyTorch inference)
- `postgres`
- `mongodb`
- `redis`
- `nginx` (optional reverse proxy)

## 2) Expected command flow

```bash
cd infra
docker compose up -d --build
docker compose ps
docker compose logs -f backend
```

Stop:

```bash
docker compose down
```

Reset local demo data:

```bash
docker compose down -v
docker compose up -d --build
```

## 3) Health checks to define

- Backend health endpoint: `/health`
- ML service health endpoint: `/health`
- Postgres readiness: `pg_isready`
- Redis ping check

## 4) Demo mode setup

Add seed script for viva/demo:

```bash
docker compose exec backend python scripts/seed_demo_data.py
```

Seed data should include:

- one normal user,
- one admin/reviewer,
- one approved sample KYC,
- one flagged sample KYC for manual review.

## 5) Why this matters for IGNOU viva

- You can launch the complete executable quickly.
- You can reliably show end-to-end workflow live.
- You can demonstrate logs, reports, and security behavior in one setup.
