#!/bin/sh
set -e

# Render provides DATABASE_URL as postgres://...
# Derive async (app) and sync (alembic) variants from it.
if [ -n "$DATABASE_URL" ]; then
  export APP_DB_DSN=$(echo "$DATABASE_URL" | sed 's|^postgres://|postgresql+asyncpg://|g' | sed 's|^postgresql://|postgresql+asyncpg://|g')
  export POSTGRES_DSN=$(echo "$DATABASE_URL" | sed 's|^postgres://|postgresql+psycopg://|g' | sed 's|^postgresql://|postgresql+psycopg://|g')
  echo "Derived APP_DB_DSN and POSTGRES_DSN from DATABASE_URL"
fi

# Run alembic only when connecting to PostgreSQL
if echo "${APP_DB_DSN:-}" | grep -q "postgresql"; then
  echo "Running database migrations..."
  python -m alembic upgrade head
fi

exec uvicorn app.main:app --host 0.0.0.0 --port 8000
