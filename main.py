
import os
import secrets
from pathlib import Path
from datetime import datetime, timezone

import psycopg
from fastapi import FastAPI, HTTPException, Header
from fastapi.responses import JSONResponse

APP_VERSION = "1.2.0"
MIGRATION_VERSION = "001_initial_core"

app = FastAPI(
    title="MASIH GRAM GLOBAL API",
    description="MASIH GRAM GLOBAL ULTIMATE Backend",
    version=APP_VERSION
)


def get_database_url():
    url = os.getenv("DATABASE_URL")
    if not url:
        raise HTTPException(
            status_code=503,
            detail="Database configuration is missing"
        )
    return url


def get_connection():
    try:
        return psycopg.connect(
            get_database_url(),
            connect_timeout=10
        )
    except HTTPException:
        raise
    except Exception:
        raise HTTPException(
            status_code=503,
            detail="Database connection failed"
        )


def verify_admin_key(key):
    expected = os.getenv("ADMIN_API_KEY")

    if not expected:
        raise HTTPException(
            status_code=503,
            detail="Admin API key is not configured"
        )

    if not key or not secrets.compare_digest(key, expected):
        raise HTTPException(
            status_code=403,
            detail="Access denied"
        )


@app.get("/")
def root():
    return {
        "name": "MASIH GRAM GLOBAL",
        "status": "online",
        "version": APP_VERSION,
        "server_time": datetime.now(timezone.utc).isoformat()
    }


@app.get("/api/v1/system/health")
def health():
    return {
        "status": "healthy",
        "service": "masih-gram-backend",
        "timestamp": datetime.now(timezone.utc).isoformat()
    }


@app.get("/api/v1/system/database")
def database_health():
    with get_connection() as connection:
        with connection.cursor() as cursor:
            cursor.execute("SELECT 1")
            result = cursor.fetchone()

    return {
        "status": "connected",
        "database": "PostgreSQL",
        "test": result[0]
    }


@app.get("/api/v1/system/database/tables")
def database_tables(
    x_admin_key: str = Header(default=None)
):
    verify_admin_key(x_admin_key)

    query = """
        SELECT table_schema, table_name
        FROM information_schema.tables
        WHERE table_schema NOT IN (
            'pg_catalog',
            'information_schema'
        )
        AND table_type = 'BASE TABLE'
        ORDER BY table_schema, table_name
    """

    with get_connection() as connection:
        with connection.cursor() as cursor:
            cursor.execute(query)
            rows = cursor.fetchall()

    tables = [
        {"schema": row[0], "name": row[1]}
        for row in rows
    ]

    return {
        "status": "success",
        "database": "PostgreSQL",
        "total_tables": len(tables),
        "tables": tables
    }


@app.post("/api/v1/admin/migrations/apply")
def apply_initial_migration(
    x_admin_key: str = Header(default=None)
):
    verify_admin_key(x_admin_key)

    migration_file = (
        Path(__file__).resolve().parent
        / "001_initial_core.sql"
    )

    if not migration_file.is_file():
        raise HTTPException(
            status_code=500,
            detail="Migration file was not found"
        )

    try:
        sql = migration_file.read_text(encoding="utf-8")

        if not sql.strip():
            raise HTTPException(
                status_code=400,
                detail="Migration file is empty"
            )

        with psycopg.connect(
            get_database_url(),
            connect_timeout=15,
            autocommit=True
        ) as connection:
            with connection.cursor() as cursor:
                cursor.execute(sql, prepare=False)

                cursor.execute("""
                    SELECT COUNT(*)
                    FROM public.mg_schema_migrations
                    WHERE version = %s
                """, (MIGRATION_VERSION,))

                applied = cursor.fetchone()[0]

                cursor.execute("""
                    SELECT COUNT(*)
                    FROM information_schema.tables
                    WHERE table_schema = 'public'
                    AND table_type = 'BASE TABLE'
                    AND table_name LIKE 'mg\\_%'
                """)

                table_count = cursor.fetchone()[0]

        if not applied:
            raise HTTPException(
                status_code=500,
                detail="Migration completion could not be verified"
            )

        return {
            "status": "success",
            "migration": MIGRATION_VERSION,
            "database": "PostgreSQL",
            "applied": True,
            "masih_gram_tables": table_count,
            "message": "MASIH GRAM core migration completed"
        }

    except HTTPException:
        raise
    except Exception:
        raise HTTPException(
            status_code=500,
            detail="Migration failed. Check backend logs."
        )


@app.get("/api/v1/system/info")
def system_info():
    return {
        "application": "MASIH GRAM",
        "edition": "GLOBAL ULTIMATE",
        "api_version": "v1",
        "backend_version": APP_VERSION,
        "modules": {
            "authentication": "core_database_ready",
            "messaging": "core_database_ready",
            "groups": "core_database_ready",
            "channels": "core_database_ready",
            "media": "core_database_ready",
            "social": "in_development",
            "ai": "planned",
            "cloud": "planned",
            "live": "planned"
        }
    }


@app.exception_handler(404)
async def not_found_handler(request, exc):
    return JSONResponse(
        status_code=404,
        content={
            "success": False,
            "error": "Endpoint not found"
        }
    )
