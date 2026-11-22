import os
from datetime import datetime, timezone

import psycopg
from fastapi import FastAPI, HTTPException
from fastapi.responses import JSONResponse

app = FastAPI(
    title="MASIH GRAM GLOBAL API",
    description="Core backend services for MASIH GRAM",
    version="1.0.0"
)


@app.get("/")
def root():
    return {
        "name": "MASIH GRAM GLOBAL",
        "status": "online",
        "version": "1.0.0",
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
    database_url = os.getenv("DATABASE_URL")

    if not database_url:
        raise HTTPException(
            status_code=503,
            detail="Database configuration is missing"
        )

    try:
        with psycopg.connect(
            database_url,
            connect_timeout=5
        ) as connection:
            with connection.cursor() as cursor:
                cursor.execute("SELECT 1")
                result = cursor.fetchone()

        return {
            "status": "connected",
            "database": "PostgreSQL",
            "test": result[0]
        }

    except Exception:
        raise HTTPException(
            status_code=503,
            detail="Database connection failed"
        )


@app.get("/api/v1/system/info")
def system_info():
    return {
        "application": "MASIH GRAM",
        "edition": "GLOBAL ULTIMATE",
        "api_version": "v1",
        "modules": {
            "authentication": "planned",
            "messaging": "planned",
            "groups": "planned",
            "media": "planned",
            "social": "planned",
            "ai": "planned"
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
