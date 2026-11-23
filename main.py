import os
import re
import json
import hmac
import uuid
import time
import base64
import hashlib
import secrets
from pathlib import Path
from datetime import datetime, timedelta, timezone
from typing import Optional

import httpx
import psycopg
from psycopg import errors

from fastapi import FastAPI, HTTPException, Header, Request
from fastapi.responses import JSONResponse
from pydantic import BaseModel, Field


APP_VERSION = "2.1.0"
MIGRATION_VERSION = "001_initial_core"
AUTH_MIGRATION_VERSION = "002_auth_engine"

TEXTBEE_URL = "https://api.textbee.dev/api/v1/gateway/send-sms"

OTP_LIFETIME_SECONDS = 300
OTP_RESEND_SECONDS = 60
OTP_MAX_ATTEMPTS = 5
OTP_HOURLY_LIMIT = 3
IP_HOURLY_LIMIT = 10

ACCESS_TOKEN_SECONDS = 900
REFRESH_TOKEN_DAYS = 30

app = FastAPI(
    title="MASIH GRAM GLOBAL API",
    description="MASIH GRAM GLOBAL ULTIMATE ENGINE",
    version=APP_VERSION
)


# ---------------------------------------------------------
# CONFIGURATION
# ---------------------------------------------------------

def env_required(name: str) -> str:
    value = os.getenv(name)
    if not value:
        raise HTTPException(
            status_code=503,
            detail=f"Server configuration missing: {name}"
        )
    return value


def get_database_url() -> str:
    return env_required("DATABASE_URL")


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


def utcnow():
    return datetime.now(timezone.utc)


def verify_admin_key(key: Optional[str]):
    expected = os.getenv("ADMIN_API_KEY")
    if not expected:
        raise HTTPException(
            status_code=503,
            detail="Admin API key is not configured"
        )
    if not key or not secrets.compare_digest(key, expected):
        raise HTTPException(status_code=403, detail="Access denied")


def _secret_bytes(name: str) -> bytes:
    value = env_required(name)
    raw = value.encode("utf-8")
    if len(raw) < 32:
        raise HTTPException(
            status_code=503,
            detail=f"{name} must contain at least 32 bytes"
        )
    return raw


def auth_secret() -> bytes:
    return _secret_bytes("AUTH_SECRET")


def otp_pepper() -> bytes:
    return _secret_bytes("OTP_PEPPER")


# ---------------------------------------------------------
# REQUEST MODELS
# ---------------------------------------------------------

class OTPRequest(BaseModel):
    phone: str = Field(min_length=8, max_length=30)
    purpose: str = Field(pattern="^(signup|login)$")


class OTPVerify(BaseModel):
    phone: str = Field(min_length=8, max_length=30)
    purpose: str = Field(pattern="^(signup|login)$")
    code: str = Field(pattern="^[0-9]{6}$")
    username: Optional[str] = Field(default=None, min_length=3, max_length=32)
    display_name: Optional[str] = Field(default=None, min_length=1, max_length=100)
    device_name: Optional[str] = Field(default=None, max_length=120)
    platform: Optional[str] = Field(default="Android", max_length=50)
    app_version: Optional[str] = Field(default=None, max_length=40)


class RefreshRequest(BaseModel):
    refresh_token: str = Field(min_length=30, max_length=200)


# ---------------------------------------------------------
# PHONE AND HASH UTILITIES
# ---------------------------------------------------------

def normalize_phone(phone: str) -> str:
    value = re.sub(r"[\s\-().]", "", phone.strip())
    if not re.fullmatch(r"\+[1-9][0-9]{7,14}", value):
        raise HTTPException(
            status_code=422,
            detail="Phone must use international format, for example +989121234567"
        )
    return value


def hash_otp(phone: str, purpose: str, code: str) -> str:
    message = f"{phone}:{purpose}:{code}".encode("utf-8")
    return hmac.new(otp_pepper(), message, hashlib.sha256).hexdigest()


def hash_refresh_token(token: str) -> str:
    return hashlib.sha256(token.encode("utf-8")).hexdigest()


def get_client_ip(request: Request) -> Optional[str]:
    if request.client:
        return request.client.host
    return None


# ---------------------------------------------------------
# ACCESS TOKEN
# ---------------------------------------------------------

def b64url(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def create_access_token(user_id, session_id) -> str:
    now = int(time.time())
    header = {"alg": "HS256", "typ": "JWT"}
    payload = {
        "sub": str(user_id),
        "sid": str(session_id),
        "iat": now,
        "exp": now + ACCESS_TOKEN_SECONDS,
        "iss": "masih-gram"
    }
    first = b64url(json.dumps(header, separators=(",", ":")).encode())
    second = b64url(json.dumps(payload, separators=(",", ":")).encode())
    signing_input = f"{first}.{second}".encode()
    signature = hmac.new(auth_secret(), signing_input, hashlib.sha256).digest()
    return f"{first}.{second}.{b64url(signature)}"


def decode_access_token(token: str):
    try:
        parts = token.split(".")
        if len(parts) != 3:
            raise ValueError("bad token")
        first, second, signature = parts

        header = json.loads(
            base64.urlsafe_b64decode(first + "=" * (-len(first) % 4))
        )
        if header.get("alg") != "HS256" or header.get("typ") != "JWT":
            raise ValueError("bad algorithm")

        signing_input = f"{first}.{second}".encode()
        expected = hmac.new(auth_secret(), signing_input, hashlib.sha256).digest()
        supplied = base64.urlsafe_b64decode(
            signature + "=" * (-len(signature) % 4)
        )
        if not hmac.compare_digest(expected, supplied):
            raise ValueError("bad signature")

        payload = json.loads(
            base64.urlsafe_b64decode(second + "=" * (-len(second) % 4))
        )
        if payload.get("iss") != "masih-gram":
            raise ValueError("bad issuer")
        if int(payload.get("exp", 0)) <= int(time.time()):
            raise ValueError("expired")
        uuid.UUID(payload["sub"])
        uuid.UUID(payload["sid"])
        return payload
    except HTTPException:
        raise
    except Exception:
        raise HTTPException(
            status_code=401,
            detail="Invalid or expired access token"
        )


def get_authenticated_user(authorization: Optional[str] = None):
    if not authorization or not authorization.startswith("Bearer "):
        raise HTTPException(status_code=401, detail="Bearer token required")

    payload = decode_access_token(authorization[7:].strip())

    with get_connection() as connection:
        with connection.cursor() as cursor:
            cursor.execute("""
                SELECT u.id, u.username, u.display_name, u.phone,
                       u.account_status, s.id
                FROM public.mg_users u
                JOIN public.mg_user_sessions s ON s.user_id = u.id
                WHERE u.id = %s
                  AND s.id = %s
                  AND s.revoked_at IS NULL
                  AND s.expires_at > NOW()
                  AND u.account_status = 'active'
                  AND u.deleted_at IS NULL
            """, (payload["sub"], payload["sid"]))
            row = cursor.fetchone()

    if not row:
        raise HTTPException(status_code=401, detail="Session is invalid or revoked")

    return {
        "id": str(row[0]),
        "username": row[1],
        "display_name": row[2],
        "phone": row[3],
        "account_status": row[4],
        "session_id": str(row[5])
    }


# ---------------------------------------------------------
# SCHEMA CHECKS AND MIGRATIONS
# ---------------------------------------------------------

def require_auth_schema(cursor):
    cursor.execute("""
        SELECT
            to_regclass('public.mg_auth_otp_challenges'),
            to_regclass('public.mg_user_sessions'),
            to_regclass('public.mg_user_devices')
    """)
    row = cursor.fetchone()
    if not row or not all(row):
        raise HTTPException(
            status_code=503,
            detail="Authentication database migration 002 is not installed"
        )


@app.post("/api/v1/admin/migrations/auth/apply")
def apply_auth_migration(x_admin_key: Optional[str] = Header(default=None)):
    verify_admin_key(x_admin_key)

    migration_file = Path(__file__).resolve().parent / "002_auth_engine.sql"
    if not migration_file.is_file():
        raise HTTPException(
            status_code=503,
            detail="Authentication migration file not found in deployed service"
        )

    sql = migration_file.read_text(encoding="utf-8").strip()
    if not sql:
        raise HTTPException(status_code=500, detail="Migration file is empty")

    if not re.match(r"(?is)^BEGIN\s*;", sql) or not re.search(r"(?is)COMMIT\s*;\s*$", sql):
        raise HTTPException(
            status_code=500,
            detail="Migration transaction boundaries are invalid"
        )

    sql = re.sub(r"(?is)^BEGIN\s*;", "", sql, count=1)
    sql = re.sub(r"(?is)COMMIT\s*;\s*$", "", sql, count=1)

    with get_connection() as connection:
        with connection.cursor() as cursor:
            cursor.execute(
                "SELECT pg_advisory_xact_lock(hashtext(%s))",
                ("masih_gram_002_auth_engine",)
            )

            cursor.execute("""
                SELECT version
                FROM public.mg_schema_migrations
                WHERE version = %s
            """, (AUTH_MIGRATION_VERSION,))

            if cursor.fetchone():
                require_auth_schema(cursor)
                return {
                    "success": True,
                    "status": "already_applied",
                    "migration": AUTH_MIGRATION_VERSION
                }

            # The migration file contains only trusted, version-controlled SQL.
            cursor.execute(sql, prepare=False)

    return {
        "success": True,
        "status": "applied",
        "migration": AUTH_MIGRATION_VERSION
    }


# ---------------------------------------------------------
# TEXTBEE SMS
# ---------------------------------------------------------

def send_textbee_sms(phone: str, message: str) -> str:
    api_key = os.getenv("TEXTBEE_API_KEY")
    if not api_key:
        raise HTTPException(status_code=503, detail="SMS provider is not configured")

    try:
        response = httpx.post(
            TEXTBEE_URL,
            headers={
                "x-api-key": api_key,
                "Content-Type": "application/json"
            },
            json={"recipients": [phone], "message": message},
            timeout=20
        )
        if response.status_code < 200 or response.status_code >= 300:
            raise HTTPException(status_code=502, detail="SMS provider rejected the request")

        result = response.json()
        data = result.get("data") or {}
        batch_id = data.get("smsBatchId")
        if not batch_id:
            raise HTTPException(
                status_code=502,
                detail="SMS provider did not confirm the batch"
            )
        return str(batch_id)
    except HTTPException:
        raise
    except Exception:
        raise HTTPException(
            status_code=502,
            detail="SMS provider is temporarily unavailable"
        )


# ---------------------------------------------------------
# OTP REQUEST
# ---------------------------------------------------------

@app.post("/api/v1/auth/otp/request")
def request_otp(data: OTPRequest, request: Request):
    phone = normalize_phone(data.phone)
    ip = get_client_ip(request)

    # Return a generic response for unknown/existing accounts to reduce
    # phone-number enumeration. A challenge is created only when eligible.
    eligible = False
    code = f"{secrets.randbelow(1000000):06d}"
    code_hash = hash_otp(phone, data.purpose, code)

    with get_connection() as connection:
        with connection.cursor() as cursor:
            # Serialize requests for the same phone/purpose so simultaneous
            # requests cannot bypass resend/hourly limits.
            cursor.execute(
                "SELECT pg_advisory_xact_lock(hashtext(%s), hashtext(%s))",
                (phone, data.purpose)
            )

            cursor.execute("""
                SELECT id, account_status
                FROM public.mg_users
                WHERE phone = %s AND deleted_at IS NULL
            """, (phone,))
            existing_user = cursor.fetchone()

            if data.purpose == "signup":
                eligible = existing_user is None
            else:
                eligible = bool(existing_user and existing_user[1] == "active")

            if eligible:
                cursor.execute("""
                    SELECT created_at
                    FROM public.mg_auth_otp_challenges
                    WHERE phone = %s
                      AND purpose = %s
                      AND created_at > NOW() - INTERVAL '60 seconds'
                    ORDER BY created_at DESC
                    LIMIT 1
                """, (phone, data.purpose))
                if cursor.fetchone():
                    raise HTTPException(
                        status_code=429,
                        detail="Please wait before requesting another code"
                    )

                cursor.execute("""
                    SELECT COUNT(*)
                    FROM public.mg_auth_otp_challenges
                    WHERE phone = %s
                      AND created_at > NOW() - INTERVAL '1 hour'
                """, (phone,))
                if cursor.fetchone()[0] >= OTP_HOURLY_LIMIT:
                    raise HTTPException(
                        status_code=429,
                        detail="Hourly verification limit reached"
                    )

                if ip:
                    cursor.execute(
                        "SELECT pg_advisory_xact_lock(hashtext(%s))",
                        ("otp-ip:" + ip,)
                    )
                    cursor.execute("""
                        SELECT COUNT(*)
                        FROM public.mg_auth_otp_challenges
                        WHERE request_ip = %s::inet
                          AND created_at > NOW() - INTERVAL '1 hour'
                    """, (ip,))
                    if cursor.fetchone()[0] >= IP_HOURLY_LIMIT:
                        raise HTTPException(
                            status_code=429,
                            detail="Too many requests from this network"
                        )

                # Reserve the OTP before contacting the provider. If provider
                # delivery fails, the challenge is immediately consumed below.
                cursor.execute("""
                    UPDATE public.mg_auth_otp_challenges
                    SET consumed_at = NOW()
                    WHERE phone = %s
                      AND purpose = %s
                      AND consumed_at IS NULL
                """, (phone, data.purpose))

                cursor.execute("""
                    INSERT INTO public.mg_auth_otp_challenges (
                        phone, purpose, code_hash, attempts, max_attempts,
                        expires_at, request_ip, provider
                    )
                    VALUES (
                        %s, %s, %s, 0, %s,
                        NOW() + INTERVAL '5 minutes',
                        %s::inet, 'textbee'
                    )
                    RETURNING id
                """, (phone, data.purpose, code_hash, OTP_MAX_ATTEMPTS, ip))
                challenge_id = cursor.fetchone()[0]
            else:
                challenge_id = None

    if not eligible:
        return {
            "success": True,
            "message": "If the number is eligible, a verification message will be sent",
            "expires_in": OTP_LIFETIME_SECONDS,
            "resend_after": OTP_RESEND_SECONDS
        }

    message = (
        "MASIH GRAM | مسیح، شاه مجازی\n"
        f"Your verification code: {code}\n"
        "Valid for 5 minutes. Do not share this code."
    )

    try:
        batch_id = send_textbee_sms(phone, message)
    except HTTPException:
        with get_connection() as connection:
            with connection.cursor() as cursor:
                cursor.execute("""
                    UPDATE public.mg_auth_otp_challenges
                    SET consumed_at = NOW()
                    WHERE id = %s AND consumed_at IS NULL
                """, (challenge_id,))
        raise

    with get_connection() as connection:
        with connection.cursor() as cursor:
            cursor.execute("""
                UPDATE public.mg_auth_otp_challenges
                SET provider_batch_id = %s
                WHERE id = %s
            """, (batch_id, challenge_id))

    return {
        "success": True,
        "message": "Verification SMS accepted by provider",
        "expires_in": OTP_LIFETIME_SECONDS,
        "resend_after": OTP_RESEND_SECONDS
    }


# ---------------------------------------------------------
# OTP VERIFY / SIGNUP / LOGIN
# ---------------------------------------------------------

@app.post("/api/v1/auth/otp/verify")
def verify_otp(data: OTPVerify, request: Request):
    phone = normalize_phone(data.phone)

    if data.purpose == "signup":
        if not data.username or not data.display_name:
            raise HTTPException(
                status_code=422,
                detail="Username and display name are required for signup"
            )
        if not re.fullmatch(r"[a-zA-Z0-9_]{3,32}", data.username):
            raise HTTPException(
                status_code=422,
                detail="Username must contain 3-32 letters, numbers or underscores"
            )

    code_hash = hash_otp(phone, data.purpose, data.code)
    wrong_code = False
    result = None

    with get_connection() as connection:
        with connection.cursor() as cursor:
            cursor.execute(
                "SELECT pg_advisory_xact_lock(hashtext(%s), hashtext(%s))",
                (phone, data.purpose)
            )

            cursor.execute("""
                SELECT id, code_hash, attempts, max_attempts
                FROM public.mg_auth_otp_challenges
                WHERE phone = %s
                  AND purpose = %s
                  AND consumed_at IS NULL
                  AND expires_at > NOW()
                ORDER BY created_at DESC
                LIMIT 1
                FOR UPDATE
            """, (phone, data.purpose))
            challenge = cursor.fetchone()

            if not challenge:
                raise HTTPException(
                    status_code=400,
                    detail="Verification code is invalid or expired"
                )

            challenge_id, stored_hash, attempts, max_attempts = challenge

            if attempts >= max_attempts:
                raise HTTPException(
                    status_code=429,
                    detail="Maximum verification attempts reached"
                )

            if not hmac.compare_digest(stored_hash, code_hash):
                cursor.execute("""
                    UPDATE public.mg_auth_otp_challenges
                    SET attempts = attempts + 1
                    WHERE id = %s
                """, (challenge_id,))
                wrong_code = True
            else:
                cursor.execute("""
                    UPDATE public.mg_auth_otp_challenges
                    SET consumed_at = NOW()
                    WHERE id = %s
                """, (challenge_id,))

                cursor.execute("""
                    SELECT id, username, display_name, account_status
                    FROM public.mg_users
                    WHERE phone = %s AND deleted_at IS NULL
                    FOR UPDATE
                """, (phone,))
                user = cursor.fetchone()

                if data.purpose == "signup":
                    if user:
                        raise HTTPException(
                            status_code=409,
                            detail="An account already exists for this phone"
                        )

                    cursor.execute("""
                        INSERT INTO public.mg_users (
                            username, display_name, phone, password_hash,
                            account_status, is_verified,
                            phone_verified_at, registration_completed_at
                        )
                        VALUES (%s, %s, %s, NULL, 'active', TRUE, NOW(), NOW())
                        RETURNING id, username, display_name, account_status
                    """, (
                        data.username.lower(),
                        data.display_name.strip(),
                        phone
                    ))
                    user = cursor.fetchone()

                    cursor.execute("""
                        INSERT INTO public.mg_user_profiles(user_id)
                        VALUES (%s)
                        ON CONFLICT (user_id) DO NOTHING
                    """, (user[0],))

                    cursor.execute("""
                        INSERT INTO public.mg_user_settings(user_id)
                        VALUES (%s)
                        ON CONFLICT (user_id) DO NOTHING
                    """, (user[0],))
                else:
                    if not user:
                        raise HTTPException(
                            status_code=404,
                            detail="Account not found"
                        )
                    if user[3] != "active":
                        raise HTTPException(
                            status_code=403,
                            detail="Account is not active"
                        )

                user_id = user[0]
                device_id = uuid.uuid4()

                cursor.execute("""
                    INSERT INTO public.mg_user_devices (
                        id, user_id, device_name, device_type, platform,
                        app_version, last_active_at, is_active
                    )
                    VALUES (%s, %s, %s, 'mobile', %s, %s, NOW(), TRUE)
                """, (
                    device_id,
                    user_id,
                    data.device_name or "MASIH GRAM Device",
                    data.platform or "Android",
                    data.app_version
                ))

                refresh_token = secrets.token_urlsafe(48)
                refresh_hash = hash_refresh_token(refresh_token)
                session_id = uuid.uuid4()
                expires_at = utcnow() + timedelta(days=REFRESH_TOKEN_DAYS)

                cursor.execute("""
                    INSERT INTO public.mg_user_sessions (
                        id, user_id, device_id, refresh_token_hash,
                        ip_address, user_agent, expires_at
                    )
                    VALUES (%s, %s, %s, %s, %s::inet, %s, %s)
                """, (
                    session_id,
                    user_id,
                    device_id,
                    refresh_hash,
                    get_client_ip(request),
                    request.headers.get("user-agent"),
                    expires_at
                ))

                cursor.execute("""
                    UPDATE public.mg_users
                    SET last_seen_at = NOW(), updated_at = NOW()
                    WHERE id = %s
                """, (user_id,))

                result = {
                    "user_id": user_id,
                    "username": user[1],
                    "display_name": user[2],
                    "account_status": user[3],
                    "session_id": session_id,
                    "refresh_token": refresh_token
                }

    # Raise only after the transaction commits, so failed attempts persist.
    if wrong_code:
        raise HTTPException(
            status_code=400,
            detail="Verification code is incorrect"
        )

    access_token = create_access_token(
        result["user_id"],
        result["session_id"]
    )

    return {
        "success": True,
        "message": "Authentication successful",
        "user": {
            "id": str(result["user_id"]),
            "username": result["username"],
            "display_name": result["display_name"],
            "phone": phone,
            "account_status": result["account_status"]
        },
        "tokens": {
            "token_type": "Bearer",
            "access_token": access_token,
            "expires_in": ACCESS_TOKEN_SECONDS,
            "refresh_token": result["refresh_token"],
            "refresh_expires_in": REFRESH_TOKEN_DAYS * 86400
        }
    }


# ---------------------------------------------------------
# REFRESH TOKEN ROTATION
# ---------------------------------------------------------

@app.post("/api/v1/auth/token/refresh")
def refresh_access_token(data: RefreshRequest):
    old_hash = hash_refresh_token(data.refresh_token)
    new_refresh_token = secrets.token_urlsafe(48)
    new_hash = hash_refresh_token(new_refresh_token)

    with get_connection() as connection:
        with connection.cursor() as cursor:
            cursor.execute("""
                SELECT s.id, s.user_id
                FROM public.mg_user_sessions s
                JOIN public.mg_users u ON u.id = s.user_id
                WHERE s.refresh_token_hash = %s
                  AND s.revoked_at IS NULL
                  AND s.expires_at > NOW()
                  AND u.account_status = 'active'
                  AND u.deleted_at IS NULL
                FOR UPDATE OF s
            """, (old_hash,))
            row = cursor.fetchone()

            if not row:
                raise HTTPException(
                    status_code=401,
                    detail="Refresh token is invalid or expired"
                )

            session_id, user_id = row
            cursor.execute("""
                UPDATE public.mg_user_sessions
                SET refresh_token_hash = %s,
                    expires_at = NOW() + INTERVAL '30 days'
                WHERE id = %s
            """, (new_hash, session_id))

    return {
        "success": True,
        "tokens": {
            "token_type": "Bearer",
            "access_token": create_access_token(user_id, session_id),
            "expires_in": ACCESS_TOKEN_SECONDS,
            "refresh_token": new_refresh_token,
            "refresh_expires_in": REFRESH_TOKEN_DAYS * 86400
        }
    }


# ---------------------------------------------------------
# LOGOUT
# ---------------------------------------------------------

@app.post("/api/v1/auth/logout")
def logout(authorization: Optional[str] = Header(default=None)):
    if not authorization or not authorization.startswith("Bearer "):
        raise HTTPException(status_code=401, detail="Bearer token required")

    payload = decode_access_token(authorization[7:].strip())

    with get_connection() as connection:
        with connection.cursor() as cursor:
            cursor.execute("""
                UPDATE public.mg_user_sessions
                SET revoked_at = NOW()
                WHERE id = %s AND user_id = %s AND revoked_at IS NULL
            """, (payload["sid"], payload["sub"]))
            changed = cursor.rowcount

    return {
        "success": True,
        "message": "Session revoked" if changed else "Session was already revoked"
    }


# ---------------------------------------------------------
# CURRENT USER
# ---------------------------------------------------------

@app.get("/api/v1/auth/me")
def current_user(authorization: Optional[str] = Header(default=None)):
    user = get_authenticated_user(authorization)

    with get_connection() as connection:
        with connection.cursor() as cursor:
            cursor.execute("""
                SELECT bio, avatar_url, cover_url, language,
                       timezone, profile_visibility
                FROM public.mg_user_profiles
                WHERE user_id = %s
            """, (user["id"],))
            profile = cursor.fetchone()

    return {
        "success": True,
        "user": user,
        "profile": {
            "bio": profile[0] if profile else None,
            "avatar_url": profile[1] if profile else None,
            "cover_url": profile[2] if profile else None,
            "language": profile[3] if profile else "fa",
            "timezone": profile[4] if profile else None,
            "visibility": profile[5] if profile else "public"
        }
    }


# ---------------------------------------------------------
# SESSION MANAGEMENT
# ---------------------------------------------------------

@app.get("/api/v1/auth/sessions")
def list_sessions(authorization: Optional[str] = Header(default=None)):
    user = get_authenticated_user(authorization)

    with get_connection() as connection:
        with connection.cursor() as cursor:
            cursor.execute("""
                SELECT s.id, s.device_id, s.created_at, s.expires_at,
                       s.ip_address::text, s.user_agent,
                       d.device_name, d.platform, d.app_version
                FROM public.mg_user_sessions s
                LEFT JOIN public.mg_user_devices d ON d.id = s.device_id
                WHERE s.user_id = %s
                  AND s.revoked_at IS NULL
                  AND s.expires_at > NOW()
                ORDER BY s.created_at DESC
            """, (user["id"],))
            rows = cursor.fetchall()

    return {
        "success": True,
        "total": len(rows),
        "sessions": [
            {
                "id": str(r[0]),
                "device_id": str(r[1]) if r[1] else None,
                "created_at": r[2].isoformat(),
                "expires_at": r[3].isoformat(),
                "ip_address": r[4],
                "user_agent": r[5],
                "device_name": r[6],
                "platform": r[7],
                "app_version": r[8],
                "current": str(r[0]) == user["session_id"]
            }
            for r in rows
        ]
    }


@app.delete("/api/v1/auth/sessions/{session_id}")
def revoke_session(
    session_id: uuid.UUID,
    authorization: Optional[str] = Header(default=None)
):
    user = get_authenticated_user(authorization)

    with get_connection() as connection:
        with connection.cursor() as cursor:
            cursor.execute("""
                UPDATE public.mg_user_sessions
                SET revoked_at = NOW()
                WHERE id = %s
                  AND user_id = %s
                  AND revoked_at IS NULL
            """, (session_id, user["id"]))
            changed = cursor.rowcount

    if not changed:
        raise HTTPException(
            status_code=404,
            detail="Session not found or already revoked"
        )

    return {"success": True, "message": "Session revoked"}


# ---------------------------------------------------------
# SYSTEM
# ---------------------------------------------------------

@app.get("/")
def root():
    return {
        "name": "MASIH GRAM GLOBAL",
        "brand": "مسیح، شاه مجازی",
        "edition": "GLOBAL ULTIMATE",
        "status": "online",
        "version": APP_VERSION,
        "server_time": utcnow().isoformat()
    }


@app.get("/api/v1/system/health")
def health():
    return {
        "status": "healthy",
        "service": "masih-gram-backend",
        "version": APP_VERSION,
        "timestamp": utcnow().isoformat()
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
def database_tables(x_admin_key: Optional[str] = Header(default=None)):
    verify_admin_key(x_admin_key)

    with get_connection() as connection:
        with connection.cursor() as cursor:
            cursor.execute("""
                SELECT table_schema, table_name
                FROM information_schema.tables
                WHERE table_schema NOT IN ('pg_catalog', 'information_schema')
                  AND table_type = 'BASE TABLE'
                ORDER BY table_schema, table_name
            """)
            rows = cursor.fetchall()

    tables = [{"schema": row[0], "name": row[1]} for row in rows]
    return {
        "status": "success",
        "database": "PostgreSQL",
        "total_tables": len(tables),
        "tables": tables
    }


@app.get("/api/v1/system/info")
def system_info():
    return {
        "application": "MASIH GRAM",
        "brand": "مسیح، شاه مجازی",
        "edition": "GLOBAL ULTIMATE",
        "api_version": "v1",
        "backend_version": APP_VERSION,
        "modules": {
            "authentication": "implemented_pending_migration_check",
            "otp": "implemented_pending_provider_test",
            "sessions": "implemented",
            "devices": "implemented",
            "messaging": "database_foundation_only",
            "groups": "database_foundation_only",
            "channels": "database_foundation_only",
            "media": "database_foundation_only",
            "social": "not_implemented",
            "ai": "not_implemented",
            "cloud": "not_implemented",
            "live": "not_implemented"
        }
    }


# ---------------------------------------------------------
# ERROR HANDLING
# ---------------------------------------------------------

@app.exception_handler(404)
async def not_found_handler(request, exc):
    return JSONResponse(
        status_code=404,
        content={
            "success": False,
            "error": "Endpoint not found"
        }
    )
    # =========================================================
# MASIH GRAM GLOBAL — GOD EDITION
# MODULE 01: GLOBAL SOCIAL DATABASE AND MODELS
# =========================================================

from pydantic import ConfigDict
from typing import List, Dict, Any


GLOBAL_MODULE_VERSION = "3.0.0"
GLOBAL_SCHEMA_VERSION = "003_global_social"


# ---------------------------------------------------------
# REQUEST MODELS
# ---------------------------------------------------------

class GlobalPostCreate(BaseModel):
    content: str = Field(min_length=1, max_length=10000)
    visibility: str = Field(default="public")
    media_url: Optional[str] = Field(default=None, max_length=2000)

    model_config = ConfigDict(extra="forbid")


class GlobalCommentCreate(BaseModel):
    content: str = Field(min_length=1, max_length=3000)

    model_config = ConfigDict(extra="forbid")


class GlobalProfileUpdate(BaseModel):
    display_name: Optional[str] = Field(default=None, max_length=100)
    bio: Optional[str] = Field(default=None, max_length=1000)
    avatar_url: Optional[str] = Field(default=None, max_length=2000)
    cover_url: Optional[str] = Field(default=None, max_length=2000)

    model_config = ConfigDict(extra="forbid")


class GlobalFeatureRequest(BaseModel):
    feature_code: str = Field(min_length=2, max_length=80)
    message: Optional[str] = Field(default=None, max_length=2000)

    model_config = ConfigDict(extra="forbid")


class GlobalFeatureReview(BaseModel):
    status: str = Field(pattern="^(approved|rejected)$")
    admin_note: Optional[str] = Field(default=None, max_length=2000)
    activate: bool = True

    model_config = ConfigDict(extra="forbid")


class GlobalFeatureCreate(BaseModel):
    code: str = Field(min_length=2, max_length=80)
    name: str = Field(min_length=2, max_length=120)
    description: str = Field(default="", max_length=2000)
    category: str = Field(default="general", max_length=80)
    enabled: bool = True
    requires_review: bool = True

    model_config = ConfigDict(extra="forbid")


class GlobalFollowRequest(BaseModel):
    user_id: uuid.UUID


class GlobalReportCreate(BaseModel):
    target_type: str = Field(pattern="^(post|comment|user)$")
    target_id: uuid.UUID
    reason: str = Field(min_length=3, max_length=1000)


class GlobalNotificationRead(BaseModel):
    notification_ids: List[uuid.UUID] = Field(max_length=100)


# ---------------------------------------------------------
# GLOBAL DATABASE SCHEMA
# ---------------------------------------------------------

GLOBAL_SCHEMA_STATEMENTS = [

"""
CREATE TABLE IF NOT EXISTS public.mg_social_posts (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id UUID NOT NULL REFERENCES public.mg_users(id),
    content TEXT NOT NULL,
    media_url TEXT,
    visibility VARCHAR(20) NOT NULL DEFAULT 'public',
    likes_count INTEGER NOT NULL DEFAULT 0,
    comments_count INTEGER NOT NULL DEFAULT 0,
    views_count BIGINT NOT NULL DEFAULT 0,
    is_pinned BOOLEAN NOT NULL DEFAULT FALSE,
    is_deleted BOOLEAN NOT NULL DEFAULT FALSE,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    CONSTRAINT mg_social_posts_visibility_check
        CHECK (visibility IN ('public','followers','private'))
)
""",

"""
CREATE INDEX IF NOT EXISTS idx_mg_social_posts_created
ON public.mg_social_posts(created_at DESC)
WHERE is_deleted = FALSE
""",

"""
CREATE INDEX IF NOT EXISTS idx_mg_social_posts_user
ON public.mg_social_posts(user_id, created_at DESC)
WHERE is_deleted = FALSE
""",

"""
CREATE TABLE IF NOT EXISTS public.mg_social_comments (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    post_id UUID NOT NULL REFERENCES public.mg_social_posts(id),
    user_id UUID NOT NULL REFERENCES public.mg_users(id),
    parent_id UUID REFERENCES public.mg_social_comments(id),
    content TEXT NOT NULL,
    is_deleted BOOLEAN NOT NULL DEFAULT FALSE,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
)
""",

"""
CREATE INDEX IF NOT EXISTS idx_mg_social_comments_post
ON public.mg_social_comments(post_id, created_at)
""",

"""
CREATE TABLE IF NOT EXISTS public.mg_social_likes (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    post_id UUID NOT NULL REFERENCES public.mg_social_posts(id),
    user_id UUID NOT NULL REFERENCES public.mg_users(id),
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    UNIQUE(post_id, user_id)
)
""",

"""
CREATE TABLE IF NOT EXISTS public.mg_social_follows (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    follower_id UUID NOT NULL REFERENCES public.mg_users(id),
    following_id UUID NOT NULL REFERENCES public.mg_users(id),
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    UNIQUE(follower_id, following_id),
    CHECK(follower_id <> following_id)
)
""",

"""
CREATE INDEX IF NOT EXISTS idx_mg_social_follows_following
ON public.mg_social_follows(following_id)
""",

"""
CREATE TABLE IF NOT EXISTS public.mg_feature_catalog (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    code VARCHAR(80) NOT NULL UNIQUE,
    name VARCHAR(120) NOT NULL,
    description TEXT NOT NULL DEFAULT '',
    category VARCHAR(80) NOT NULL DEFAULT 'general',
    enabled BOOLEAN NOT NULL DEFAULT TRUE,
    requires_review BOOLEAN NOT NULL DEFAULT TRUE,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
)
""",

"""
CREATE TABLE IF NOT EXISTS public.mg_feature_requests (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id UUID NOT NULL REFERENCES public.mg_users(id),
    feature_id UUID NOT NULL REFERENCES public.mg_feature_catalog(id),
    message TEXT,
    status VARCHAR(20) NOT NULL DEFAULT 'pending',
    admin_note TEXT,
    reviewed_by UUID REFERENCES public.mg_users(id),
    reviewed_at TIMESTAMPTZ,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    CHECK(status IN ('pending','approved','rejected'))
)
""",

"""
CREATE INDEX IF NOT EXISTS idx_mg_feature_requests_status
ON public.mg_feature_requests(status, created_at DESC)
""",

"""
CREATE TABLE IF NOT EXISTS public.mg_user_feature_entitlements (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id UUID NOT NULL REFERENCES public.mg_users(id),
    feature_id UUID NOT NULL REFERENCES public.mg_feature_catalog(id),
    granted_by UUID REFERENCES public.mg_users(id),
    granted_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    expires_at TIMESTAMPTZ,
    is_active BOOLEAN NOT NULL DEFAULT TRUE,
    UNIQUE(user_id, feature_id)
)
""",

"""
CREATE TABLE IF NOT EXISTS public.mg_creator_badges (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id UUID NOT NULL UNIQUE REFERENCES public.mg_users(id),
    badge_name VARCHAR(120) NOT NULL DEFAULT 'سازنده MASIH GRAM',
    granted_by UUID REFERENCES public.mg_users(id),
    granted_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    revoked_at TIMESTAMPTZ
)
""",

"""
CREATE TABLE IF NOT EXISTS public.mg_social_reports (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    reporter_id UUID NOT NULL REFERENCES public.mg_users(id),
    target_type VARCHAR(20) NOT NULL,
    target_id UUID NOT NULL,
    reason TEXT NOT NULL,
    status VARCHAR(20) NOT NULL DEFAULT 'pending',
    reviewed_by UUID REFERENCES public.mg_users(id),
    admin_note TEXT,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    reviewed_at TIMESTAMPTZ,
    CHECK(target_type IN ('post','comment','user')),
    CHECK(status IN ('pending','reviewed','dismissed'))
)
""",

"""
CREATE TABLE IF NOT EXISTS public.mg_global_notifications (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id UUID NOT NULL REFERENCES public.mg_users(id),
    actor_id UUID REFERENCES public.mg_users(id),
    notification_type VARCHAR(60) NOT NULL,
    title VARCHAR(200) NOT NULL,
    body TEXT NOT NULL DEFAULT '',
    reference_type VARCHAR(40),
    reference_id UUID,
    is_read BOOLEAN NOT NULL DEFAULT FALSE,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
)
""",

"""
CREATE INDEX IF NOT EXISTS idx_mg_global_notifications_user
ON public.mg_global_notifications(user_id, created_at DESC)
""",

"""
CREATE TABLE IF NOT EXISTS public.mg_global_audit (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    actor_id UUID REFERENCES public.mg_users(id),
    action VARCHAR(120) NOT NULL,
    target_type VARCHAR(80),
    target_id UUID,
    details JSONB NOT NULL DEFAULT '{}'::jsonb,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
)
""",

"""
CREATE INDEX IF NOT EXISTS idx_mg_global_audit_created
ON public.mg_global_audit(created_at DESC)
""",

"""
INSERT INTO public.mg_feature_catalog
(code, name, description, category, enabled, requires_review)
VALUES
('social_feed','شبکه اجتماعی','انتشار و مشاهده پست‌ها','social',TRUE,FALSE),
('post_likes','لایک پست‌ها','ثبت و حذف پسندیدن پست','social',TRUE,FALSE),
('post_comments','دیدگاه‌ها','ثبت و مدیریت دیدگاه‌ها','social',TRUE,FALSE),
('user_follow','دنبال‌کردن','دنبال‌کردن و لغو دنبال‌کردن کاربران','social',TRUE,FALSE),
('creator_badge','نشان سازنده','نشان رسمی سازنده برنامه','identity',TRUE,TRUE),
('advanced_profile','پروفایل پیشرفته','امکانات تکمیلی پروفایل','profile',TRUE,TRUE),
('custom_themes','پوسته‌های اختصاصی','فعال‌سازی پوسته‌های حساب','appearance',TRUE,TRUE),
('advanced_privacy','حریم خصوصی پیشرفته','تنظیمات تکمیلی حریم خصوصی','security',TRUE,TRUE),
('priority_support','پشتیبانی ویژه','دسترسی به مسیر پشتیبانی ویژه','support',TRUE,TRUE)
ON CONFLICT(code) DO NOTHING
"""
]


# ---------------------------------------------------------
# GLOBAL SCHEMA INITIALIZATION
# ---------------------------------------------------------

def require_global_schema(cursor):
    cursor.execute("""
        SELECT
            to_regclass('public.mg_social_posts'),
            to_regclass('public.mg_social_comments'),
            to_regclass('public.mg_social_likes'),
            to_regclass('public.mg_feature_catalog'),
            to_regclass('public.mg_feature_requests'),
            to_regclass('public.mg_user_feature_entitlements'),
            to_regclass('public.mg_creator_badges'),
            to_regclass('public.mg_global_notifications')
    """)
    row = cursor.fetchone()

    if not row or not all(row):
        raise HTTPException(
            status_code=503,
            detail="GLOBAL database migration is not installed"
        )


def global_user(authorization):
    return get_authenticated_user(authorization)


def global_audit(cursor, actor_id, action,
                 target_type=None, target_id=None, details=None):
    cursor.execute("""
        INSERT INTO public.mg_global_audit (
            actor_id, action, target_type, target_id, details
        )
        VALUES (%s, %s, %s, %s, %s::jsonb)
    """, (
        actor_id,
        action,
        target_type,
        target_id,
        json.dumps(details or {}, ensure_ascii=False)
    ))


def create_global_notification(
    cursor,
    user_id,
    notification_type,
    title,
    body="",
    actor_id=None,
    reference_type=None,
    reference_id=None
):
    cursor.execute("""
        INSERT INTO public.mg_global_notifications (
            user_id, actor_id, notification_type, title, body,
            reference_type, reference_id
        )
        VALUES (%s,%s,%s,%s,%s,%s,%s)
    """, (
        user_id,
        actor_id,
        notification_type,
        title,
        body,
        reference_type,
        reference_id
    ))


# =========================================================
# END MODULE 01
# NEXT: GLOBAL MIGRATION + SOCIAL API
# =========================================================

# =========================================================
# MODULE 02: GLOBAL MIGRATION + SOCIAL ENGINE
# =========================================================

@app.post("/api/v1/admin/migrations/global/apply")
def apply_global_migration(
    x_admin_key: Optional[str] = Header(default=None)
):
    verify_admin_key(x_admin_key)

    with get_connection() as connection:
        with connection.cursor() as cursor:
            cursor.execute(
                "SELECT pg_advisory_xact_lock(hashtext(%s))",
                ("masih_gram_003_global",)
            )

            for statement in GLOBAL_SCHEMA_STATEMENTS:
                cursor.execute(statement, prepare=False)

            cursor.execute("""
                INSERT INTO public.mg_schema_migrations(version)
                VALUES (%s)
                ON CONFLICT(version) DO NOTHING
            """, (GLOBAL_SCHEMA_VERSION,))

            require_global_schema(cursor)

    return {
        "success": True,
        "migration": GLOBAL_SCHEMA_VERSION,
        "status": "applied"
    }


# ---------------------------------------------------------
# SOCIAL SERIALIZATION
# ---------------------------------------------------------

def social_post_dict(row, liked=False):
    return {
        "id": str(row[0]),
        "user": {
            "id": str(row[1]),
            "username": row[2],
            "display_name": row[3]
        },
        "content": row[4],
        "media_url": row[5],
        "visibility": row[6],
        "likes_count": row[7],
        "comments_count": row[8],
        "views_count": row[9],
        "created_at": row[10].isoformat(),
        "liked_by_me": liked
    }


SOCIAL_POST_SELECT = """
    SELECT
        p.id,
        u.id,
        u.username,
        u.display_name,
        p.content,
        p.media_url,
        p.visibility,
        p.likes_count,
        p.comments_count,
        p.views_count,
        p.created_at
    FROM public.mg_social_posts p
    JOIN public.mg_users u ON u.id = p.user_id
"""


# ---------------------------------------------------------
# CREATE POST
# ---------------------------------------------------------

@app.post("/api/v1/social/posts")
def create_social_post(
    data: GlobalPostCreate,
    authorization: Optional[str] = Header(default=None)
):
    user = global_user(authorization)

    if data.visibility not in ("public", "followers", "private"):
        raise HTTPException(status_code=422, detail="Invalid visibility")

    if data.media_url and not data.media_url.startswith(("https://", "http://")):
        raise HTTPException(status_code=422, detail="Invalid media URL")

    with get_connection() as connection:
        with connection.cursor() as cursor:
            require_global_schema(cursor)

            cursor.execute("""
                INSERT INTO public.mg_social_posts (
                    user_id, content, media_url, visibility
                )
                VALUES (%s,%s,%s,%s)
                RETURNING id
            """, (
                user["id"],
                data.content.strip(),
                data.media_url,
                data.visibility
            ))

            post_id = cursor.fetchone()[0]

            global_audit(
                cursor,
                user["id"],
                "social.post.create",
                "post",
                post_id
            )

    return {
        "success": True,
        "post_id": str(post_id)
    }


# ---------------------------------------------------------
# SOCIAL FEED
# ---------------------------------------------------------

@app.get("/api/v1/social/posts")
def social_feed(
    limit: int = 20,
    offset: int = 0,
    authorization: Optional[str] = Header(default=None)
):
    user = global_user(authorization)

    limit = max(1, min(limit, 50))
    offset = max(0, offset)

    with get_connection() as connection:
        with connection.cursor() as cursor:
            require_global_schema(cursor)

            cursor.execute(
                SOCIAL_POST_SELECT + """
                WHERE p.is_deleted = FALSE
                  AND (
                    p.visibility = 'public'
                    OR p.user_id = %s
                    OR (
                        p.visibility = 'followers'
                        AND EXISTS (
                            SELECT 1
                            FROM public.mg_social_follows f
                            WHERE f.follower_id = %s
                              AND f.following_id = p.user_id
                        )
                    )
                  )
                ORDER BY p.created_at DESC
                LIMIT %s OFFSET %s
                """,
                (user["id"], user["id"], limit, offset)
            )

            rows = cursor.fetchall()

            posts = []
            for row in rows:
                cursor.execute("""
                    SELECT EXISTS(
                        SELECT 1
                        FROM public.mg_social_likes
                        WHERE post_id = %s AND user_id = %s
                    )
                """, (row[0], user["id"]))

                liked = cursor.fetchone()[0]
                posts.append(social_post_dict(row, liked))

    return {
        "success": True,
        "limit": limit,
        "offset": offset,
        "count": len(posts),
        "posts": posts
    }


# ---------------------------------------------------------
# GET SINGLE POST
# ---------------------------------------------------------

@app.get("/api/v1/social/posts/{post_id}")
def get_social_post(
    post_id: uuid.UUID,
    authorization: Optional[str] = Header(default=None)
):
    user = global_user(authorization)

    with get_connection() as connection:
        with connection.cursor() as cursor:
            require_global_schema(cursor)

            cursor.execute(
                SOCIAL_POST_SELECT + """
                WHERE p.id = %s AND p.is_deleted = FALSE
                """,
                (post_id,)
            )
            row = cursor.fetchone()

            if not row:
                raise HTTPException(status_code=404, detail="Post not found")

            if row[6] == "private" and row[1] != uuid.UUID(user["id"]):
                raise HTTPException(status_code=403, detail="Private post")

            if row[6] == "followers" and row[1] != uuid.UUID(user["id"]):
                cursor.execute("""
                    SELECT EXISTS(
                        SELECT 1 FROM public.mg_social_follows
                        WHERE follower_id = %s AND following_id = %s
                    )
                """, (user["id"], row[1]))

                if not cursor.fetchone()[0]:
                    raise HTTPException(status_code=403, detail="Followers only")

            cursor.execute("""
                UPDATE public.mg_social_posts
                SET views_count = views_count + 1
                WHERE id = %s
            """, (post_id,))

            cursor.execute("""
                SELECT EXISTS(
                    SELECT 1 FROM public.mg_social_likes
                    WHERE post_id = %s AND user_id = %s
                )
            """, (post_id, user["id"]))

            liked = cursor.fetchone()[0]

    return {
        "success": True,
        "post": social_post_dict(row, liked)
    }


# ---------------------------------------------------------
# DELETE OWN POST
# ---------------------------------------------------------

@app.delete("/api/v1/social/posts/{post_id}")
def delete_social_post(
    post_id: uuid.UUID,
    authorization: Optional[str] = Header(default=None)
):
    user = global_user(authorization)

    with get_connection() as connection:
        with connection.cursor() as cursor:
            require_global_schema(cursor)

            cursor.execute("""
                UPDATE public.mg_social_posts
                SET is_deleted = TRUE,
                    updated_at = NOW()
                WHERE id = %s
                  AND user_id = %s
                  AND is_deleted = FALSE
            """, (post_id, user["id"]))

            if cursor.rowcount == 0:
                raise HTTPException(
                    status_code=404,
                    detail="Post not found or access denied"
                )

            global_audit(
                cursor,
                user["id"],
                "social.post.delete",
                "post",
                post_id
            )

    return {"success": True, "message": "Post deleted"}


# ---------------------------------------------------------
# LIKE POST
# ---------------------------------------------------------

@app.post("/api/v1/social/posts/{post_id}/like")
def like_social_post(
    post_id: uuid.UUID,
    authorization: Optional[str] = Header(default=None)
):
    user = global_user(authorization)

    with get_connection() as connection:
        with connection.cursor() as cursor:
            require_global_schema(cursor)

            cursor.execute("""
                INSERT INTO public.mg_social_likes(post_id, user_id)
                SELECT id, %s
                FROM public.mg_social_posts
                WHERE id = %s AND is_deleted = FALSE
                ON CONFLICT(post_id, user_id) DO NOTHING
                RETURNING id
            """, (user["id"], post_id))

            inserted = cursor.fetchone()

            if inserted:
                cursor.execute("""
                    UPDATE public.mg_social_posts
                    SET likes_count = likes_count + 1
                    WHERE id = %s
                """, (post_id,))

    return {
        "success": True,
        "liked": True,
        "already_liked": inserted is None
    }


# ---------------------------------------------------------
# UNLIKE POST
# ---------------------------------------------------------

@app.delete("/api/v1/social/posts/{post_id}/like")
def unlike_social_post(
    post_id: uuid.UUID,
    authorization: Optional[str] = Header(default=None)
):
    user = global_user(authorization)

    with get_connection() as connection:
        with connection.cursor() as cursor:
            require_global_schema(cursor)

            cursor.execute("""
                DELETE FROM public.mg_social_likes
                WHERE post_id = %s AND user_id = %s
                RETURNING id
            """, (post_id, user["id"]))

            removed = cursor.fetchone()

            if removed:
                cursor.execute("""
                    UPDATE public.mg_social_posts
                    SET likes_count = GREATEST(0, likes_count - 1)
                    WHERE id = %s
                """, (post_id,))

    return {
        "success": True,
        "liked": False,
        "removed": removed is not None
    }


# ---------------------------------------------------------
# CREATE COMMENT
# ---------------------------------------------------------

@app.post("/api/v1/social/posts/{post_id}/comments")
def create_social_comment(
    post_id: uuid.UUID,
    data: GlobalCommentCreate,
    authorization: Optional[str] = Header(default=None)
):
    user = global_user(authorization)

    with get_connection() as connection:
        with connection.cursor() as cursor:
            require_global_schema(cursor)

            cursor.execute("""
                SELECT user_id, visibility
                FROM public.mg_social_posts
                WHERE id = %s AND is_deleted = FALSE
                FOR UPDATE
            """, (post_id,))

            post = cursor.fetchone()

            if not post:
                raise HTTPException(status_code=404, detail="Post not found")

            if post[1] == "private" and str(post[0]) != user["id"]:
                raise HTTPException(status_code=403, detail="Private post")

            cursor.execute("""
                INSERT INTO public.mg_social_comments (
                    post_id, user_id, content
                )
                VALUES (%s,%s,%s)
                RETURNING id, created_at
            """, (post_id, user["id"], data.content.strip()))

            comment = cursor.fetchone()

            cursor.execute("""
                UPDATE public.mg_social_posts
                SET comments_count = comments_count + 1
                WHERE id = %s
            """, (post_id,))

            if str(post[0]) != user["id"]:
                create_global_notification(
                    cursor,
                    post[0],
                    "post_comment",
                    "دیدگاه جدید",
                    "برای پست شما دیدگاه ثبت شد",
                    user["id"],
                    "post",
                    post_id
                )

    return {
        "success": True,
        "comment": {
            "id": str(comment[0]),
            "created_at": comment[1].isoformat()
        }
    }


# ---------------------------------------------------------
# LIST COMMENTS
# ---------------------------------------------------------

@app.get("/api/v1/social/posts/{post_id}/comments")
def list_social_comments(
    post_id: uuid.UUID,
    limit: int = 30,
    offset: int = 0,
    authorization: Optional[str] = Header(default=None)
):
    user = global_user(authorization)

    limit = max(1, min(limit, 100))
    offset = max(0, offset)

    with get_connection() as connection:
        with connection.cursor() as cursor:
            require_global_schema(cursor)

            cursor.execute("""
                SELECT visibility, user_id
                FROM public.mg_social_posts
                WHERE id = %s AND is_deleted = FALSE
            """, (post_id,))

            post = cursor.fetchone()

            if not post:
                raise HTTPException(status_code=404, detail="Post not found")

            if post[0] == "private" and str(post[1]) != user["id"]:
                raise HTTPException(status_code=403, detail="Private post")

            cursor.execute("""
                SELECT
                    c.id,
                    c.content,
                    c.created_at,
                    u.id,
                    u.username,
                    u.display_name
                FROM public.mg_social_comments c
                JOIN public.mg_users u ON u.id = c.user_id
                WHERE c.post_id = %s
                  AND c.is_deleted = FALSE
                ORDER BY c.created_at ASC
                LIMIT %s OFFSET %s
            """, (post_id, limit, offset))

            rows = cursor.fetchall()

    return {
        "success": True,
        "count": len(rows),
        "comments": [
            {
                "id": str(r[0]),
                "content": r[1],
                "created_at": r[2].isoformat(),
                "user": {
                    "id": str(r[3]),
                    "username": r[4],
                    "display_name": r[5]
                }
            }
            for r in rows
        ]
    }


# ---------------------------------------------------------
# DELETE OWN COMMENT
# ---------------------------------------------------------

@app.delete("/api/v1/social/comments/{comment_id}")
def delete_social_comment(
    comment_id: uuid.UUID,
    authorization: Optional[str] = Header(default=None)
):
    user = global_user(authorization)

    with get_connection() as connection:
        with connection.cursor() as cursor:
            require_global_schema(cursor)

            cursor.execute("""
                SELECT post_id
                FROM public.mg_social_comments
                WHERE id = %s
                  AND user_id = %s
                  AND is_deleted = FALSE
                FOR UPDATE
            """, (comment_id, user["id"]))

            row = cursor.fetchone()

            if not row:
                raise HTTPException(
                    status_code=404,
                    detail="Comment not found or access denied"
                )

            cursor.execute("""
                UPDATE public.mg_social_comments
                SET is_deleted = TRUE,
                    updated_at = NOW()
                WHERE id = %s
            """, (comment_id,))

            cursor.execute("""
                UPDATE public.mg_social_posts
                SET comments_count = GREATEST(0, comments_count - 1)
                WHERE id = %s
            """, (row[0],))

    return {"success": True, "message": "Comment deleted"}


# =========================================================
# END MODULE 02
# NEXT: FOLLOW SYSTEM + PROFILES + CREATOR BADGE
# =========================================================

# =========================================================
# MODULE 03: GLOBAL IDENTITY + FOLLOW GRAPH
# =========================================================

# ---------------------------------------------------------
# FOLLOW USER
# ---------------------------------------------------------

@app.post("/api/v1/social/follow/{target_user_id}")
def follow_user(
    target_user_id: uuid.UUID,
    authorization: Optional[str] = Header(default=None)
):
    user = global_user(authorization)

    if str(target_user_id) == user["id"]:
        raise HTTPException(
            status_code=422,
            detail="You cannot follow yourself"
        )

    with get_connection() as connection:
        with connection.cursor() as cursor:
            require_global_schema(cursor)

            cursor.execute("""
                SELECT id, account_status
                FROM public.mg_users
                WHERE id = %s AND deleted_at IS NULL
            """, (target_user_id,))

            target = cursor.fetchone()

            if not target or target[1] != "active":
                raise HTTPException(
                    status_code=404,
                    detail="User not found"
                )

            cursor.execute("""
                INSERT INTO public.mg_social_follows(
                    follower_id, following_id
                )
                VALUES (%s,%s)
                ON CONFLICT(follower_id, following_id) DO NOTHING
                RETURNING id
            """, (user["id"], target_user_id))

            inserted = cursor.fetchone()

            if inserted:
                create_global_notification(
                    cursor,
                    target_user_id,
                    "new_follower",
                    "دنبال‌کننده جدید",
                    f"{user['display_name']} شما را دنبال کرد",
                    user["id"],
                    "user",
                    uuid.UUID(user["id"])
                )

                global_audit(
                    cursor,
                    user["id"],
                    "social.follow",
                    "user",
                    target_user_id
                )

    return {
        "success": True,
        "following": True,
        "already_following": inserted is None
    }


# ---------------------------------------------------------
# UNFOLLOW USER
# ---------------------------------------------------------

@app.delete("/api/v1/social/follow/{target_user_id}")
def unfollow_user(
    target_user_id: uuid.UUID,
    authorization: Optional[str] = Header(default=None)
):
    user = global_user(authorization)

    with get_connection() as connection:
        with connection.cursor() as cursor:
            require_global_schema(cursor)

            cursor.execute("""
                DELETE FROM public.mg_social_follows
                WHERE follower_id = %s
                  AND following_id = %s
                RETURNING id
            """, (user["id"], target_user_id))

            removed = cursor.fetchone()

    return {
        "success": True,
        "following": False,
        "removed": removed is not None
    }


# ---------------------------------------------------------
# FOLLOWERS
# ---------------------------------------------------------

@app.get("/api/v1/social/users/{target_user_id}/followers")
def get_followers(
    target_user_id: uuid.UUID,
    limit: int = 30,
    offset: int = 0,
    authorization: Optional[str] = Header(default=None)
):
    user = global_user(authorization)

    limit = max(1, min(limit, 100))
    offset = max(0, offset)

    with get_connection() as connection:
        with connection.cursor() as cursor:
            require_global_schema(cursor)

            cursor.execute("""
                SELECT id
                FROM public.mg_users
                WHERE id = %s AND deleted_at IS NULL
            """, (target_user_id,))

            if not cursor.fetchone():
                raise HTTPException(status_code=404, detail="User not found")

            cursor.execute("""
                SELECT
                    u.id,
                    u.username,
                    u.display_name,
                    f.created_at,
                    EXISTS(
                        SELECT 1
                        FROM public.mg_social_follows mine
                        WHERE mine.follower_id = %s
                          AND mine.following_id = u.id
                    )
                FROM public.mg_social_follows f
                JOIN public.mg_users u ON u.id = f.follower_id
                WHERE f.following_id = %s
                  AND u.account_status = 'active'
                  AND u.deleted_at IS NULL
                ORDER BY f.created_at DESC
                LIMIT %s OFFSET %s
            """, (user["id"], target_user_id, limit, offset))

            rows = cursor.fetchall()

    return {
        "success": True,
        "count": len(rows),
        "users": [
            {
                "id": str(r[0]),
                "username": r[1],
                "display_name": r[2],
                "followed_at": r[3].isoformat(),
                "following_me": bool(r[4])
            }
            for r in rows
        ]
    }


# ---------------------------------------------------------
# FOLLOWING
# ---------------------------------------------------------

@app.get("/api/v1/social/users/{target_user_id}/following")
def get_following(
    target_user_id: uuid.UUID,
    limit: int = 30,
    offset: int = 0,
    authorization: Optional[str] = Header(default=None)
):
    user = global_user(authorization)

    limit = max(1, min(limit, 100))
    offset = max(0, offset)

    with get_connection() as connection:
        with connection.cursor() as cursor:
            require_global_schema(cursor)

            cursor.execute("""
                SELECT id
                FROM public.mg_users
                WHERE id = %s AND deleted_at IS NULL
            """, (target_user_id,))

            if not cursor.fetchone():
                raise HTTPException(status_code=404, detail="User not found")

            cursor.execute("""
                SELECT
                    u.id,
                    u.username,
                    u.display_name,
                    f.created_at,
                    EXISTS(
                        SELECT 1
                        FROM public.mg_social_follows mine
                        WHERE mine.follower_id = %s
                          AND mine.following_id = u.id
                    )
                FROM public.mg_social_follows f
                JOIN public.mg_users u ON u.id = f.following_id
                WHERE f.follower_id = %s
                  AND u.account_status = 'active'
                  AND u.deleted_at IS NULL
                ORDER BY f.created_at DESC
                LIMIT %s OFFSET %s
            """, (user["id"], target_user_id, limit, offset))

            rows = cursor.fetchall()

    return {
        "success": True,
        "count": len(rows),
        "users": [
            {
                "id": str(r[0]),
                "username": r[1],
                "display_name": r[2],
                "followed_at": r[3].isoformat(),
                "following_me": bool(r[4])
            }
            for r in rows
        ]
    }


# ---------------------------------------------------------
# PROFILE UPDATE
# ---------------------------------------------------------

@app.patch("/api/v1/profile/me")
def update_my_profile(
    data: GlobalProfileUpdate,
    authorization: Optional[str] = Header(default=None)
):
    user = global_user(authorization)

    updates = data.model_dump(exclude_unset=True)

    if not updates:
        raise HTTPException(
            status_code=422,
            detail="No profile fields supplied"
        )

    for field in ("avatar_url", "cover_url"):
        value = updates.get(field)
        if value and not value.startswith(("https://", "http://")):
            raise HTTPException(
                status_code=422,
                detail=f"Invalid {field}"
            )

    with get_connection() as connection:
        with connection.cursor() as cursor:
            require_global_schema(cursor)

            cursor.execute("""
                INSERT INTO public.mg_user_profiles(user_id)
                VALUES (%s)
                ON CONFLICT(user_id) DO NOTHING
            """, (user["id"],))

            allowed = {
                "bio": "bio",
                "avatar_url": "avatar_url",
                "cover_url": "cover_url"
            }

            profile_updates = {
                key: value
                for key, value in updates.items()
                if key in allowed
            }

            if profile_updates:
                assignments = []
                values = []

                for key, value in profile_updates.items():
                    assignments.append(f"{allowed[key]} = %s")
                    values.append(value)

                values.append(user["id"])

                cursor.execute(
                    "UPDATE public.mg_user_profiles SET "
                    + ", ".join(assignments)
                    + ", updated_at = NOW() WHERE user_id = %s",
                    tuple(values)
                )

            if updates.get("display_name") is not None:
                cursor.execute("""
                    UPDATE public.mg_users
                    SET display_name = %s, updated_at = NOW()
                    WHERE id = %s
                """, (
                    updates["display_name"].strip(),
                    user["id"]
                ))

            global_audit(
                cursor,
                user["id"],
                "profile.update",
                "user",
                uuid.UUID(user["id"]),
                {"fields": list(updates.keys())}
            )

    return {
        "success": True,
        "message": "Profile updated"
    }


# ---------------------------------------------------------
# PUBLIC PROFILE
# ---------------------------------------------------------

@app.get("/api/v1/profile/{username}")
def get_public_profile(
    username: str,
    authorization: Optional[str] = Header(default=None)
):
    user = global_user(authorization)

    with get_connection() as connection:
        with connection.cursor() as cursor:
            require_global_schema(cursor)

            cursor.execute("""
                SELECT
                    u.id,
                    u.username,
                    u.display_name,
                    u.created_at,
                    p.bio,
                    p.avatar_url,
                    p.cover_url,
                    p.profile_visibility
                FROM public.mg_users u
                LEFT JOIN public.mg_user_profiles p
                    ON p.user_id = u.id
                WHERE LOWER(u.username) = LOWER(%s)
                  AND u.account_status = 'active'
                  AND u.deleted_at IS NULL
            """, (username,))

            row = cursor.fetchone()

            if not row:
                raise HTTPException(status_code=404, detail="User not found")

            is_owner = str(row[0]) == user["id"]

            if row[7] == "private" and not is_owner:
                raise HTTPException(status_code=403, detail="Private profile")

            cursor.execute("""
                SELECT COUNT(*) FROM public.mg_social_follows
                WHERE following_id = %s
            """, (row[0],))
            followers = cursor.fetchone()[0]

            cursor.execute("""
                SELECT COUNT(*) FROM public.mg_social_follows
                WHERE follower_id = %s
            """, (row[0],))
            following = cursor.fetchone()[0]

            cursor.execute("""
                SELECT COUNT(*) FROM public.mg_social_posts
                WHERE user_id = %s AND is_deleted = FALSE
            """, (row[0],))
            posts = cursor.fetchone()[0]

            cursor.execute("""
                SELECT EXISTS(
                    SELECT 1 FROM public.mg_social_follows
                    WHERE follower_id = %s AND following_id = %s
                )
            """, (user["id"], row[0]))
            is_following = cursor.fetchone()[0]

            cursor.execute("""
                SELECT badge_name
                FROM public.mg_creator_badges
                WHERE user_id = %s AND revoked_at IS NULL
            """, (row[0],))
            badge = cursor.fetchone()

    return {
        "success": True,
        "profile": {
            "id": str(row[0]),
            "username": row[1],
            "display_name": row[2],
            "joined_at": row[3].isoformat(),
            "bio": row[4],
            "avatar_url": row[5],
            "cover_url": row[6],
            "followers_count": followers,
            "following_count": following,
            "posts_count": posts,
            "is_following": bool(is_following),
            "creator_badge": badge[0] if badge else None
        }
    }


# ---------------------------------------------------------
# MY CREATOR BADGE
# ---------------------------------------------------------

@app.get("/api/v1/creator-badge/me")
def my_creator_badge(
    authorization: Optional[str] = Header(default=None)
):
    user = global_user(authorization)

    with get_connection() as connection:
        with connection.cursor() as cursor:
            require_global_schema(cursor)

            cursor.execute("""
                SELECT badge_name, granted_at
                FROM public.mg_creator_badges
                WHERE user_id = %s AND revoked_at IS NULL
            """, (user["id"],))

            row = cursor.fetchone()

    return {
        "success": True,
        "has_badge": row is not None,
        "badge": {
            "name": row[0],
            "granted_at": row[1].isoformat()
        } if row else None
    }


# ---------------------------------------------------------
# ADMIN: GRANT CREATOR BADGE
# ---------------------------------------------------------

@app.post("/api/v1/admin/users/{target_user_id}/creator-badge")
def admin_grant_creator_badge(
    target_user_id: uuid.UUID,
    x_admin_key: Optional[str] = Header(default=None)
):
    verify_admin_key(x_admin_key)

    with get_connection() as connection:
        with connection.cursor() as cursor:
            require_global_schema(cursor)

            cursor.execute("""
                SELECT id FROM public.mg_users
                WHERE id = %s AND deleted_at IS NULL
            """, (target_user_id,))

            if not cursor.fetchone():
                raise HTTPException(status_code=404, detail="User not found")

            cursor.execute("""
                INSERT INTO public.mg_creator_badges(
                    user_id, badge_name
                )
                VALUES (%s, 'سازنده MASIH GRAM')
                ON CONFLICT(user_id)
                DO UPDATE SET
                    badge_name = EXCLUDED.badge_name,
                    granted_at = NOW(),
                    revoked_at = NULL
                RETURNING id
            """, (target_user_id,))

            badge_id = cursor.fetchone()[0]

            global_audit(
                cursor,
                None,
                "admin.creator_badge.grant",
                "user",
                target_user_id
            )

    return {
        "success": True,
        "badge_id": str(badge_id),
        "badge": "سازنده MASIH GRAM"
    }


# ---------------------------------------------------------
# ADMIN: REVOKE CREATOR BADGE
# ---------------------------------------------------------

@app.delete("/api/v1/admin/users/{target_user_id}/creator-badge")
def admin_revoke_creator_badge(
    target_user_id: uuid.UUID,
    x_admin_key: Optional[str] = Header(default=None)
):
    verify_admin_key(x_admin_key)

    with get_connection() as connection:
        with connection.cursor() as cursor:
            require_global_schema(cursor)

            cursor.execute("""
                UPDATE public.mg_creator_badges
                SET revoked_at = NOW()
                WHERE user_id = %s AND revoked_at IS NULL
            """, (target_user_id,))

            changed = cursor.rowcount

            global_audit(
                cursor,
                None,
                "admin.creator_badge.revoke",
                "user",
                target_user_id
            )

    return {
        "success": True,
        "revoked": bool(changed)
    }


# =========================================================
# END MODULE 03
# NEXT: FEATURE STORE + ADMIN CONTROL CENTER
# =========================================================
# =========================================================
# MASIH GRAM GLOBAL — SECTION 4
# FEATURE STORE + REQUEST CENTER + ADMIN ACTIVATION
# =========================================================

from datetime import timedelta


def global_admin_check(x_admin_key: Optional[str]):
    """اعتبارسنجی کلید مدیریت با سیستم امنیتی اصلی برنامه."""
    verify_admin_key(x_admin_key)


def global_feature_dict(row):
    return {
        "code": row[0],
        "name": row[1],
        "description": row[2],
        "category": row[3],
        "enabled": bool(row[4]),
        "requires_review": bool(row[5]),
        "created_at": row[6].isoformat() if row[6] else None
    }


def global_feature_request_dict(row):
    return {
        "id": str(row[0]),
        "feature_code": row[1],
        "feature_name": row[2],
        "message": row[3],
        "status": row[4],
        "admin_note": row[5],
        "created_at": row[6].isoformat() if row[6] else None,
        "reviewed_at": row[7].isoformat() if row[7] else None
    }


def global_entitlement_dict(row):
    return {
        "feature_code": row[0],
        "feature_name": row[1],
        "activated_at": row[2].isoformat() if row[2] else None,
        "expires_at": row[3].isoformat() if row[3] else None
    }


# ---------------------------------------------------------
# 4.1 — PUBLIC FEATURE CATALOG
# ---------------------------------------------------------

@app.get("/api/v1/features")
def global_list_features(
    category: Optional[str] = None,
    authorization: Optional[str] = Header(default=None)
):
    user = get_authenticated_user(authorization)

    with get_connection() as connection:
        with connection.cursor() as cursor:
            require_global_schema(cursor)

            if category:
                cursor.execute("""
                    SELECT code, name, description, category,
                           enabled, requires_review, created_at
                    FROM public.mg_feature_catalog
                    WHERE enabled = TRUE
                      AND category = %s
                    ORDER BY category, name
                """, (category.strip(),))
            else:
                cursor.execute("""
                    SELECT code, name, description, category,
                           enabled, requires_review, created_at
                    FROM public.mg_feature_catalog
                    WHERE enabled = TRUE
                    ORDER BY category, name
                """)

            rows = cursor.fetchall()

    return {
        "success": True,
        "count": len(rows),
        "features": [global_feature_dict(row) for row in rows]
    }


@app.get("/api/v1/features/{feature_code}")
def global_get_feature(
    feature_code: str,
    authorization: Optional[str] = Header(default=None)
):
    user = get_authenticated_user(authorization)

    with get_connection() as connection:
        with connection.cursor() as cursor:
            require_global_schema(cursor)

            cursor.execute("""
                SELECT code, name, description, category,
                       enabled, requires_review, created_at
                FROM public.mg_feature_catalog
                WHERE code = %s AND enabled = TRUE
            """, (feature_code,))

            row = cursor.fetchone()

    if not row:
        raise HTTPException(status_code=404, detail="Feature not found")

    return {
        "success": True,
        "feature": global_feature_dict(row)
    }


# ---------------------------------------------------------
# 4.2 — USER FEATURE REQUESTS
# ---------------------------------------------------------

@app.post("/api/v1/features/requests")
def global_create_feature_request(
    data: GlobalFeatureRequest,
    authorization: Optional[str] = Header(default=None)
):
    user = get_authenticated_user(authorization)

    feature_code = data.feature_code.strip().lower()
    message = (data.message or "").strip()

    if not re.fullmatch(r"[a-z0-9_]{2,64}", feature_code):
        raise HTTPException(status_code=422, detail="Invalid feature code")

    if len(message) > 2000:
        raise HTTPException(status_code=422, detail="Message is too long")

    with get_connection() as connection:
        with connection.cursor() as cursor:
            require_global_schema(cursor)

            cursor.execute("""
                SELECT code, name, enabled
                FROM public.mg_feature_catalog
                WHERE code = %s
            """, (feature_code,))
            feature = cursor.fetchone()

            if not feature or not feature[2]:
                raise HTTPException(status_code=404, detail="Feature is unavailable")

            cursor.execute("""
                SELECT id
                FROM public.mg_user_feature_entitlements
                WHERE user_id = %s
                  AND feature_code = %s
                  AND revoked_at IS NULL
                  AND (expires_at IS NULL OR expires_at > NOW())
                LIMIT 1
            """, (user["id"], feature_code))

            if cursor.fetchone():
                raise HTTPException(
                    status_code=409,
                    detail="This feature is already active for your account"
                )

            cursor.execute("""
                SELECT id
                FROM public.mg_feature_requests
                WHERE user_id = %s
                  AND feature_code = %s
                  AND status IN ('pending', 'approved')
                LIMIT 1
            """, (user["id"], feature_code))

            if cursor.fetchone():
                raise HTTPException(
                    status_code=409,
                    detail="You already have an active request for this feature"
                )

            cursor.execute("""
                INSERT INTO public.mg_feature_requests
                    (user_id, feature_code, message, status, created_at)
                VALUES (%s, %s, %s, 'pending', NOW())
                RETURNING id, created_at
            """, (user["id"], feature_code, message))

            request_row = cursor.fetchone()

            global_audit(
                cursor,
                user["id"],
                "feature_request_created",
                "feature",
                feature_code,
                {"request_id": str(request_row[0])}
            )

            create_global_notification(
                cursor,
                user["id"],
                "feature_request_submitted",
                "درخواست قابلیت ثبت شد",
                f"درخواست فعال‌سازی {feature[1]} برای بررسی ارسال شد"
            )

    return {
        "success": True,
        "message": "درخواست با موفقیت ثبت شد",
        "request": {
            "id": str(request_row[0]),
            "feature_code": feature_code,
            "feature_name": feature[1],
            "status": "pending",
            "created_at": request_row[1].isoformat()
        }
    }


@app.get("/api/v1/features/requests/me")
def global_my_feature_requests(
    authorization: Optional[str] = Header(default=None)
):
    user = get_authenticated_user(authorization)

    with get_connection() as connection:
        with connection.cursor() as cursor:
            require_global_schema(cursor)

            cursor.execute("""
                SELECT r.id, r.feature_code, f.name, r.message,
                       r.status, r.admin_note, r.created_at, r.reviewed_at
                FROM public.mg_feature_requests r
                JOIN public.mg_feature_catalog f
                  ON f.code = r.feature_code
                WHERE r.user_id = %s
                ORDER BY r.created_at DESC
                LIMIT 200
            """, (user["id"],))

            rows = cursor.fetchall()

    return {
        "success": True,
        "count": len(rows),
        "requests": [global_feature_request_dict(row) for row in rows]
    }


@app.get("/api/v1/features/me")
def global_my_active_features(
    authorization: Optional[str] = Header(default=None)
):
    user = get_authenticated_user(authorization)

    with get_connection() as connection:
        with connection.cursor() as cursor:
            require_global_schema(cursor)

            cursor.execute("""
                SELECT e.feature_code, f.name,
                       e.activated_at, e.expires_at
                FROM public.mg_user_feature_entitlements e
                JOIN public.mg_feature_catalog f
                  ON f.code = e.feature_code
                WHERE e.user_id = %s
                  AND e.revoked_at IS NULL
                  AND (e.expires_at IS NULL OR e.expires_at > NOW())
                  AND f.enabled = TRUE
                ORDER BY e.activated_at DESC
            """, (user["id"],))

            rows = cursor.fetchall()

    return {
        "success": True,
        "count": len(rows),
        "active_features": [global_entitlement_dict(row) for row in rows]
    }


# ---------------------------------------------------------
# 4.3 — ADMIN FEATURE CATALOG CONTROL
# ---------------------------------------------------------

@app.get("/api/v1/admin/features")
def global_admin_list_features(
    x_admin_key: Optional[str] = Header(default=None)
):
    global_admin_check(x_admin_key)

    with get_connection() as connection:
        with connection.cursor() as cursor:
            require_global_schema(cursor)

            cursor.execute("""
                SELECT code, name, description, category,
                       enabled, requires_review, created_at
                FROM public.mg_feature_catalog
                ORDER BY category, name
            """)

            rows = cursor.fetchall()

    return {
        "success": True,
        "count": len(rows),
        "features": [global_feature_dict(row) for row in rows]
    }


@app.post("/api/v1/admin/features")
def global_admin_create_feature(
    data: GlobalFeatureCreate,
    x_admin_key: Optional[str] = Header(default=None)
):
    global_admin_check(x_admin_key)

    code = data.code.strip().lower()
    name = data.name.strip()
    description = data.description.strip()
    category = data.category.strip().lower()

    if not re.fullmatch(r"[a-z0-9_]{2,64}", code):
        raise HTTPException(status_code=422, detail="Invalid feature code")

    if not name or len(name) > 120:
        raise HTTPException(status_code=422, detail="Invalid feature name")

    if len(description) > 3000:
        raise HTTPException(status_code=422, detail="Description is too long")

    if not category or len(category) > 60:
        raise HTTPException(status_code=422, detail="Invalid category")

    with get_connection() as connection:
        with connection.cursor() as cursor:
            require_global_schema(cursor)

            cursor.execute("""
                INSERT INTO public.mg_feature_catalog
                    (code, name, description, category,
                     enabled, requires_review, created_at)
                VALUES (%s, %s, %s, %s, %s, %s, NOW())
                ON CONFLICT (code) DO NOTHING
                RETURNING code
            """, (
                code,
                name,
                description,
                category,
                bool(data.enabled),
                bool(data.requires_review)
            ))

            created = cursor.fetchone()

            if not created:
                raise HTTPException(
                    status_code=409,
                    detail="A feature with this code already exists"
                )

            global_audit(
                cursor,
                None,
                "admin_feature_created",
                "feature",
                code,
                {"name": name, "category": category}
            )

    return {
        "success": True,
        "message": "قابلیت جدید ثبت شد",
        "feature_code": code
    }


@app.patch("/api/v1/admin/features/{feature_code}/status")
def global_admin_update_feature_status(
    feature_code: str,
    enabled: bool,
    x_admin_key: Optional[str] = Header(default=None)
):
    global_admin_check(x_admin_key)

    with get_connection() as connection:
        with connection.cursor() as cursor:
            require_global_schema(cursor)

            cursor.execute("""
                UPDATE public.mg_feature_catalog
                SET enabled = %s
                WHERE code = %s
                RETURNING code
            """, (enabled, feature_code))

            row = cursor.fetchone()

            if not row:
                raise HTTPException(status_code=404, detail="Feature not found")

            global_audit(
                cursor,
                None,
                "admin_feature_status_changed",
                "feature",
                feature_code,
                {"enabled": enabled}
            )

    return {
        "success": True,
        "feature_code": feature_code,
        "enabled": enabled
    }


# ---------------------------------------------------------
# 4.4 — ADMIN REQUEST REVIEW CENTER
# ---------------------------------------------------------

@app.get("/api/v1/admin/features/requests")
def global_admin_feature_requests(
    status: Optional[str] = None,
    limit: int = 100,
    x_admin_key: Optional[str] = Header(default=None)
):
    global_admin_check(x_admin_key)

    limit = max(1, min(limit, 300))

    allowed_statuses = {"pending", "approved", "rejected", "cancelled"}
    if status and status not in allowed_statuses:
        raise HTTPException(status_code=422, detail="Invalid request status")

    with get_connection() as connection:
        with connection.cursor() as cursor:
            require_global_schema(cursor)

            if status:
                cursor.execute("""
                    SELECT r.id, r.feature_code, f.name, r.message,
                           r.status, r.admin_note, r.created_at, r.reviewed_at
                    FROM public.mg_feature_requests r
                    JOIN public.mg_feature_catalog f
                      ON f.code = r.feature_code
                    WHERE r.status = %s
                    ORDER BY r.created_at ASC
                    LIMIT %s
                """, (status, limit))
            else:
                cursor.execute("""
                    SELECT r.id, r.feature_code, f.name, r.message,
                           r.status, r.admin_note, r.created_at, r.reviewed_at
                    FROM public.mg_feature_requests r
                    JOIN public.mg_feature_catalog f
                      ON f.code = r.feature_code
                    ORDER BY
                      CASE WHEN r.status = 'pending' THEN 0 ELSE 1 END,
                      r.created_at ASC
                    LIMIT %s
                """, (limit,))

            rows = cursor.fetchall()

    return {
        "success": True,
        "count": len(rows),
        "requests": [global_feature_request_dict(row) for row in rows]
    }


@app.post("/api/v1/admin/features/requests/{request_id}/review")
def global_admin_review_feature_request(
    request_id: str,
    data: GlobalFeatureReview,
    x_admin_key: Optional[str] = Header(default=None)
):
    global_admin_check(x_admin_key)

    try:
        request_uuid = uuid.UUID(request_id)
    except Exception:
        raise HTTPException(status_code=422, detail="Invalid request ID")

    if data.status not in ("approved", "rejected"):
        raise HTTPException(
            status_code=422,
            detail="Status must be approved or rejected"
        )

    admin_note = (data.admin_note or "").strip()
    if len(admin_note) > 2000:
        raise HTTPException(status_code=422, detail="Admin note is too long")

    with get_connection() as connection:
        with connection.cursor() as cursor:
            require_global_schema(cursor)

            cursor.execute("""
                SELECT r.id, r.user_id, r.feature_code, r.status,
                       f.name, f.enabled
                FROM public.mg_feature_requests r
                JOIN public.mg_feature_catalog f
                  ON f.code = r.feature_code
                WHERE r.id = %s
                FOR UPDATE OF r
            """, (request_uuid,))

            request_row = cursor.fetchone()

            if not request_row:
                raise HTTPException(status_code=404, detail="Request not found")

            if request_row[3] != "pending":
                raise HTTPException(
                    status_code=409,
                    detail="This request has already been reviewed"
                )

            if data.status == "approved" and not request_row[5]:
                raise HTTPException(
                    status_code=409,
                    detail="This feature is currently disabled"
                )

            cursor.execute("""
                UPDATE public.mg_feature_requests
                SET status = %s,
                    admin_note = %s,
                    reviewed_at = NOW()
                WHERE id = %s
            """, (data.status, admin_note, request_uuid))

            activated = False

            if data.status == "approved" and bool(data.activate):
                cursor.execute("""
                    INSERT INTO public.mg_user_feature_entitlements
                        (user_id, feature_code, activated_at, expires_at, revoked_at)
                    VALUES (%s, %s, NOW(), NULL, NULL)
                    ON CONFLICT (user_id, feature_code)
                    DO UPDATE SET
                        activated_at = NOW(),
                        expires_at = NULL,
                        revoked_at = NULL
                """, (request_row[1], request_row[2]))

                activated = True

            global_audit(
                cursor,
                None,
                "admin_feature_request_reviewed",
                "feature_request",
                str(request_uuid),
                {
                    "status": data.status,
                    "feature_code": request_row[2],
                    "activated": activated
                }
            )

            create_global_notification(
                cursor,
                str(request_row[1]),
                "feature_request_reviewed",
                "وضعیت درخواست قابلیت",
                (
                    f"درخواست {request_row[4]} تأیید شد"
                    if data.status == "approved"
                    else f"درخواست {request_row[4]} رد شد"
                )
            )

    return {
        "success": True,
        "request_id": str(request_uuid),
        "status": data.status,
        "feature_activated": activated
    }


# ---------------------------------------------------------
# 4.5 — MANUAL USER FEATURE ACTIVATION
# ---------------------------------------------------------

@app.post("/api/v1/admin/users/{user_id}/features/{feature_code}/activate")
def global_admin_activate_user_feature(
    user_id: str,
    feature_code: str,
    x_admin_key: Optional[str] = Header(default=None)
):
    global_admin_check(x_admin_key)

    try:
        target_user_id = uuid.UUID(user_id)
    except Exception:
        raise HTTPException(status_code=422, detail="Invalid user ID")

    with get_connection() as connection:
        with connection.cursor() as cursor:
            require_global_schema(cursor)

            cursor.execute("""
                SELECT id
                FROM public.mg_users
                WHERE id = %s
                  AND account_status = 'active'
                  AND deleted_at IS NULL
            """, (target_user_id,))

            if not cursor.fetchone():
                raise HTTPException(status_code=404, detail="User not found")

            cursor.execute("""
                SELECT code
                FROM public.mg_feature_catalog
                WHERE code = %s AND enabled = TRUE
            """, (feature_code,))

            if not cursor.fetchone():
                raise HTTPException(status_code=404, detail="Feature not found or disabled")

            cursor.execute("""
                INSERT INTO public.mg_user_feature_entitlements
                    (user_id, feature_code, activated_at, expires_at, revoked_at)
                VALUES (%s, %s, NOW(), NULL, NULL)
                ON CONFLICT (user_id, feature_code)
                DO UPDATE SET
                    activated_at = NOW(),
                    expires_at = NULL,
                    revoked_at = NULL
            """, (target_user_id, feature_code))

            global_audit(
                cursor,
                None,
                "admin_user_feature_activated",
                "user_feature",
                f"{user_id}:{feature_code}",
                {}
            )

            create_global_notification(
                cursor,
                str(target_user_id),
                "feature_activated",
                "قابلیت جدید فعال شد",
                f"قابلیت {feature_code} برای حساب شما فعال شد"
            )

    return {
        "success": True,
        "user_id": str(target_user_id),
        "feature_code": feature_code,
        "active": True
    }


@app.delete("/api/v1/admin/users/{user_id}/features/{feature_code}")
def global_admin_revoke_user_feature(
    user_id: str,
    feature_code: str,
    x_admin_key: Optional[str] = Header(default=None)
):
    global_admin_check(x_admin_key)

    try:
        target_user_id = uuid.UUID(user_id)
    except Exception:
        raise HTTPException(status_code=422, detail="Invalid user ID")

    with get_connection() as connection:
        with connection.cursor() as cursor:
            require_global_schema(cursor)

            cursor.execute("""
                UPDATE public.mg_user_feature_entitlements
                SET revoked_at = NOW()
                WHERE user_id = %s
                  AND feature_code = %s
                  AND revoked_at IS NULL
                RETURNING feature_code
            """, (target_user_id, feature_code))

            row = cursor.fetchone()

            if not row:
                raise HTTPException(
                    status_code=404,
                    detail="Active feature entitlement not found"
                )

            global_audit(
                cursor,
                None,
                "admin_user_feature_revoked",
                "user_feature",
                f"{user_id}:{feature_code}",
                {}
            )

            create_global_notification(
                cursor,
                str(target_user_id),
                "feature_revoked",
                "دسترسی قابلیت تغییر کرد",
                f"دسترسی قابلیت {feature_code} از حساب شما لغو شد"
            )

    return {
        "success": True,
        "user_id": str(target_user_id),
        "feature_code": feature_code,
        "active": False
    }


# =========================================================
# END OF SECTION 4
# NEXT: SECTION 5 — NOTIFICATIONS + REPORTS + USER SAFETY
# =========================================================
# =========================================================
# MASIH GRAM GLOBAL — SECTION 5
# NOTIFICATION ENGINE + TRUST & SAFETY + MODERATION CENTER
# =========================================================

# ---------------------------------------------------------
# 5.1 — NOTIFICATION SERIALIZER
# ---------------------------------------------------------

def global_notification_dict(row):
    return {
        "id": str(row[0]),
        "type": row[1],
        "title": row[2],
        "body": row[3],
        "is_read": bool(row[4]),
        "created_at": row[5].isoformat() if row[5] else None
    }


def global_report_dict(row):
    return {
        "id": str(row[0]),
        "target_type": row[1],
        "target_id": str(row[2]),
        "reason": row[3],
        "status": row[4],
        "created_at": row[5].isoformat() if row[5] else None
    }


# ---------------------------------------------------------
# 5.2 — NOTIFICATION INBOX
# ---------------------------------------------------------

@app.get("/api/v1/notifications")
def global_get_notifications(
    unread_only: bool = False,
    limit: int = 50,
    offset: int = 0,
    authorization: Optional[str] = Header(default=None)
):
    user = get_authenticated_user(authorization)

    limit = max(1, min(limit, 100))
    offset = max(0, min(offset, 100000))

    with get_connection() as connection:
        with connection.cursor() as cursor:
            require_global_schema(cursor)

            if unread_only:
                cursor.execute("""
                    SELECT id, notification_type, title, body,
                           is_read, created_at
                    FROM public.mg_global_notifications
                    WHERE user_id = %s
                      AND is_read = FALSE
                    ORDER BY created_at DESC
                    LIMIT %s OFFSET %s
                """, (user["id"], limit, offset))
            else:
                cursor.execute("""
                    SELECT id, notification_type, title, body,
                           is_read, created_at
                    FROM public.mg_global_notifications
                    WHERE user_id = %s
                    ORDER BY created_at DESC
                    LIMIT %s OFFSET %s
                """, (user["id"], limit, offset))

            rows = cursor.fetchall()

            cursor.execute("""
                SELECT COUNT(*)
                FROM public.mg_global_notifications
                WHERE user_id = %s AND is_read = FALSE
            """, (user["id"],))

            unread_count = cursor.fetchone()[0]

    return {
        "success": True,
        "unread_count": unread_count,
        "count": len(rows),
        "notifications": [
            global_notification_dict(row) for row in rows
        ],
        "pagination": {
            "limit": limit,
            "offset": offset
        }
    }


@app.get("/api/v1/notifications/unread-count")
def global_notification_unread_count(
    authorization: Optional[str] = Header(default=None)
):
    user = get_authenticated_user(authorization)

    with get_connection() as connection:
        with connection.cursor() as cursor:
            require_global_schema(cursor)

            cursor.execute("""
                SELECT COUNT(*)
                FROM public.mg_global_notifications
                WHERE user_id = %s
                  AND is_read = FALSE
            """, (user["id"],))

            count = cursor.fetchone()[0]

    return {
        "success": True,
        "unread_count": count
    }


# ---------------------------------------------------------
# 5.3 — MARK NOTIFICATIONS AS READ
# ---------------------------------------------------------

@app.post("/api/v1/notifications/read")
def global_mark_notifications_read(
    data: GlobalNotificationRead,
    authorization: Optional[str] = Header(default=None)
):
    user = get_authenticated_user(authorization)

    if not data.notification_ids:
        raise HTTPException(
            status_code=422,
            detail="At least one notification ID is required"
        )

    if len(data.notification_ids) > 100:
        raise HTTPException(
            status_code=422,
            detail="Maximum 100 notification IDs per request"
        )

    notification_ids = []

    for value in data.notification_ids:
        try:
            notification_ids.append(uuid.UUID(str(value)))
        except Exception:
            raise HTTPException(
                status_code=422,
                detail="One or more notification IDs are invalid"
            )

    with get_connection() as connection:
        with connection.cursor() as cursor:
            require_global_schema(cursor)

            cursor.execute("""
                UPDATE public.mg_global_notifications
                SET is_read = TRUE
                WHERE user_id = %s
                  AND id = ANY(%s)
                  AND is_read = FALSE
                RETURNING id
            """, (user["id"], notification_ids))

            updated_count = len(cursor.fetchall())

            cursor.execute("""
                SELECT COUNT(*)
                FROM public.mg_global_notifications
                WHERE user_id = %s
                  AND is_read = FALSE
            """, (user["id"],))

            unread_count = cursor.fetchone()[0]

    return {
        "success": True,
        "updated_count": updated_count,
        "unread_count": unread_count
    }


@app.post("/api/v1/notifications/read-all")
def global_mark_all_notifications_read(
    authorization: Optional[str] = Header(default=None)
):
    user = get_authenticated_user(authorization)

    with get_connection() as connection:
        with connection.cursor() as cursor:
            require_global_schema(cursor)

            cursor.execute("""
                UPDATE public.mg_global_notifications
                SET is_read = TRUE
                WHERE user_id = %s
                  AND is_read = FALSE
                RETURNING id
            """, (user["id"],))

            updated_count = len(cursor.fetchall())

    return {
        "success": True,
        "updated_count": updated_count,
        "unread_count": 0
    }


# ---------------------------------------------------------
# 5.4 — REPORT CONTENT
# ---------------------------------------------------------

@app.post("/api/v1/reports")
def global_create_report(
    data: GlobalReportCreate,
    authorization: Optional[str] = Header(default=None)
):
    user = get_authenticated_user(authorization)

    target_type = data.target_type.strip().lower()
    reason = data.reason.strip()

    if target_type not in ("post", "comment", "profile"):
        raise HTTPException(
            status_code=422,
            detail="Unsupported report target type"
        )

    if len(reason) < 5 or len(reason) > 1500:
        raise HTTPException(
            status_code=422,
            detail="Report reason must contain 5 to 1500 characters"
        )

    try:
        target_uuid = uuid.UUID(str(data.target_id))
    except Exception:
        raise HTTPException(
            status_code=422,
            detail="Invalid target ID"
        )

    with get_connection() as connection:
        with connection.cursor() as cursor:
            require_global_schema(cursor)

            if target_type == "post":
                cursor.execute("""
                    SELECT id, user_id
                    FROM public.mg_social_posts
                    WHERE id = %s
                      AND deleted_at IS NULL
                """, (target_uuid,))
                target = cursor.fetchone()

            elif target_type == "comment":
                cursor.execute("""
                    SELECT id, user_id
                    FROM public.mg_social_comments
                    WHERE id = %s
                      AND deleted_at IS NULL
                """, (target_uuid,))
                target = cursor.fetchone()

            else:
                cursor.execute("""
                    SELECT id
                    FROM public.mg_users
                    WHERE id = %s
                      AND deleted_at IS NULL
                """, (target_uuid,))
                target = cursor.fetchone()

            if not target:
                raise HTTPException(
                    status_code=404,
                    detail="Reported content was not found"
                )

            target_owner_id = str(target[1]) if target_type != "profile" else str(target[0])

            if target_owner_id == user["id"]:
                raise HTTPException(
                    status_code=422,
                    detail="You cannot report your own content"
                )

            cursor.execute("""
                SELECT id
                FROM public.mg_social_reports
                WHERE reporter_id = %s
                  AND target_type = %s
                  AND target_id = %s
                  AND status = 'pending'
                LIMIT 1
            """, (user["id"], target_type, target_uuid))

            if cursor.fetchone():
                raise HTTPException(
                    status_code=409,
                    detail="You already submitted a pending report for this content"
                )

            cursor.execute("""
                INSERT INTO public.mg_social_reports
                    (reporter_id, target_type, target_id,
                     reason, status, created_at)
                VALUES (%s, %s, %s, %s, 'pending', NOW())
                RETURNING id, created_at
            """, (
                user["id"],
                target_type,
                target_uuid,
                reason
            ))

            report_row = cursor.fetchone()

            global_audit(
                cursor,
                user["id"],
                "content_report_created",
                target_type,
                str(target_uuid),
                {"report_id": str(report_row[0])}
            )

    return {
        "success": True,
        "message": "گزارش شما برای بررسی ثبت شد",
        "report": {
            "id": str(report_row[0]),
            "target_type": target_type,
            "target_id": str(target_uuid),
            "status": "pending",
            "created_at": report_row[1].isoformat()
        }
    }


# ---------------------------------------------------------
# 5.5 — USER REPORT HISTORY
# ---------------------------------------------------------

@app.get("/api/v1/reports/me")
def global_my_reports(
    limit: int = 50,
    offset: int = 0,
    authorization: Optional[str] = Header(default=None)
):
    user = get_authenticated_user(authorization)

    limit = max(1, min(limit, 100))
    offset = max(0, min(offset, 100000))

    with get_connection() as connection:
        with connection.cursor() as cursor:
            require_global_schema(cursor)

            cursor.execute("""
                SELECT id, target_type, target_id,
                       reason, status, created_at
                FROM public.mg_social_reports
                WHERE reporter_id = %s
                ORDER BY created_at DESC
                LIMIT %s OFFSET %s
            """, (user["id"], limit, offset))

            rows = cursor.fetchall()

    return {
        "success": True,
        "count": len(rows),
        "reports": [global_report_dict(row) for row in rows]
    }


# ---------------------------------------------------------
# 5.6 — ADMIN MODERATION QUEUE
# ---------------------------------------------------------

@app.get("/api/v1/admin/moderation/reports")
def global_admin_moderation_queue(
    status: Optional[str] = "pending",
    limit: int = 100,
    offset: int = 0,
    x_admin_key: Optional[str] = Header(default=None)
):
    global_admin_check(x_admin_key)

    allowed_statuses = {
        "pending",
        "reviewed",
        "dismissed",
        "action_taken"
    }

    if status and status not in allowed_statuses:
        raise HTTPException(
            status_code=422,
            detail="Invalid moderation status"
        )

    limit = max(1, min(limit, 300))
    offset = max(0, min(offset, 100000))

    with get_connection() as connection:
        with connection.cursor() as cursor:
            require_global_schema(cursor)

            if status:
                cursor.execute("""
                    SELECT id, reporter_id, target_type, target_id,
                           reason, status, created_at
                    FROM public.mg_social_reports
                    WHERE status = %s
                    ORDER BY created_at ASC
                    LIMIT %s OFFSET %s
                """, (status, limit, offset))
            else:
                cursor.execute("""
                    SELECT id, reporter_id, target_type, target_id,
                           reason, status, created_at
                    FROM public.mg_social_reports
                    ORDER BY created_at DESC
                    LIMIT %s OFFSET %s
                """, (limit, offset))

            rows = cursor.fetchall()

    reports = []

    for row in rows:
        reports.append({
            "id": str(row[0]),
            "reporter_id": str(row[1]),
            "target_type": row[2],
            "target_id": str(row[3]),
            "reason": row[4],
            "status": row[5],
            "created_at": row[6].isoformat() if row[6] else None
        })

    return {
        "success": True,
        "count": len(reports),
        "reports": reports
    }


# ---------------------------------------------------------
# 5.7 — ADMIN REPORT DECISION
# ---------------------------------------------------------

@app.post("/api/v1/admin/moderation/reports/{report_id}/decision")
def global_admin_report_decision(
    report_id: str,
    decision: str,
    admin_note: str = "",
    x_admin_key: Optional[str] = Header(default=None)
):
    global_admin_check(x_admin_key)

    try:
        report_uuid = uuid.UUID(report_id)
    except Exception:
        raise HTTPException(
            status_code=422,
            detail="Invalid report ID"
        )

    decision = decision.strip().lower()
    admin_note = admin_note.strip()

    if decision not in ("reviewed", "dismissed", "action_taken"):
        raise HTTPException(
            status_code=422,
            detail="Invalid moderation decision"
        )

    if len(admin_note) > 2000:
        raise HTTPException(
            status_code=422,
            detail="Admin note is too long"
        )

    with get_connection() as connection:
        with connection.cursor() as cursor:
            require_global_schema(cursor)

            cursor.execute("""
                SELECT id, reporter_id, target_type, target_id, status
                FROM public.mg_social_reports
                WHERE id = %s
                FOR UPDATE
            """, (report_uuid,))

            report = cursor.fetchone()

            if not report:
                raise HTTPException(
                    status_code=404,
                    detail="Report not found"
                )

            if report[4] != "pending":
                raise HTTPException(
                    status_code=409,
                    detail="This report has already been processed"
                )

            cursor.execute("""
                UPDATE public.mg_social_reports
                SET status = %s,
                    admin_note = %s,
                    reviewed_at = NOW()
                WHERE id = %s
            """, (decision, admin_note, report_uuid))

            global_audit(
                cursor,
                None,
                "moderation_report_decision",
                report[2],
                str(report[3]),
                {
                    "report_id": str(report_uuid),
                    "decision": decision
                }
            )

            create_global_notification(
                cursor,
                str(report[1]),
                "report_reviewed",
                "گزارش شما بررسی شد",
                "گزارش ثبت‌شده شما توسط مدیریت بررسی شد"
            )

    return {
        "success": True,
        "report_id": str(report_uuid),
        "decision": decision
    }


# =========================================================
# END OF SECTION 5
# NEXT: SECTION 6 — SEARCH + DISCOVERY + GLOBAL DIRECTORY
# =========================================================

# ============================================================
# MASIH GRAM GLOBAL
# SECTION 6 — GLOBAL DISCOVERY ENGINE
# Search / Explore / Trending / Popular / New
# ============================================================

from fastapi import Query


def discovery_post_dict(row):
    return {
        "id": str(row["id"]),
        "user_id": str(row["user_id"]),
        "content": row["content"],
        "media_url": row.get("media_url"),
        "created_at": row["created_at"].isoformat() if row.get("created_at") else None,
        "likes_count": int(row.get("likes_count") or 0),
        "comments_count": int(row.get("comments_count") or 0),
        "engagement_score": float(row.get("engagement_score") or 0),
        "author": {
            "display_name": row.get("display_name"),
            "avatar_url": row.get("avatar_url"),
        },
    }


def discovery_user_dict(row):
    return {
        "id": str(row["id"]),
        "display_name": row.get("display_name"),
        "bio": row.get("bio"),
        "avatar_url": row.get("avatar_url"),
        "cover_url": row.get("cover_url"),
        "followers_count": int(row.get("followers_count") or 0),
        "following_count": int(row.get("following_count") or 0),
        "posts_count": int(row.get("posts_count") or 0),
    }


def discovery_pagination(limit, offset):
    limit = max(1, min(int(limit), 50))
    offset = max(0, int(offset))
    return limit, offset


def discovery_search_pattern(value):
    value = (value or "").strip()
    if not value:
        return None

    # Escape SQL LIKE wildcards so user input is treated literally.
    value = value.replace("\\", "\\\\")
    value = value.replace("%", "\\%").replace("_", "\\_")
    return "%" + value + "%"


@app.get("/api/v1/discovery/search")
def global_discovery_search(
    q: str = Query(..., min_length=2, max_length=100),
    search_type: str = Query("all", pattern="^(all|users|posts)$"),
    limit: int = Query(20, ge=1, le=50),
    offset: int = Query(0, ge=0),
    authorization: Optional[str] = Header(None),
):
    user = global_user(authorization)
    require_global_schema()

    limit, offset = discovery_pagination(limit, offset)
    pattern = discovery_search_pattern(q)

    if not pattern:
        raise HTTPException(status_code=400, detail="عبارت جست‌وجو معتبر نیست")

    result = {"query": q.strip(), "users": [], "posts": []}

    with get_db() as conn:
        with conn.cursor() as cursor:

            if search_type in ("all", "users"):
                cursor.execute(
                    """
                    SELECT
                        u.id,
                        p.display_name,
                        p.bio,
                        p.avatar_url,
                        p.cover_url,
                        (
                            SELECT COUNT(*)
                            FROM mg_social_follows f
                            WHERE f.following_id = u.id
                        ) AS followers_count,
                        (
                            SELECT COUNT(*)
                            FROM mg_social_follows f
                            WHERE f.follower_id = u.id
                        ) AS following_count,
                        (
                            SELECT COUNT(*)
                            FROM mg_social_posts sp
                            WHERE sp.user_id = u.id
                              AND sp.deleted_at IS NULL
                        ) AS posts_count
                    FROM mg_users u
                    JOIN mg_user_profiles p ON p.user_id = u.id
                    WHERE u.id <> %s
                      AND p.profile_visibility = 'public'
                      AND (
                          p.display_name ILIKE %s ESCAPE '\\'
                          OR COALESCE(p.bio, '') ILIKE %s ESCAPE '\\'
                      )
                    ORDER BY followers_count DESC, p.display_name ASC
                    LIMIT %s OFFSET %s
                    """,
                    (user["id"], pattern, pattern, limit, offset),
                )

                result["users"] = [
                    discovery_user_dict(row)
                    for row in cursor.fetchall()
                ]

            if search_type in ("all", "posts"):
                cursor.execute(
                    """
                    SELECT
                        sp.id,
                        sp.user_id,
                        sp.content,
                        sp.media_url,
                        sp.created_at,
                        p.display_name,
                        p.avatar_url,
                        (
                            SELECT COUNT(*)
                            FROM mg_social_likes sl
                            WHERE sl.post_id = sp.id
                        ) AS likes_count,
                        (
                            SELECT COUNT(*)
                            FROM mg_social_comments sc
                            WHERE sc.post_id = sp.id
                        ) AS comments_count,
                        (
                            SELECT COUNT(*) * 2
                            FROM mg_social_likes sl
                            WHERE sl.post_id = sp.id
                        ) +
                        (
                            SELECT COUNT(*)
                            FROM mg_social_comments sc
                            WHERE sc.post_id = sp.id
                        ) AS engagement_score
                    FROM mg_social_posts sp
                    JOIN mg_user_profiles p ON p.user_id = sp.user_id
                    WHERE sp.visibility = 'public'
                      AND sp.deleted_at IS NULL
                      AND p.profile_visibility = 'public'
                      AND sp.content ILIKE %s ESCAPE '\\'
                    ORDER BY sp.created_at DESC
                    LIMIT %s OFFSET %s
                    """,
                    (pattern, limit, offset),
                )

                result["posts"] = [
                    discovery_post_dict(row)
                    for row in cursor.fetchall()
                ]

    return {
        "success": True,
        "data": result,
        "pagination": {
            "limit": limit,
            "offset": offset,
        },
    }


@app.get("/api/v1/discovery/trending")
def global_discovery_trending(
    limit: int = Query(20, ge=1, le=50),
    offset: int = Query(0, ge=0),
    authorization: Optional[str] = Header(None),
):
    user = global_user(authorization)
    require_global_schema()

    limit, offset = discovery_pagination(limit, offset)

    with get_db() as conn:
        with conn.cursor() as cursor:
            cursor.execute(
                """
                SELECT
                    sp.id,
                    sp.user_id,
                    sp.content,
                    sp.media_url,
                    sp.created_at,
                    p.display_name,
                    p.avatar_url,
                    (
                        SELECT COUNT(*)
                        FROM mg_social_likes sl
                        WHERE sl.post_id = sp.id
                    ) AS likes_count,
                    (
                        SELECT COUNT(*)
                        FROM mg_social_comments sc
                        WHERE sc.post_id = sp.id
                    ) AS comments_count,
                    (
                        (
                            SELECT COUNT(*)
                            FROM mg_social_likes sl
                            WHERE sl.post_id = sp.id
                        ) * 2
                        +
                        (
                            SELECT COUNT(*)
                            FROM mg_social_comments sc
                            WHERE sc.post_id = sp.id
                        ) * 3
                    )::DOUBLE PRECISION
                    /
                    GREATEST(
                        1,
                        EXTRACT(EPOCH FROM (NOW() - sp.created_at)) / 3600 + 2
                    ) AS engagement_score
                FROM mg_social_posts sp
                JOIN mg_user_profiles p ON p.user_id = sp.user_id
                WHERE sp.visibility = 'public'
                  AND sp.deleted_at IS NULL
                  AND p.profile_visibility = 'public'
                  AND sp.created_at >= NOW() - INTERVAL '30 days'
                ORDER BY engagement_score DESC, sp.created_at DESC
                LIMIT %s OFFSET %s
                """,
                (limit, offset),
            )

            posts = [
                discovery_post_dict(row)
                for row in cursor.fetchall()
            ]

    return {
        "success": True,
        "data": posts,
        "algorithm": "engagement_recency_v1",
        "pagination": {
            "limit": limit,
            "offset": offset,
        },
    }


@app.get("/api/v1/discovery/latest")
def global_discovery_latest(
    limit: int = Query(20, ge=1, le=50),
    offset: int = Query(0, ge=0),
    authorization: Optional[str] = Header(None),
):
    user = global_user(authorization)
    require_global_schema()

    limit, offset = discovery_pagination(limit, offset)

    with get_db() as conn:
        with conn.cursor() as cursor:
            cursor.execute(
                """
                SELECT
                    sp.id,
                    sp.user_id,
                    sp.content,
                    sp.media_url,
                    sp.created_at,
                    p.display_name,
                    p.avatar_url,
                    (
                        SELECT COUNT(*)
                        FROM mg_social_likes sl
                        WHERE sl.post_id = sp.id
                    ) AS likes_count,
                    (
                        SELECT COUNT(*)
                        FROM mg_social_comments sc
                        WHERE sc.post_id = sp.id
                    ) AS comments_count,
                    0::DOUBLE PRECISION AS engagement_score
                FROM mg_social_posts sp
                JOIN mg_user_profiles p ON p.user_id = sp.user_id
                WHERE sp.visibility = 'public'
                  AND sp.deleted_at IS NULL
                  AND p.profile_visibility = 'public'
                ORDER BY sp.created_at DESC
                LIMIT %s OFFSET %s
                """,
                (limit, offset),
            )

            posts = [
                discovery_post_dict(row)
                for row in cursor.fetchall()
            ]

    return {
        "success": True,
        "data": posts,
        "pagination": {
            "limit": limit,
            "offset": offset,
        },
    }


@app.get("/api/v1/discovery/creators")
def global_discovery_creators(
    limit: int = Query(20, ge=1, le=50),
    offset: int = Query(0, ge=0),
    authorization: Optional[str] = Header(None),
):
    user = global_user(authorization)
    require_global_schema()

    limit, offset = discovery_pagination(limit, offset)

    with get_db() as conn:
        with conn.cursor() as cursor:
            cursor.execute(
                """
                SELECT
                    u.id,
                    p.display_name,
                    p.bio,
                    p.avatar_url,
                    p.cover_url,
                    (
                        SELECT COUNT(*)
                        FROM mg_social_follows f
                        WHERE f.following_id = u.id
                    ) AS followers_count,
                    (
                        SELECT COUNT(*)
                        FROM mg_social_follows f
                        WHERE f.follower_id = u.id
                    ) AS following_count,
                    (
                        SELECT COUNT(*)
                        FROM mg_social_posts sp
                        WHERE sp.user_id = u.id
                          AND sp.deleted_at IS NULL
                    ) AS posts_count
                FROM mg_users u
                JOIN mg_user_profiles p ON p.user_id = u.id
                WHERE p.profile_visibility = 'public'
                ORDER BY followers_count DESC, posts_count DESC
                LIMIT %s OFFSET %s
                """,
                (limit, offset),
            )

            creators = [
                discovery_user_dict(row)
                for row in cursor.fetchall()
            ]

    return {
        "success": True,
        "data": creators,
        "pagination": {
            "limit": limit,
            "offset": offset,
        },
    }


@app.get("/api/v1/discovery/popular")
def global_discovery_popular(
    period: str = Query("7d", pattern="^(24h|7d|30d|all)$"),
    limit: int = Query(20, ge=1, le=50),
    offset: int = Query(0, ge=0),
    authorization: Optional[str] = Header(None),
):
    user = global_user(authorization)
    require_global_schema()

    limit, offset = discovery_pagination(limit, offset)

    intervals = {
        "24h": "24 hours",
        "7d": "7 days",
        "30d": "30 days",
        "all": None,
    }

    interval = intervals[period]

    with get_db() as conn:
        with conn.cursor() as cursor:
            if interval:
                cursor.execute(
                    """
                    SELECT
                        sp.id,
                        sp.user_id,
                        sp.content,
                        sp.media_url,
                        sp.created_at,
                        p.display_name,
                        p.avatar_url,
                        (
                            SELECT COUNT(*)
                            FROM mg_social_likes sl
                            WHERE sl.post_id = sp.id
                        ) AS likes_count,
                        (
                            SELECT COUNT(*)
                            FROM mg_social_comments sc
                            WHERE sc.post_id = sp.id
                        ) AS comments_count,
                        (
                            (
                                SELECT COUNT(*)
                                FROM mg_social_likes sl
                                WHERE sl.post_id = sp.id
                            ) * 2
                            +
                            (
                                SELECT COUNT(*)
                                FROM mg_social_comments sc
                                WHERE sc.post_id = sp.id
                            ) * 3
                        )::DOUBLE PRECISION AS engagement_score
                    FROM mg_social_posts sp
                    JOIN mg_user_profiles p ON p.user_id = sp.user_id
                    WHERE sp.visibility = 'public'
                      AND sp.deleted_at IS NULL
                      AND p.profile_visibility = 'public'
                      AND sp.created_at >= NOW() - %s::INTERVAL
                    ORDER BY engagement_score DESC, sp.created_at DESC
                    LIMIT %s OFFSET %s
                    """,
                    (interval, limit, offset),
                )
            else:
                cursor.execute(
                    """
                    SELECT
                        sp.id,
                        sp.user_id,
                        sp.content,
                        sp.media_url,
                        sp.created_at,
                        p.display_name,
                        p.avatar_url,
                        (
                            SELECT COUNT(*)
                            FROM mg_social_likes sl
                            WHERE sl.post_id = sp.id
                        ) AS likes_count,
                        (
                            SELECT COUNT(*)
                            FROM mg_social_comments sc
                            WHERE sc.post_id = sp.id
                        ) AS comments_count,
                        (
                            (
                                SELECT COUNT(*)
                                FROM mg_social_likes sl
                                WHERE sl.post_id = sp.id
                            ) * 2
                            +
                            (
                                SELECT COUNT(*)
                                FROM mg_social_comments sc
                                WHERE sc.post_id = sp.id
                            ) * 3
                        )::DOUBLE PRECISION AS engagement_score
                    FROM mg_social_posts sp
                    JOIN mg_user_profiles p ON p.user_id = sp.user_id
                    WHERE sp.visibility = 'public'
                      AND sp.deleted_at IS NULL
                      AND p.profile_visibility = 'public'
                    ORDER BY engagement_score DESC, sp.created_at DESC
                    LIMIT %s OFFSET %s
                    """,
                    (limit, offset),
                )

            posts = [
                discovery_post_dict(row)
                for row in cursor.fetchall()
            ]

    return {
        "success": True,
        "period": period,
        "data": posts,
        "pagination": {
            "limit": limit,
            "offset": offset,
        },
    }


# ============================================================
# END SECTION 6
# NEXT: GLOBAL PRIVACY / BLOCKING / ACCOUNT SAFETY ENGINE
# ============================================================

# ============================================================
# MASIH GRAM GLOBAL
# SECTION 7 — PRIVACY & ACCOUNT SECURITY ENGINE
# ============================================================

import uuid as privacy_uuid
import secrets as privacy_secrets

from fastapi import Query
from pydantic import BaseModel, Field


PRIVACY_ENGINE_VERSION = "1.0.0"


# ------------------------------------------------------------
# REQUEST MODELS
# ------------------------------------------------------------

class PrivacySettingsUpdate(BaseModel):
    private_account: Optional[bool] = None
    allow_messages_from: Optional[str] = Field(
        default=None,
        pattern="^(everyone|followers|nobody)$"
    )
    allow_comments_from: Optional[str] = Field(
        default=None,
        pattern="^(everyone|followers|nobody)$"
    )
    show_followers: Optional[bool] = None
    show_following: Optional[bool] = None
    show_online_status: Optional[bool] = None
    allow_search: Optional[bool] = None


class PrivacyBlockRequest(BaseModel):
    user_id: str = Field(..., min_length=1, max_length=64)
    reason: Optional[str] = Field(default=None, max_length=300)


class PrivacyFollowDecision(BaseModel):
    decision: str = Field(..., pattern="^(accept|reject)$")


# ------------------------------------------------------------
# VALIDATION AND DATABASE HELPERS
# ------------------------------------------------------------

def privacy_uuid_value(value):
    try:
        return privacy_uuid.UUID(str(value))
    except (ValueError, TypeError, AttributeError):
        raise HTTPException(
            status_code=400,
            detail="شناسه کاربر معتبر نیست"
        )


def privacy_require_user(authorization):
    user = global_user(authorization)
    if not user or not user.get("id"):
        raise HTTPException(status_code=401, detail="احراز هویت نامعتبر است")
    return user


def privacy_require_schema(cursor):
    cursor.execute("""
        SELECT table_name
        FROM information_schema.tables
        WHERE table_schema = current_schema()
          AND table_name IN (
              'mg_privacy_settings',
              'mg_privacy_blocks',
              'mg_follow_requests',
              'mg_security_events'
          )
    """)
    found = {row["table_name"] for row in cursor.fetchall()}

    required = {
        "mg_privacy_settings",
        "mg_privacy_blocks",
        "mg_follow_requests",
        "mg_security_events",
    }

    if found != required:
        raise HTTPException(
            status_code=503,
            detail="مهاجرت بخش امنیت و حریم خصوصی اجرا نشده است"
        )


def privacy_log_event(
    cursor,
    user_id,
    event_type,
    target_user_id=None,
    metadata=None
):
    cursor.execute(
        """
        INSERT INTO mg_security_events
        (user_id, target_user_id, event_type, metadata, created_at)
        VALUES (%s, %s, %s, %s, NOW())
        """,
        (
            user_id,
            target_user_id,
            event_type,
            json.dumps(metadata or {}, ensure_ascii=False),
        ),
    )


def privacy_get_settings(cursor, user_id):
    cursor.execute(
        """
        SELECT *
        FROM mg_privacy_settings
        WHERE user_id = %s
        """,
        (user_id,),
    )

    row = cursor.fetchone()

    if row:
        return row

    cursor.execute(
        """
        INSERT INTO mg_privacy_settings (user_id)
        VALUES (%s)
        ON CONFLICT (user_id) DO NOTHING
        """,
        (user_id,),
    )

    cursor.execute(
        """
        SELECT *
        FROM mg_privacy_settings
        WHERE user_id = %s
        """,
        (user_id,),
    )

    return cursor.fetchone()


def privacy_is_blocked(cursor, user_a, user_b):
    cursor.execute(
        """
        SELECT 1
        FROM mg_privacy_blocks
        WHERE (blocker_id = %s AND blocked_id = %s)
           OR (blocker_id = %s AND blocked_id = %s)
        LIMIT 1
        """,
        (user_a, user_b, user_b, user_a),
    )
    return cursor.fetchone() is not None


def privacy_is_following(cursor, follower_id, following_id):
    cursor.execute(
        """
        SELECT 1
        FROM mg_social_follows
        WHERE follower_id = %s
          AND following_id = %s
        LIMIT 1
        """,
        (follower_id, following_id),
    )
    return cursor.fetchone() is not None


def privacy_can_view_profile(cursor, viewer_id, owner_id):
    if str(viewer_id) == str(owner_id):
        return True

    if privacy_is_blocked(cursor, viewer_id, owner_id):
        return False

    cursor.execute(
        """
        SELECT profile_visibility
        FROM mg_user_profiles
        WHERE user_id = %s
        """,
        (owner_id,),
    )
    profile = cursor.fetchone()

    if not profile:
        return False

    settings = privacy_get_settings(cursor, owner_id)

    if profile["profile_visibility"] == "private":
        return privacy_is_following(cursor, viewer_id, owner_id)

    if settings["private_account"]:
        return privacy_is_following(cursor, viewer_id, owner_id)

    return True


# ------------------------------------------------------------
# ADMIN DATABASE MIGRATION
# ------------------------------------------------------------

@app.post("/api/v1/admin/migrations/privacy/apply")
def apply_privacy_migration(
    x_admin_key: Optional[str] = Header(None, alias="x-admin-key")
):
    configured_key = os.getenv("ADMIN_API_KEY")

    if not configured_key:
        raise HTTPException(
            status_code=503,
            detail="کلید مدیریت در سرور تنظیم نشده است"
        )

    if not x_admin_key or not privacy_secrets.compare_digest(
        str(x_admin_key),
        str(configured_key)
    ):
        raise HTTPException(
            status_code=403,
            detail="دسترسی مدیریت مجاز نیست"
        )

    statements = [
        """
        CREATE TABLE IF NOT EXISTS mg_privacy_settings (
            user_id UUID PRIMARY KEY REFERENCES mg_users(id) ON DELETE CASCADE,
            private_account BOOLEAN NOT NULL DEFAULT FALSE,
            allow_messages_from VARCHAR(20) NOT NULL DEFAULT 'everyone',
            allow_comments_from VARCHAR(20) NOT NULL DEFAULT 'everyone',
            show_followers BOOLEAN NOT NULL DEFAULT TRUE,
            show_following BOOLEAN NOT NULL DEFAULT TRUE,
            show_online_status BOOLEAN NOT NULL DEFAULT TRUE,
            allow_search BOOLEAN NOT NULL DEFAULT TRUE,
            created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
            updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
            CHECK (allow_messages_from IN ('everyone','followers','nobody')),
            CHECK (allow_comments_from IN ('everyone','followers','nobody'))
        )
        """,
        """
        CREATE TABLE IF NOT EXISTS mg_privacy_blocks (
            id UUID PRIMARY KEY,
            blocker_id UUID NOT NULL REFERENCES mg_users(id) ON DELETE CASCADE,
            blocked_id UUID NOT NULL REFERENCES mg_users(id) ON DELETE CASCADE,
            reason VARCHAR(300),
            created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
            UNIQUE (blocker_id, blocked_id),
            CHECK (blocker_id <> blocked_id)
        )
        """,
        """
        CREATE INDEX IF NOT EXISTS idx_privacy_blocks_blocker
        ON mg_privacy_blocks(blocker_id, created_at DESC)
        """,
        """
        CREATE INDEX IF NOT EXISTS idx_privacy_blocks_blocked
        ON mg_privacy_blocks(blocked_id)
        """,
        """
        CREATE TABLE IF NOT EXISTS mg_follow_requests (
            id UUID PRIMARY KEY,
            requester_id UUID NOT NULL REFERENCES mg_users(id) ON DELETE CASCADE,
            target_id UUID NOT NULL REFERENCES mg_users(id) ON DELETE CASCADE,
            status VARCHAR(20) NOT NULL DEFAULT 'pending',
            created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
            reviewed_at TIMESTAMPTZ,
            UNIQUE (requester_id, target_id),
            CHECK (requester_id <> target_id),
            CHECK (status IN ('pending','accepted','rejected','cancelled'))
        )
        """,
        """
        CREATE INDEX IF NOT EXISTS idx_follow_requests_target
        ON mg_follow_requests(target_id, status, created_at DESC)
        """,
        """
        CREATE INDEX IF NOT EXISTS idx_follow_requests_requester
        ON mg_follow_requests(requester_id, created_at DESC)
        """,
        """
        CREATE TABLE IF NOT EXISTS mg_security_events (
            id BIGSERIAL PRIMARY KEY,
            user_id UUID REFERENCES mg_users(id) ON DELETE SET NULL,
            target_user_id UUID REFERENCES mg_users(id) ON DELETE SET NULL,
            event_type VARCHAR(80) NOT NULL,
            metadata JSONB NOT NULL DEFAULT '{}'::jsonb,
            created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
        )
        """,
        """
        CREATE INDEX IF NOT EXISTS idx_security_events_user
        ON mg_security_events(user_id, created_at DESC)
        """,
        """
        CREATE INDEX IF NOT EXISTS idx_security_events_type
        ON mg_security_events(event_type, created_at DESC)
        """,
    ]

    with get_db() as conn:
        with conn.cursor() as cursor:
            for statement in statements:
                cursor.execute(statement)

    return {
        "success": True,
        "migration": "privacy_security_engine",
        "version": PRIVACY_ENGINE_VERSION,
        "message": "ساختار دیتابیس حریم خصوصی ایجاد شد"
    }


# ------------------------------------------------------------
# PRIVACY SETTINGS
# ------------------------------------------------------------

@app.get("/api/v1/privacy/settings")
def get_my_privacy_settings(
    authorization: Optional[str] = Header(None)
):
    user = privacy_require_user(authorization)

    with get_db() as conn:
        with conn.cursor() as cursor:
            privacy_require_schema(cursor)
            settings = privacy_get_settings(cursor, user["id"])

            return {
                "success": True,
                "settings": {
                    "private_account": settings["private_account"],
                    "allow_messages_from": settings["allow_messages_from"],
                    "allow_comments_from": settings["allow_comments_from"],
                    "show_followers": settings["show_followers"],
                    "show_following": settings["show_following"],
                    "show_online_status": settings["show_online_status"],
                    "allow_search": settings["allow_search"],
                }
            }


@app.patch("/api/v1/privacy/settings")
def update_my_privacy_settings(
    payload: PrivacySettingsUpdate,
    authorization: Optional[str] = Header(None)
):
    user = privacy_require_user(authorization)
    changes = payload.dict(exclude_unset=True)

    if not changes:
        raise HTTPException(
            status_code=400,
            detail="هیچ تنظیمی برای تغییر ارسال نشده است"
        )

    allowed = {
        "private_account",
        "allow_messages_from",
        "allow_comments_from",
        "show_followers",
        "show_following",
        "show_online_status",
        "allow_search",
    }

    if not set(changes).issubset(allowed):
        raise HTTPException(status_code=400, detail="تنظیم نامعتبر است")

    with get_db() as conn:
        with conn.cursor() as cursor:
            privacy_require_schema(cursor)
            privacy_get_settings(cursor, user["id"])

            assignments = []
            values = []

            for key, value in changes.items():
                assignments.append(key + " = %s")
                values.append(value)

            assignments.append("updated_at = NOW()")
            values.append(user["id"])

            cursor.execute(
                """
                UPDATE mg_privacy_settings
                SET """ + ", ".join(assignments) + """
                WHERE user_id = %s
                RETURNING *
                """,
                tuple(values),
            )

            updated = cursor.fetchone()

            if "private_account" in changes:
                cursor.execute(
                    """
                    UPDATE mg_user_profiles
                    SET profile_visibility = %s
                    WHERE user_id = %s
                    """,
                    (
                        "private" if changes["private_account"] else "public",
                        user["id"],
                    ),
                )

            privacy_log_event(
                cursor,
                user["id"],
                "privacy_settings_updated",
                metadata={"changed_fields": list(changes.keys())},
            )

    return {
        "success": True,
        "settings": {
            key: updated[key]
            for key in allowed
        }
    }


# ------------------------------------------------------------
# BLOCK / UNBLOCK
# ------------------------------------------------------------

@app.post("/api/v1/privacy/block")
def block_global_user(
    payload: PrivacyBlockRequest,
    authorization: Optional[str] = Header(None)
):
    user = privacy_require_user(authorization)
    target_id = privacy_uuid_value(payload.user_id)

    if str(target_id) == str(user["id"]):
        raise HTTPException(
            status_code=400,
            detail="نمی‌توانید حساب خودتان را مسدود کنید"
        )

    with get_db() as conn:
        with conn.cursor() as cursor:
            privacy_require_schema(cursor)

            cursor.execute(
                "SELECT id FROM mg_users WHERE id = %s",
                (target_id,),
            )

            if not cursor.fetchone():
                raise HTTPException(
                    status_code=404,
                    detail="کاربر پیدا نشد"
                )

            cursor.execute(
                """
                SELECT id
                FROM mg_privacy_blocks
                WHERE blocker_id = %s AND blocked_id = %s
                """,
                (user["id"], target_id),
            )

            if cursor.fetchone():
                return {
                    "success": True,
                    "already_blocked": True
                }

            cursor.execute(
                """
                INSERT INTO mg_privacy_blocks
                (id, blocker_id, blocked_id, reason)
                VALUES (%s, %s, %s, %s)
                """,
                (
                    privacy_uuid.uuid4(),
                    user["id"],
                    target_id,
                    payload.reason,
                ),
            )

            cursor.execute(
                """
                DELETE FROM mg_follow_requests
                WHERE (requester_id = %s AND target_id = %s)
                   OR (requester_id = %s AND target_id = %s)
                """,
                (user["id"], target_id, target_id, user["id"]),
            )

            cursor.execute(
                """
                DELETE FROM mg_social_follows
                WHERE (follower_id = %s AND following_id = %s)
                   OR (follower_id = %s AND following_id = %s)
                """,
                (user["id"], target_id, target_id, user["id"]),
            )

            privacy_log_event(
                cursor,
                user["id"],
                "user_blocked",
                target_id,
            )

    return {
        "success": True,
        "blocked": True,
        "user_id": str(target_id)
    }


@app.delete("/api/v1/privacy/block/{target_user_id}")
def unblock_global_user(
    target_user_id: str,
    authorization: Optional[str] = Header(None)
):
    user = privacy_require_user(authorization)
    target_id = privacy_uuid_value(target_user_id)

    with get_db() as conn:
        with conn.cursor() as cursor:
            privacy_require_schema(cursor)

            cursor.execute(
                """
                DELETE FROM mg_privacy_blocks
                WHERE blocker_id = %s AND blocked_id = %s
                RETURNING id
                """,
                (user["id"], target_id),
            )

            removed = cursor.fetchone()

            if removed:
                privacy_log_event(
                    cursor,
                    user["id"],
                    "user_unblocked",
                    target_id,
                )

    return {
        "success": True,
        "unblocked": removed is not None
    }


@app.get("/api/v1/privacy/blocked")
def list_blocked_users(
    limit: int = Query(30, ge=1, le=100),
    offset: int = Query(0, ge=0),
    authorization: Optional[str] = Header(None)
):
    user = privacy_require_user(authorization)

    with get_db() as conn:
        with conn.cursor() as cursor:
            privacy_require_schema(cursor)

            cursor.execute(
                """
                SELECT
                    b.blocked_id,
                    b.reason,
                    b.created_at,
                    p.display_name,
                    p.avatar_url
                FROM mg_privacy_blocks b
                LEFT JOIN mg_user_profiles p
                    ON p.user_id = b.blocked_id
                WHERE b.blocker_id = %s
                ORDER BY b.created_at DESC
                LIMIT %s OFFSET %s
                """,
                (user["id"], limit, offset),
            )

            rows = cursor.fetchall()

    return {
        "success": True,
        "data": [
            {
                "user_id": str(row["blocked_id"]),
                "display_name": row["display_name"],
                "avatar_url": row["avatar_url"],
                "reason": row["reason"],
                "blocked_at": row["created_at"].isoformat(),
            }
            for row in rows
        ],
        "pagination": {
            "limit": limit,
            "offset": offset
        }
    }


# ------------------------------------------------------------
# FOLLOW REQUEST SYSTEM
# ------------------------------------------------------------

@app.post("/api/v1/privacy/follow/{target_user_id}")
def privacy_follow_user(
    target_user_id: str,
    authorization: Optional[str] = Header(None)
):
    user = privacy_require_user(authorization)
    target_id = privacy_uuid_value(target_user_id)

    if str(target_id) == str(user["id"]):
        raise HTTPException(status_code=400, detail="عملیات نامعتبر است")

    with get_db() as conn:
        with conn.cursor() as cursor:
            privacy_require_schema(cursor)

            cursor.execute(
                "SELECT id FROM mg_users WHERE id = %s",
                (target_id,),
            )

            if not cursor.fetchone():
                raise HTTPException(status_code=404, detail="کاربر پیدا نشد")

            if privacy_is_blocked(cursor, user["id"], target_id):
                raise HTTPException(
                    status_code=403,
                    detail="امکان دنبال‌کردن این حساب وجود ندارد"
                )

            if privacy_is_following(cursor, user["id"], target_id):
                return {
                    "success": True,
                    "status": "already_following"
                }

            settings = privacy_get_settings(cursor, target_id)

            if settings["private_account"]:
                cursor.execute(
                    """
                    SELECT id, status
                    FROM mg_follow_requests
                    WHERE requester_id = %s AND target_id = %s
                    """,
                    (user["id"], target_id),
                )

                existing = cursor.fetchone()

                if existing and existing["status"] == "pending":
                    return {
                        "success": True,
                        "status": "pending"
                    }

                if existing:
                    cursor.execute(
                        """
                        UPDATE mg_follow_requests
                        SET status = 'pending',
                            created_at = NOW(),
                            reviewed_at = NULL
                        WHERE id = %s
                        """,
                        (existing["id"],),
                    )
                else:
                    cursor.execute(
                        """
                        INSERT INTO mg_follow_requests
                        (id, requester_id, target_id)
                        VALUES (%s, %s, %s)
                        """,
                        (privacy_uuid.uuid4(), user["id"], target_id),
                    )

                privacy_log_event(
                    cursor,
                    user["id"],
                    "follow_request_sent",
                    target_id,
                )

                return {
                    "success": True,
                    "status": "pending"
                }

            cursor.execute(
                """
                INSERT INTO mg_social_follows
                (follower_id, following_id)
                SELECT %s, %s
                WHERE NOT EXISTS (
                    SELECT 1 FROM mg_social_follows
                    WHERE follower_id = %s AND following_id = %s
                )
                """,
                (user["id"], target_id, user["id"], target_id),
            )

            privacy_log_event(
                cursor,
                user["id"],
                "user_followed",
                target_id,
            )

    return {
        "success": True,
        "status": "following"
    }


@app.get("/api/v1/privacy/follow-requests")
def get_incoming_follow_requests(
    limit: int = Query(30, ge=1, le=100),
    offset: int = Query(0, ge=0),
    authorization: Optional[str] = Header(None)
):
    user = privacy_require_user(authorization)

    with get_db() as conn:
        with conn.cursor() as cursor:
            privacy_require_schema(cursor)

            cursor.execute(
                """
                SELECT
                    r.id,
                    r.requester_id,
                    r.created_at,
                    p.display_name,
                    p.avatar_url
                FROM mg_follow_requests r
                LEFT JOIN mg_user_profiles p
                    ON p.user_id = r.requester_id
                WHERE r.target_id = %s
                  AND r.status = 'pending'
                ORDER BY r.created_at DESC
                LIMIT %s OFFSET %s
                """,
                (user["id"], limit, offset),
            )

            rows = cursor.fetchall()

    return {
        "success": True,
        "data": [
            {
                "request_id": str(row["id"]),
                "user_id": str(row["requester_id"]),
                "display_name": row["display_name"],
                "avatar_url": row["avatar_url"],
                "created_at": row["created_at"].isoformat(),
            }
            for row in rows
        ]
    }


@app.post("/api/v1/privacy/follow-requests/{request_id}/decision")
def decide_follow_request(
    request_id: str,
    payload: PrivacyFollowDecision,
    authorization: Optional[str] = Header(None)
):
    user = privacy_require_user(authorization)
    request_uuid = privacy_uuid_value(request_id)

    with get_db() as conn:
        with conn.cursor() as cursor:
            privacy_require_schema(cursor)

            cursor.execute(
                """
                SELECT id, requester_id, target_id, status
                FROM mg_follow_requests
                WHERE id = %s AND target_id = %s
                FOR UPDATE
                """,
                (request_uuid, user["id"]),
            )

            request_row = cursor.fetchone()

            if not request_row or request_row["status"] != "pending":
                raise HTTPException(
                    status_code=404,
                    detail="درخواست فعال پیدا نشد"
                )

            requester_id = request_row["requester_id"]

            if privacy_is_blocked(cursor, user["id"], requester_id):
                raise HTTPException(
                    status_code=403,
                    detail="این ارتباط به دلیل مسدودسازی امکان‌پذیر نیست"
                )

            if payload.decision == "accept":
                cursor.execute(
                    """
                    INSERT INTO mg_social_follows
                    (follower_id, following_id)
                    SELECT %s, %s
                    WHERE NOT EXISTS (
                        SELECT 1 FROM mg_social_follows
                        WHERE follower_id = %s AND following_id = %s
                    )
                    """,
                    (
                        requester_id,
                        user["id"],
                        requester_id,
                        user["id"],
                    ),
                )

                new_status = "accepted"
            else:
                new_status = "rejected"

            cursor.execute(
                """
                UPDATE mg_follow_requests
                SET status = %s, reviewed_at = NOW()
                WHERE id = %s
                """,
                (new_status, request_uuid),
            )

            privacy_log_event(
                cursor,
                user["id"],
                "follow_request_" + new_status,
                requester_id,
            )

    return {
        "success": True,
        "status": new_status
    }


@app.delete("/api/v1/privacy/follow-requests/{request_id}")
def cancel_follow_request(
    request_id: str,
    authorization: Optional[str] = Header(None)
):
    user = privacy_require_user(authorization)
    request_uuid = privacy_uuid_value(request_id)

    with get_db() as conn:
        with conn.cursor() as cursor:
            privacy_require_schema(cursor)

            cursor.execute(
                """
                UPDATE mg_follow_requests
                SET status = 'cancelled',
                    reviewed_at = NOW()
                WHERE id = %s
                  AND requester_id = %s
                  AND status = 'pending'
                RETURNING id
                """,
                (request_uuid, user["id"]),
            )

            removed = cursor.fetchone()

    return {
        "success": True,
        "cancelled": removed is not None
    }


# ------------------------------------------------------------
# PROFILE ACCESS CHECK
# ------------------------------------------------------------

@app.get("/api/v1/privacy/access/{target_user_id}")
def check_profile_access(
    target_user_id: str,
    authorization: Optional[str] = Header(None)
):
    user = privacy_require_user(authorization)
    target_id = privacy_uuid_value(target_user_id)

    with get_db() as conn:
        with conn.cursor() as cursor:
            privacy_require_schema(cursor)

            cursor.execute(
                "SELECT id FROM mg_users WHERE id = %s",
                (target_id,),
            )

            if not cursor.fetchone():
                raise HTTPException(status_code=404, detail="کاربر پیدا نشد")

            allowed = privacy_can_view_profile(
                cursor,
                user["id"],
                target_id,
            )

    return {
        "success": True,
        "can_view": allowed,
        "user_id": str(target_id)
    }


# ------------------------------------------------------------
# SECURITY EVENT HISTORY
# ------------------------------------------------------------

@app.get("/api/v1/privacy/security-events")
def get_my_security_events(
    limit: int = Query(30, ge=1, le=100),
    offset: int = Query(0, ge=0),
    authorization: Optional[str] = Header(None)
):
    user = privacy_require_user(authorization)

    with get_db() as conn:
        with conn.cursor() as cursor:
            privacy_require_schema(cursor)

            cursor.execute(
                """
                SELECT
                    id,
                    event_type,
                    target_user_id,
                    metadata,
                    created_at
                FROM mg_security_events
                WHERE user_id = %s
                ORDER BY created_at DESC
                LIMIT %s OFFSET %s
                """,
                (user["id"], limit, offset),
            )

            rows = cursor.fetchall()

    return {
        "success": True,
        "data": [
            {
                "id": row["id"],
                "event": row["event_type"],
                "target_user_id": (
                    str(row["target_user_id"])
                    if row["target_user_id"] else None
                ),
                "metadata": row["metadata"],
                "created_at": row["created_at"].isoformat(),
            }
            for row in rows
        ],
        "pagination": {
            "limit": limit,
            "offset": offset
        }
    }


# ============================================================
# END SECTION 7
# NEXT: GLOBAL MESSAGING PERMISSIONS & ANTI-SPAM ENGINE
# ============================================================

# ============================================================
# MASIH GRAM GLOBAL
# SECTION 8 — MESSAGING PERMISSIONS & ANTI-SPAM ENGINE
# ============================================================

import hashlib as messaging_hashlib
import uuid as messaging_uuid

from pydantic import BaseModel, Field


MESSAGING_ENGINE_VERSION = "1.0.0"

# Default protection limits.
# These are server-side policy values, not client-controlled.
MSG_MAX_PER_MINUTE = 8
MSG_MAX_PER_TEN_MINUTES = 30
MSG_MAX_PER_RECIPIENT_PER_HOUR = 12


# ------------------------------------------------------------
# REQUEST MODELS
# ------------------------------------------------------------

class MessagingPolicyUpdate(BaseModel):
    allow_messages_from: str = Field(
        ...,
        pattern="^(everyone|followers|nobody)$"
    )


class MessagingPermissionCheck(BaseModel):
    recipient_id: str = Field(..., min_length=1, max_length=64)


# ------------------------------------------------------------
# VALIDATION
# ------------------------------------------------------------

def messaging_user(authorization):
    user = global_user(authorization)

    if not user or not user.get("id"):
        raise HTTPException(
            status_code=401,
            detail="احراز هویت معتبر نیست"
        )

    return user


def messaging_uuid(value):
    try:
        return messaging_uuid.UUID(str(value))
    except (ValueError, TypeError, AttributeError):
        raise HTTPException(
            status_code=400,
            detail="شناسه کاربر معتبر نیست"
        )


def messaging_require_schema(cursor):
    cursor.execute("""
        SELECT table_name
        FROM information_schema.tables
        WHERE table_schema = current_schema()
          AND table_name IN (
              'mg_message_policies',
              'mg_message_rate_events',
              'mg_message_reports'
          )
    """)

    found = {row["table_name"] for row in cursor.fetchall()}

    required = {
        "mg_message_policies",
        "mg_message_rate_events",
        "mg_message_reports",
    }

    if found != required:
        raise HTTPException(
            status_code=503,
            detail="مهاجرت موتور پیام‌رسانی اجرا نشده است"
        )


# ------------------------------------------------------------
# DATABASE MIGRATION
# ------------------------------------------------------------

@app.post("/api/v1/admin/migrations/messaging/apply")
def apply_messaging_migration(
    x_admin_key: Optional[str] = Header(
        None,
        alias="x-admin-key"
    )
):
    configured_key = os.getenv("ADMIN_API_KEY")

    if not configured_key:
        raise HTTPException(
            status_code=503,
            detail="کلید مدیریت سرور تنظیم نشده است"
        )

    if not x_admin_key or not hmac.compare_digest(
        str(x_admin_key),
        str(configured_key)
    ):
        raise HTTPException(
            status_code=403,
            detail="دسترسی مدیریت مجاز نیست"
        )

    statements = [
        """
        CREATE TABLE IF NOT EXISTS mg_message_policies (
            user_id UUID PRIMARY KEY
                REFERENCES mg_users(id) ON DELETE CASCADE,
            allow_messages_from VARCHAR(20)
                NOT NULL DEFAULT 'everyone',
            updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
            CHECK (
                allow_messages_from IN (
                    'everyone',
                    'followers',
                    'nobody'
                )
            )
        )
        """,
        """
        CREATE TABLE IF NOT EXISTS mg_message_rate_events (
            id BIGSERIAL PRIMARY KEY,
            sender_id UUID NOT NULL
                REFERENCES mg_users(id) ON DELETE CASCADE,
            recipient_id UUID NOT NULL
                REFERENCES mg_users(id) ON DELETE CASCADE,
            idempotency_key VARCHAR(100),
            created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
            CHECK (sender_id <> recipient_id)
        )
        """,
        """
        CREATE UNIQUE INDEX IF NOT EXISTS
        idx_message_rate_idempotency
        ON mg_message_rate_events(sender_id, idempotency_key)
        WHERE idempotency_key IS NOT NULL
        """,
        """
        CREATE INDEX IF NOT EXISTS
        idx_message_rate_sender_time
        ON mg_message_rate_events(sender_id, created_at DESC)
        """,
        """
        CREATE INDEX IF NOT EXISTS
        idx_message_rate_recipient_time
        ON mg_message_rate_events(
            sender_id,
            recipient_id,
            created_at DESC
        )
        """,
        """
        CREATE TABLE IF NOT EXISTS mg_message_reports (
            id UUID PRIMARY KEY,
            reporter_id UUID NOT NULL
                REFERENCES mg_users(id) ON DELETE CASCADE,
            reported_user_id UUID NOT NULL
                REFERENCES mg_users(id) ON DELETE CASCADE,
            reason VARCHAR(80) NOT NULL,
            description VARCHAR(1000),
            status VARCHAR(20) NOT NULL DEFAULT 'pending',
            created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
            reviewed_at TIMESTAMPTZ,
            admin_note VARCHAR(1000),
            CHECK (reporter_id <> reported_user_id),
            CHECK (
                status IN (
                    'pending',
                    'reviewed',
                    'dismissed',
                    'action_taken'
                )
            )
        )
        """,
        """
        CREATE INDEX IF NOT EXISTS
        idx_message_reports_status
        ON mg_message_reports(status, created_at DESC)
        """,
    ]

    with get_db() as conn:
        with conn.cursor() as cursor:
            for statement in statements:
                cursor.execute(statement)

    return {
        "success": True,
        "migration": "messaging_permissions_antispam",
        "version": MESSAGING_ENGINE_VERSION,
    }


# ------------------------------------------------------------
# POLICY HELPERS
# ------------------------------------------------------------

def messaging_get_policy(cursor, user_id):
    cursor.execute(
        """
        INSERT INTO mg_message_policies(user_id)
        VALUES (%s)
        ON CONFLICT (user_id) DO NOTHING
        """,
        (user_id,),
    )

    cursor.execute(
        """
        SELECT allow_messages_from
        FROM mg_message_policies
        WHERE user_id = %s
        """,
        (user_id,),
    )

    row = cursor.fetchone()

    return row["allow_messages_from"] if row else "everyone"


def messaging_check_permission(
    cursor,
    sender_id,
    recipient_id
):
    if str(sender_id) == str(recipient_id):
        return {
            "allowed": False,
            "reason": "self_message_not_allowed"
        }

    cursor.execute(
        "SELECT id FROM mg_users WHERE id = %s",
        (recipient_id,),
    )

    if not cursor.fetchone():
        return {
            "allowed": False,
            "reason": "recipient_not_found"
        }

    # The privacy migration from Section 7 must exist.
    privacy_require_schema(cursor)

    if privacy_is_blocked(cursor, sender_id, recipient_id):
        return {
            "allowed": False,
            "reason": "blocked"
        }

    policy = messaging_get_policy(cursor, recipient_id)

    if policy == "nobody":
        return {
            "allowed": False,
            "reason": "messages_disabled"
        }

    if policy == "followers":
        if not privacy_is_following(
            cursor,
            sender_id,
            recipient_id
        ):
            return {
                "allowed": False,
                "reason": "followers_only"
            }

    return {
        "allowed": True,
        "reason": None
    }


# ------------------------------------------------------------
# ATOMIC RATE LIMIT RESERVATION
#
# IMPORTANT:
# Call this inside the same database transaction as the
# actual message insertion. Do not call it from a separate
# transaction and assume it guarantees message delivery.
# ------------------------------------------------------------

def messaging_reserve_send(
    cursor,
    sender_id,
    recipient_id,
    idempotency_key=None
):
    sender_id = messaging_uuid(sender_id)
    recipient_id = messaging_uuid(recipient_id)

    if sender_id == recipient_id:
        raise HTTPException(
            status_code=400,
            detail="ارسال پیام به حساب خودتان مجاز نیست"
        )

    if idempotency_key is not None:
        idempotency_key = str(idempotency_key).strip()

        if not idempotency_key or len(idempotency_key) > 100:
            raise HTTPException(
                status_code=400,
                detail="کلید درخواست تکراری معتبر نیست"
            )

        cursor.execute(
            """
            SELECT id
            FROM mg_message_rate_events
            WHERE sender_id = %s
              AND idempotency_key = %s
            """,
            (sender_id, idempotency_key),
        )

        if cursor.fetchone():
            return {
                "allowed": False,
                "duplicate": True,
                "reason": "duplicate_request"
            }

    permission = messaging_check_permission(
        cursor,
        sender_id,
        recipient_id
    )

    if not permission["allowed"]:
        raise HTTPException(
            status_code=403,
            detail={
                "code": permission["reason"],
                "message": "امکان ارسال پیام به این کاربر وجود ندارد"
            }
        )

    # Serialize concurrent sends from the same account.
    # PostgreSQL releases this transaction lock automatically.
    lock_key = messaging_hashlib.sha256(
        str(sender_id).encode("utf-8")
    ).hexdigest()[:16]

    lock_number = int(lock_key, 16)

    if lock_number >= 2 ** 63:
        lock_number -= 2 ** 64

    cursor.execute(
        "SELECT pg_advisory_xact_lock(%s)",
        (lock_number,),
    )

    cursor.execute(
        """
        SELECT
            COUNT(*) FILTER (
                WHERE created_at >= NOW() - INTERVAL '1 minute'
            ) AS minute_count,
            COUNT(*) FILTER (
                WHERE created_at >= NOW() - INTERVAL '10 minutes'
            ) AS ten_minute_count,
            COUNT(*) FILTER (
                WHERE recipient_id = %s
                  AND created_at >= NOW() - INTERVAL '1 hour'
            ) AS recipient_hour_count
        FROM mg_message_rate_events
        WHERE sender_id = %s
          AND created_at >= NOW() - INTERVAL '10 minutes'
        """,
        (recipient_id, sender_id),
    )

    counts = cursor.fetchone()

    if counts["minute_count"] >= MSG_MAX_PER_MINUTE:
        raise HTTPException(
            status_code=429,
            detail={
                "code": "message_rate_limit_minute",
                "message": "تعداد پیام‌های شما در این بازه بیش از حد مجاز است"
            },
            headers={"Retry-After": "60"},
        )

    if counts["ten_minute_count"] >= MSG_MAX_PER_TEN_MINUTES:
        raise HTTPException(
            status_code=429,
            detail={
                "code": "message_rate_limit_ten_minutes",
                "message": "برای ارسال پیام بیشتر کمی صبر کنید"
            },
            headers={"Retry-After": "600"},
        )

    if counts["recipient_hour_count"] >= MSG_MAX_PER_RECIPIENT_PER_HOUR:
        raise HTTPException(
            status_code=429,
            detail={
                "code": "recipient_rate_limit",
                "message": "ارسال پیام به این کاربر موقتاً محدود شده است"
            },
            headers={"Retry-After": "3600"},
        )

    cursor.execute(
        """
        INSERT INTO mg_message_rate_events(
            sender_id,
            recipient_id,
            idempotency_key
        )
        VALUES (%s, %s, %s)
        RETURNING id, created_at
        """,
        (sender_id, recipient_id, idempotency_key),
    )

    event = cursor.fetchone()

    return {
        "allowed": True,
        "duplicate": False,
        "reservation_id": event["id"],
        "created_at": event["created_at"].isoformat()
    }


# ------------------------------------------------------------
# USER MESSAGE POLICY
# ------------------------------------------------------------

@app.get("/api/v1/messaging/policy")
def get_my_messaging_policy(
    authorization: Optional[str] = Header(None)
):
    user = messaging_user(authorization)

    with get_db() as conn:
        with conn.cursor() as cursor:
            messaging_require_schema(cursor)

            policy = messaging_get_policy(
                cursor,
                user["id"]
            )

    return {
        "success": True,
        "allow_messages_from": policy
    }


@app.patch("/api/v1/messaging/policy")
def update_my_messaging_policy(
    payload: MessagingPolicyUpdate,
    authorization: Optional[str] = Header(None)
):
    user = messaging_user(authorization)

    with get_db() as conn:
        with conn.cursor() as cursor:
            messaging_require_schema(cursor)

            cursor.execute(
                """
                INSERT INTO mg_message_policies(
                    user_id,
                    allow_messages_from
                )
                VALUES (%s, %s)
                ON CONFLICT (user_id)
                DO UPDATE SET
                    allow_messages_from = EXCLUDED.allow_messages_from,
                    updated_at = NOW()
                RETURNING allow_messages_from, updated_at
                """,
                (
                    user["id"],
                    payload.allow_messages_from
                ),
            )

            row = cursor.fetchone()

    return {
        "success": True,
        "allow_messages_from": row["allow_messages_from"],
        "updated_at": row["updated_at"].isoformat()
    }


# ------------------------------------------------------------
# PRE-SEND PERMISSION CHECK
# This endpoint checks permission only.
# It does NOT send or reserve a message.
# ------------------------------------------------------------

@app.post("/api/v1/messaging/permission/check")
def check_messaging_permission_api(
    payload: MessagingPermissionCheck,
    authorization: Optional[str] = Header(None)
):
    user = messaging_user(authorization)
    recipient_id = messaging_uuid(payload.recipient_id)

    with get_db() as conn:
        with conn.cursor() as cursor:
            messaging_require_schema(cursor)

            result = messaging_check_permission(
                cursor,
                user["id"],
                recipient_id
            )

    return {
        "success": True,
        "allowed": result["allowed"],
        "reason": result["reason"]
    }


# ------------------------------------------------------------
# REPORT A MESSAGING ABUSE
# ------------------------------------------------------------

@app.post("/api/v1/messaging/reports")
def report_messaging_user(
    reported_user_id: str = Field(...),
    reason: str = Field(...),
    description: Optional[str] = None,
    authorization: Optional[str] = Header(None)
):
    user = messaging_user(authorization)
    target_id = messaging_uuid(reported_user_id)

    allowed_reasons = {
        "spam",
        "harassment",
        "impersonation",
        "scam",
        "other"
    }

    reason = str(reason).strip().lower()

    if reason not in allowed_reasons:
        raise HTTPException(
            status_code=400,
            detail="دلیل گزارش معتبر نیست"
        )

    if description is not None and len(description) > 1000:
        raise HTTPException(
            status_code=400,
            detail="توضیحات گزارش بیش از حد مجاز است"
        )

    if str(user["id"]) == str(target_id):
        raise HTTPException(
            status_code=400,
            detail="گزارش حساب خودتان مجاز نیست"
        )

    with get_db() as conn:
        with conn.cursor() as cursor:
            messaging_require_schema(cursor)

            cursor.execute(
                "SELECT id FROM mg_users WHERE id = %s",
                (target_id,),
            )

            if not cursor.fetchone():
                raise HTTPException(
                    status_code=404,
                    detail="کاربر پیدا نشد"
                )

            cursor.execute(
                """
                SELECT id
                FROM mg_message_reports
                WHERE reporter_id = %s
                  AND reported_user_id = %s
                  AND status = 'pending'
                LIMIT 1
                """,
                (user["id"], target_id),
            )

            if cursor.fetchone():
                return {
                    "success": True,
                    "already_reported": True
                }

            report_id = messaging_uuid.uuid4()

            cursor.execute(
                """
                INSERT INTO mg_message_reports(
                    id,
                    reporter_id,
                    reported_user_id,
                    reason,
                    description
                )
                VALUES (%s, %s, %s, %s, %s)
                """,
                (
                    report_id,
                    user["id"],
                    target_id,
                    reason,
                    description,
                ),
            )

    return {
        "success": True,
        "report_id": str(report_id),
        "status": "pending"
    }


# ------------------------------------------------------------
# USER REPORT HISTORY
# ------------------------------------------------------------

@app.get("/api/v1/messaging/reports/me")
def get_my_messaging_reports(
    limit: int = Query(30, ge=1, le=100),
    offset: int = Query(0, ge=0),
    authorization: Optional[str] = Header(None)
):
    user = messaging_user(authorization)

    with get_db() as conn:
        with conn.cursor() as cursor:
            messaging_require_schema(cursor)

            cursor.execute(
                """
                SELECT
                    id,
                    reported_user_id,
                    reason,
                    description,
                    status,
                    created_at,
                    reviewed_at
                FROM mg_message_reports
                WHERE reporter_id = %s
                ORDER BY created_at DESC
                LIMIT %s OFFSET %s
                """,
                (user["id"], limit, offset),
            )

            rows = cursor.fetchall()

    return {
        "success": True,
        "data": [
            {
                "id": str(row["id"]),
                "reported_user_id": str(row["reported_user_id"]),
                "reason": row["reason"],
                "description": row["description"],
                "status": row["status"],
                "created_at": row["created_at"].isoformat(),
                "reviewed_at": (
                    row["reviewed_at"].isoformat()
                    if row["reviewed_at"] else None
                )
            }
            for row in rows
        ],
        "pagination": {
            "limit": limit,
            "offset": offset
        }
    }


# ------------------------------------------------------------
# ADMIN REPORT QUEUE
# ------------------------------------------------------------

@app.get("/api/v1/admin/messaging/reports")
def admin_messaging_reports(
    status: str = Query("pending"),
    limit: int = Query(50, ge=1, le=100),
    offset: int = Query(0, ge=0),
    x_admin_key: Optional[str] = Header(
        None,
        alias="x-admin-key"
    )
):
    configured_key = os.getenv("ADMIN_API_KEY")

    if not configured_key or not x_admin_key or not hmac.compare_digest(
        str(x_admin_key),
        str(configured_key)
    ):
        raise HTTPException(
            status_code=403,
            detail="دسترسی مدیریت مجاز نیست"
        )

    allowed_statuses = {
        "pending",
        "reviewed",
        "dismissed",
        "action_taken",
        "all"
    }

    if status not in allowed_statuses:
        raise HTTPException(
            status_code=400,
            detail="وضعیت گزارش معتبر نیست"
        )

    with get_db() as conn:
        with conn.cursor() as cursor:
            messaging_require_schema(cursor)

            if status == "all":
                cursor.execute(
                    """
                    SELECT *
                    FROM mg_message_reports
                    ORDER BY created_at DESC
                    LIMIT %s OFFSET %s
                    """,
                    (limit, offset),
                )
            else:
                cursor.execute(
                    """
                    SELECT *
                    FROM mg_message_reports
                    WHERE status = %s
                    ORDER BY created_at DESC
                    LIMIT %s OFFSET %s
                    """,
                    (status, limit, offset),
                )

            rows = cursor.fetchall()

    return {
        "success": True,
        "data": [
            {
                "id": str(row["id"]),
                "reporter_id": str(row["reporter_id"]),
                "reported_user_id": str(row["reported_user_id"]),
                "reason": row["reason"],
                "description": row["description"],
                "status": row["status"],
                "created_at": row["created_at"].isoformat(),
            }
            for row in rows
        ],
        "pagination": {
            "limit": limit,
            "offset": offset
        }
    }


# ============================================================
# END SECTION 8
# NEXT: GLOBAL RELIABLE EVENT & NOTIFICATION DELIVERY ENGINE
# ============================================================

# ============================================================
# MASIH GRAM GLOBAL
# SECTION 9 — RELIABLE EVENT DELIVERY ENGINE
# Persistent Outbox / Retry / Idempotency / Worker Leases
# ============================================================

import re as event_re
import uuid as event_uuid


EVENT_ENGINE_VERSION = "1.0.0"

EVENT_MAX_BATCH = 100
EVENT_MAX_ATTEMPTS = 12
EVENT_DEFAULT_LEASE_SECONDS = 90
EVENT_MAX_LEASE_SECONDS = 600
EVENT_MAX_RETRY_SECONDS = 86400


# ------------------------------------------------------------
# REQUEST MODELS
# ------------------------------------------------------------

class EventAcknowledgeRequest(BaseModel):
    lease_token: str = Field(..., min_length=36, max_length=36)


class EventRetryRequest(BaseModel):
    lease_token: str = Field(..., min_length=36, max_length=36)
    error: str = Field(..., min_length=1, max_length=2000)
    retry_after_seconds: int = Field(
        default=30,
        ge=1,
        le=EVENT_MAX_RETRY_SECONDS
    )


# ------------------------------------------------------------
# VALIDATION
# ------------------------------------------------------------

def event_require_admin(x_admin_key):
    configured_key = os.getenv("ADMIN_API_KEY")

    if not configured_key:
        raise HTTPException(
            status_code=503,
            detail="کلید مدیریت سرور تنظیم نشده است"
        )

    if not x_admin_key or not hmac.compare_digest(
        str(x_admin_key),
        str(configured_key)
    ):
        raise HTTPException(
            status_code=403,
            detail="دسترسی سرویس مجاز نیست"
        )


def event_validate_type(value):
    value = str(value or "").strip().lower()

    if not event_re.fullmatch(r"[a-z0-9_.-]{2,100}", value):
        raise HTTPException(
            status_code=400,
            detail="نوع رویداد معتبر نیست"
        )

    return value


def event_validate_payload(payload):
    if not isinstance(payload, dict):
        raise HTTPException(
            status_code=400,
            detail="محتوای رویداد باید یک شیء JSON باشد"
        )

    try:
        encoded = json.dumps(
            payload,
            ensure_ascii=False,
            separators=(",", ":"),
            allow_nan=False
        )
    except (TypeError, ValueError):
        raise HTTPException(
            status_code=400,
            detail="محتوای رویداد قابل تبدیل به JSON نیست"
        )

    if len(encoded.encode("utf-8")) > 65536:
        raise HTTPException(
            status_code=413,
            detail="حجم محتوای رویداد بیش از حد مجاز است"
        )

    return encoded


def event_require_schema(cursor):
    cursor.execute("""
        SELECT table_name
        FROM information_schema.tables
        WHERE table_schema = current_schema()
          AND table_name = 'mg_event_outbox'
    """)

    if not cursor.fetchone():
        raise HTTPException(
            status_code=503,
            detail="مهاجرت موتور رویداد اجرا نشده است"
        )


# ------------------------------------------------------------
# DATABASE MIGRATION
# ------------------------------------------------------------

@app.post("/api/v1/admin/migrations/events/apply")
def apply_event_engine_migration(
    x_admin_key: Optional[str] = Header(
        None,
        alias="x-admin-key"
    )
):
    event_require_admin(x_admin_key)

    statements = [
        """
        CREATE TABLE IF NOT EXISTS mg_event_outbox (
            id BIGSERIAL PRIMARY KEY,
            event_id UUID NOT NULL UNIQUE,
            event_type VARCHAR(100) NOT NULL,
            payload JSONB NOT NULL DEFAULT '{}'::jsonb,
            idempotency_key VARCHAR(180),
            status VARCHAR(20) NOT NULL DEFAULT 'pending',
            attempts INTEGER NOT NULL DEFAULT 0,
            max_attempts INTEGER NOT NULL DEFAULT 12,
            available_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
            lease_token UUID,
            lease_until TIMESTAMPTZ,
            delivered_at TIMESTAMPTZ,
            last_error TEXT,
            created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
            updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
            CHECK (
                status IN (
                    'pending',
                    'processing',
                    'delivered',
                    'dead'
                )
            ),
            CHECK (attempts >= 0),
            CHECK (max_attempts BETWEEN 1 AND 100)
        )
        """,
        """
        CREATE UNIQUE INDEX IF NOT EXISTS
        idx_event_outbox_idempotency
        ON mg_event_outbox(idempotency_key)
        WHERE idempotency_key IS NOT NULL
        """,
        """
        CREATE INDEX IF NOT EXISTS
        idx_event_outbox_pending
        ON mg_event_outbox(available_at, created_at)
        WHERE status = 'pending'
        """,
        """
        CREATE INDEX IF NOT EXISTS
        idx_event_outbox_processing
        ON mg_event_outbox(lease_until)
        WHERE status = 'processing'
        """,
        """
        CREATE INDEX IF NOT EXISTS
        idx_event_outbox_delivered
        ON mg_event_outbox(delivered_at DESC)
        WHERE status = 'delivered'
        """,
    ]

    with get_db() as conn:
        with conn.cursor() as cursor:
            for statement in statements:
                cursor.execute(statement)

    return {
        "success": True,
        "migration": "reliable_event_delivery",
        "version": EVENT_ENGINE_VERSION
    }


# ------------------------------------------------------------
# INTERNAL EVENT CREATION
#
# Call inside the same database transaction as the business
# operation that creates the event.
#
# Example:
# global_enqueue_event(
#     cursor,
#     "message.created",
#     {"message_id": str(message_id)},
#     "message-created-" + str(message_id)
# )
# ------------------------------------------------------------

def global_enqueue_event(
    cursor,
    event_type,
    payload,
    idempotency_key=None,
    max_attempts=EVENT_MAX_ATTEMPTS,
    available_seconds=0
):
    event_type = event_validate_type(event_type)
    encoded_payload = event_validate_payload(payload)

    if idempotency_key is not None:
        idempotency_key = str(idempotency_key).strip()

        if not idempotency_key or len(idempotency_key) > 180:
            raise HTTPException(
                status_code=400,
                detail="کلید یکتایی رویداد معتبر نیست"
            )

    if not 1 <= int(max_attempts) <= 100:
        raise HTTPException(
            status_code=400,
            detail="تعداد تلاش نامعتبر است"
        )

    if not 0 <= int(available_seconds) <= EVENT_MAX_RETRY_SECONDS:
        raise HTTPException(
            status_code=400,
            detail="زمان اجرای رویداد معتبر نیست"
        )

    new_event_id = event_uuid.uuid4()

    cursor.execute(
        """
        INSERT INTO mg_event_outbox (
            event_id,
            event_type,
            payload,
            idempotency_key,
            max_attempts,
            available_at
        )
        VALUES (
            %s,
            %s,
            %s::jsonb,
            %s,
            %s,
            NOW() + (%s * INTERVAL '1 second')
        )
        ON CONFLICT DO NOTHING
        RETURNING id, event_id, status
        """,
        (
            new_event_id,
            event_type,
            encoded_payload,
            idempotency_key,
            int(max_attempts),
            int(available_seconds)
        )
    )

    row = cursor.fetchone()

    if row:
        return {
            "created": True,
            "id": row["id"],
            "event_id": str(row["event_id"]),
            "status": row["status"]
        }

    if idempotency_key is not None:
        cursor.execute(
            """
            SELECT id, event_id, status
            FROM mg_event_outbox
            WHERE idempotency_key = %s
            """,
            (idempotency_key,)
        )

        existing = cursor.fetchone()

        if existing:
            return {
                "created": False,
                "id": existing["id"],
                "event_id": str(existing["event_id"]),
                "status": existing["status"]
            }

    raise HTTPException(
        status_code=409,
        detail="رویداد ثبت نشد؛ درخواست را دوباره بررسی کنید"
    )


# ------------------------------------------------------------
# WORKER: CLAIM EVENTS
#
# Workers must process returned events and acknowledge or
# retry them using their lease token.
# ------------------------------------------------------------

@app.post("/api/v1/internal/events/claim")
def claim_outbox_events(
    batch_size: int = Query(20, ge=1, le=EVENT_MAX_BATCH),
    lease_seconds: int = Query(
        EVENT_DEFAULT_LEASE_SECONDS,
        ge=10,
        le=EVENT_MAX_LEASE_SECONDS
    ),
    x_admin_key: Optional[str] = Header(
        None,
        alias="x-admin-key"
    )
):
    event_require_admin(x_admin_key)

    with get_db() as conn:
        with conn.cursor() as cursor:
            event_require_schema(cursor)

            cursor.execute(
                """
                WITH candidates AS (
                    SELECT id
                    FROM mg_event_outbox
                    WHERE (
                        status = 'pending'
                        AND available_at <= NOW()
                    )
                    OR (
                        status = 'processing'
                        AND lease_until < NOW()
                    )
                    ORDER BY available_at ASC, created_at ASC
                    FOR UPDATE SKIP LOCKED
                    LIMIT %s
                )
                UPDATE mg_event_outbox AS events
                SET
                    status = CASE
                        WHEN events.attempts + 1 >= events.max_attempts
                            THEN 'dead'
                        ELSE 'processing'
                    END,
                    attempts = events.attempts + 1,
                    lease_token = CASE
                        WHEN events.attempts + 1 >= events.max_attempts
                            THEN NULL
                        ELSE gen_random_uuid()
                    END,
                    lease_until = CASE
                        WHEN events.attempts + 1 >= events.max_attempts
                            THEN NULL
                        ELSE NOW() + (%s * INTERVAL '1 second')
                    END,
                    updated_at = NOW()
                FROM candidates
                WHERE events.id = candidates.id
                RETURNING
                    events.id,
                    events.event_id,
                    events.event_type,
                    events.payload,
                    events.attempts,
                    events.max_attempts,
                    events.status,
                    events.lease_token,
                    events.lease_until
                """,
                (batch_size, lease_seconds)
            )

            rows = cursor.fetchall()

    claimed = []

    for row in rows:
        if row["status"] != "processing":
            continue

        claimed.append({
            "id": row["id"],
            "event_id": str(row["event_id"]),
            "event_type": row["event_type"],
            "payload": row["payload"],
            "attempt": row["attempts"],
            "max_attempts": row["max_attempts"],
            "lease_token": str(row["lease_token"]),
            "lease_until": row["lease_until"].isoformat()
        })

    return {
        "success": True,
        "count": len(claimed),
        "events": claimed
    }


# ------------------------------------------------------------
# WORKER: ACKNOWLEDGE SUCCESS
# ------------------------------------------------------------

@app.post("/api/v1/internal/events/{event_row_id}/ack")
def acknowledge_outbox_event(
    event_row_id: int,
    payload: EventAcknowledgeRequest,
    x_admin_key: Optional[str] = Header(
        None,
        alias="x-admin-key"
    )
):
    event_require_admin(x_admin_key)

    try:
        lease_token = event_uuid.UUID(payload.lease_token)
    except ValueError:
        raise HTTPException(
            status_code=400,
            detail="شناسه قفل رویداد معتبر نیست"
        )

    with get_db() as conn:
        with conn.cursor() as cursor:
            event_require_schema(cursor)

            cursor.execute(
                """
                UPDATE mg_event_outbox
                SET
                    status = 'delivered',
                    delivered_at = NOW(),
                    lease_token = NULL,
                    lease_until = NULL,
                    last_error = NULL,
                    updated_at = NOW()
                WHERE id = %s
                  AND status = 'processing'
                  AND lease_token = %s
                  AND lease_until > NOW()
                RETURNING id, event_id
                """,
                (event_row_id, lease_token)
            )

            row = cursor.fetchone()

    if not row:
        raise HTTPException(
            status_code=409,
            detail="قفل رویداد منقضی شده یا متعلق به این پردازش نیست"
        )

    return {
        "success": True,
        "status": "delivered",
        "event_id": str(row["event_id"])
    }


# ------------------------------------------------------------
# WORKER: RETRY AFTER FAILURE
# ------------------------------------------------------------

@app.post("/api/v1/internal/events/{event_row_id}/retry")
def retry_outbox_event(
    event_row_id: int,
    payload: EventRetryRequest,
    x_admin_key: Optional[str] = Header(
        None,
        alias="x-admin-key"
    )
):
    event_require_admin(x_admin_key)

    try:
        lease_token = event_uuid.UUID(payload.lease_token)
    except ValueError:
        raise HTTPException(
            status_code=400,
            detail="شناسه قفل رویداد معتبر نیست"
        )

    with get_db() as conn:
        with conn.cursor() as cursor:
            event_require_schema(cursor)

            cursor.execute(
                """
                UPDATE mg_event_outbox
                SET
                    status = CASE
                        WHEN attempts >= max_attempts
                            THEN 'dead'
                        ELSE 'pending'
                    END,
                    available_at = NOW() + (
                        %s * INTERVAL '1 second'
                    ),
                    lease_token = NULL,
                    lease_until = NULL,
                    last_error = %s,
                    updated_at = NOW()
                WHERE id = %s
                  AND status = 'processing'
                  AND lease_token = %s
                  AND lease_until > NOW()
                RETURNING id, event_id, status, attempts
                """,
                (
                    payload.retry_after_seconds,
                    payload.error,
                    event_row_id,
                    lease_token
                )
            )

            row = cursor.fetchone()

    if not row:
        raise HTTPException(
            status_code=409,
            detail="قفل رویداد منقضی شده یا متعلق به این پردازش نیست"
        )

    return {
        "success": True,
        "event_id": str(row["event_id"]),
        "status": row["status"],
        "attempts": row["attempts"]
    }


# ------------------------------------------------------------
# ADMIN: EVENT QUEUE STATISTICS
# ------------------------------------------------------------

@app.get("/api/v1/admin/events/statistics")
def get_event_queue_statistics(
    x_admin_key: Optional[str] = Header(
        None,
        alias="x-admin-key"
    )
):
    event_require_admin(x_admin_key)

    with get_db() as conn:
        with conn.cursor() as cursor:
            event_require_schema(cursor)

            cursor.execute(
                """
                SELECT
                    COUNT(*) AS total,
                    COUNT(*) FILTER (
                        WHERE status = 'pending'
                    ) AS pending,
                    COUNT(*) FILTER (
                        WHERE status = 'processing'
                          AND lease_until > NOW()
                    ) AS processing,
                    COUNT(*) FILTER (
                        WHERE status = 'processing'
                          AND lease_until <= NOW()
                    ) AS expired_leases,
                    COUNT(*) FILTER (
                        WHERE status = 'delivered'
                    ) AS delivered,
                    COUNT(*) FILTER (
                        WHERE status = 'dead'
                    ) AS dead
                FROM mg_event_outbox
                """
            )

            row = cursor.fetchone()

    return {
        "success": True,
        "statistics": {
            "total": row["total"],
            "pending": row["pending"],
            "processing": row["processing"],
            "expired_leases": row["expired_leases"],
            "delivered": row["delivered"],
            "dead": row["dead"]
        }
    }


# ============================================================
# END SECTION 9
# NEXT: MEDIA STORAGE & SECURE UPLOAD ENGINE
# ============================================================

# ============================================================
# MASIH GRAM GLOBAL — SECTION 10
# AUDIT TRAIL & SECURITY HISTORY ENGINE
# ============================================================

import json as audit_json
import re as audit_re
from datetime import datetime, timezone
from typing import Optional

from pydantic import BaseModel, Field
from fastapi import Query, Header, HTTPException


AUDIT_ENGINE_VERSION = "10.0.0"
AUDIT_MAX_METADATA_BYTES = 12000
AUDIT_MAX_PAGE_SIZE = 100

AUDIT_SENSITIVE_KEYS = {
    "password", "passwd", "token", "access_token",
    "refresh_token", "authorization", "secret",
    "otp", "otp_code", "api_key", "private_key",
    "phone", "email", "cookie", "session_token"
}


class AuditEventCreate(BaseModel):
    action: str = Field(min_length=2, max_length=100)
    target_type: Optional[str] = Field(default=None, max_length=80)
    target_id: Optional[str] = Field(default=None, max_length=150)
    metadata: dict = Field(default_factory=dict)


class AuditAdminQuery(BaseModel):
    action: Optional[str] = Field(default=None, max_length=100)
    actor_id: Optional[str] = Field(default=None, max_length=150)


def audit_clean_text(value, maximum=500):
    if value is None:
        return None
    value = str(value).strip()
    return value[:maximum] if value else None


def audit_clean_metadata(value, depth=0):
    if depth > 5:
        return "[MAX_DEPTH]"

    if isinstance(value, dict):
        cleaned = {}
        for key, item in list(value.items())[:60]:
            safe_key = audit_clean_text(key, 80)
            if not safe_key:
                continue

            if safe_key.lower() in AUDIT_SENSITIVE_KEYS:
                cleaned[safe_key] = "[REDACTED]"
            else:
                cleaned[safe_key] = audit_clean_metadata(item, depth + 1)

        return cleaned

    if isinstance(value, list):
        return [
            audit_clean_metadata(item, depth + 1)
            for item in value[:60]
        ]

    if isinstance(value, str):
        return value[:2000]

    if isinstance(value, (int, float, bool)) or value is None:
        return value

    return audit_clean_text(value, 500)


def audit_validate_action(action):
    action = audit_clean_text(action, 100)

    if not action:
        raise HTTPException(
            status_code=400,
            detail="Invalid audit action"
        )

    if not audit_re.fullmatch(r"[a-zA-Z0-9_.:-]+", action):
        raise HTTPException(
            status_code=400,
            detail="Audit action contains invalid characters"
        )

    return action


def audit_require_schema(cursor):
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS mg_audit_trail (
            id BIGSERIAL PRIMARY KEY,
            event_id UUID NOT NULL UNIQUE,
            actor_user_id TEXT,
            actor_role VARCHAR(40) NOT NULL DEFAULT 'user',
            action VARCHAR(100) NOT NULL,
            target_type VARCHAR(80),
            target_id VARCHAR(150),
            metadata JSONB NOT NULL DEFAULT '{}'::jsonb,
            created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
        )
    """)

    cursor.execute("""
        CREATE INDEX IF NOT EXISTS
        idx_mg_audit_actor_time
        ON mg_audit_trail(actor_user_id, created_at DESC)
    """)

    cursor.execute("""
        CREATE INDEX IF NOT EXISTS
        idx_mg_audit_action_time
        ON mg_audit_trail(action, created_at DESC)
    """)

    cursor.execute("""
        CREATE INDEX IF NOT EXISTS
        idx_mg_audit_target
        ON mg_audit_trail(target_type, target_id)
    """)


def audit_write(
    cursor,
    actor_user_id,
    action,
    actor_role="user",
    target_type=None,
    target_id=None,
    metadata=None
):
    action = audit_validate_action(action)

    clean_metadata = audit_clean_metadata(
        metadata if isinstance(metadata, dict) else {}
    )

    serialized = audit_json.dumps(
        clean_metadata,
        ensure_ascii=False,
        separators=(",", ":")
    )

    if len(serialized.encode("utf-8")) > AUDIT_MAX_METADATA_BYTES:
        raise HTTPException(
            status_code=413,
            detail="Audit metadata is too large"
        )

    import uuid as audit_uuid_lib

    event_id = str(audit_uuid_lib.uuid4())

    cursor.execute("""
        INSERT INTO mg_audit_trail (
            event_id,
            actor_user_id,
            actor_role,
            action,
            target_type,
            target_id,
            metadata
        )
        VALUES (
            %s, %s, %s, %s, %s, %s, %s::jsonb
        )
        RETURNING id, event_id, created_at
    """, (
        event_id,
        str(actor_user_id) if actor_user_id is not None else None,
        audit_clean_text(actor_role, 40) or "user",
        action,
        audit_clean_text(target_type, 80),
        audit_clean_text(target_id, 150),
        serialized
    ))

    return cursor.fetchone()


def audit_user_id(user):
    if isinstance(user, dict):
        value = user.get("id") or user.get("user_id")
    else:
        value = getattr(user, "id", None)

    if value is None:
        raise HTTPException(
            status_code=401,
            detail="Authenticated user ID is missing"
        )

    return str(value)


def audit_row_to_dict(row):
    if not row:
        return None

    return {
        "id": row[0],
        "event_id": str(row[1]),
        "actor_user_id": row[2],
        "actor_role": row[3],
        "action": row[4],
        "target_type": row[5],
        "target_id": row[6],
        "metadata": row[7],
        "created_at": row[8].isoformat() if row[8] else None
    }


@app.post("/api/v1/admin/migrations/audit/apply")
def apply_audit_migration(
    authorization: Optional[str] = Header(default=None)
):
    global_admin_check(authorization)

    with get_db() as conn:
        with conn.cursor() as cursor:
            audit_require_schema(cursor)

    return {
        "success": True,
        "engine": "MASIH GRAM AUDIT TRAIL",
        "version": AUDIT_ENGINE_VERSION,
        "message": "Audit schema is ready"
    }


@app.get("/api/v1/security/audit/me")
def get_my_audit_history(
    limit: int = Query(default=50, ge=1, le=AUDIT_MAX_PAGE_SIZE),
    offset: int = Query(default=0, ge=0, le=100000),
    authorization: Optional[str] = Header(default=None)
):
    user = global_user(authorization)
    user_id = audit_user_id(user)

    with get_db() as conn:
        with conn.cursor() as cursor:
            audit_require_schema(cursor)

            cursor.execute("""
                SELECT
                    id, event_id, actor_user_id, actor_role,
                    action, target_type, target_id,
                    metadata, created_at
                FROM mg_audit_trail
                WHERE actor_user_id = %s
                ORDER BY created_at DESC, id DESC
                LIMIT %s OFFSET %s
            """, (user_id, limit, offset))

            rows = cursor.fetchall()

    return {
        "success": True,
        "items": [audit_row_to_dict(row) for row in rows],
        "limit": limit,
        "offset": offset
    }


@app.get("/api/v1/admin/audit/events")
def admin_get_audit_events(
    limit: int = Query(default=50, ge=1, le=AUDIT_MAX_PAGE_SIZE),
    offset: int = Query(default=0, ge=0, le=100000),
    action: Optional[str] = Query(default=None, max_length=100),
    actor_id: Optional[str] = Query(default=None, max_length=150),
    authorization: Optional[str] = Header(default=None)
):
    global_admin_check(authorization)

    conditions = []
    params = []

    if action:
        conditions.append("action = %s")
        params.append(audit_validate_action(action))

    if actor_id:
        conditions.append("actor_user_id = %s")
        params.append(audit_clean_text(actor_id, 150))

    where_sql = (
        "WHERE " + " AND ".join(conditions)
        if conditions else ""
    )

    with get_db() as conn:
        with conn.cursor() as cursor:
            audit_require_schema(cursor)

            cursor.execute(f"""
                SELECT
                    id, event_id, actor_user_id, actor_role,
                    action, target_type, target_id,
                    metadata, created_at
                FROM mg_audit_trail
                {where_sql}
                ORDER BY created_at DESC, id DESC
                LIMIT %s OFFSET %s
            """, tuple(params + [limit, offset]))

            rows = cursor.fetchall()

            cursor.execute(f"""
                SELECT COUNT(*)
                FROM mg_audit_trail
                {where_sql}
            """, tuple(params))

            total = cursor.fetchone()[0]

    return {
        "success": True,
        "total": total,
        "items": [audit_row_to_dict(row) for row in rows],
        "limit": limit,
        "offset": offset
    }


@app.post("/api/v1/security/audit/event")
def create_my_audit_event(
    data: AuditEventCreate,
    authorization: Optional[str] = Header(default=None)
):
    user = global_user(authorization)
    user_id = audit_user_id(user)

    with get_db() as conn:
        with conn.cursor() as cursor:
            audit_require_schema(cursor)

            result = audit_write(
                cursor=cursor,
                actor_user_id=user_id,
                action=data.action,
                actor_role="user",
                target_type=data.target_type,
                target_id=data.target_id,
                metadata=data.metadata
            )

    return {
        "success": True,
        "event": {
            "id": result[0],
            "event_id": str(result[1]),
            "created_at": (
                result[2].isoformat()
                if result[2] else None
            )
        }
    }


@app.get("/api/v1/admin/audit/statistics")
def get_audit_statistics(
    authorization: Optional[str] = Header(default=None)
):
    global_admin_check(authorization)

    with get_db() as conn:
        with conn.cursor() as cursor:
            audit_require_schema(cursor)

            cursor.execute("""
                SELECT
                    COUNT(*) AS total_events,
                    COUNT(*) FILTER (
                        WHERE created_at >= NOW() - INTERVAL '24 hours'
                    ) AS last_24_hours,
                    COUNT(DISTINCT actor_user_id) AS active_actors
                FROM mg_audit_trail
            """)

            summary = cursor.fetchone()

            cursor.execute("""
                SELECT action, COUNT(*) AS total
                FROM mg_audit_trail
                WHERE created_at >= NOW() - INTERVAL '7 days'
                GROUP BY action
                ORDER BY total DESC
                LIMIT 20
            """)

            popular_actions = cursor.fetchall()

    return {
        "success": True,
        "statistics": {
            "total_events": summary[0],
            "last_24_hours": summary[1],
            "active_actors": summary[2]
        },
        "popular_actions": [
            {"action": row[0], "total": row[1]}
            for row in popular_actions
        ]
    }

# END OF SECTION 10

# ============================================================
# MASIH GRAM GLOBAL
# SECTION 11 — USER PREFERENCES ENGINE
# ============================================================

import json as preferences_json

from pydantic import BaseModel, Field
from fastapi import Header, HTTPException
from typing import Optional


PREFERENCES_ENGINE_VERSION = "11.0.0"

PREFERENCES_DEFAULTS = {
    "theme": "dark",
    "language": "fa",
    "font_size": "medium",
    "notifications_enabled": True,
    "message_preview": True,
    "sound_enabled": True,
    "vibration_enabled": True,
    "read_receipts": True,
    "online_status": True,
    "last_seen_visibility": "contacts",
    "media_auto_download": "wifi",
    "animations_enabled": True,
    "chat_background": "default",
    "enter_to_send": False,
    "data_saver": False
}

PREFERENCES_ALLOWED = set(PREFERENCES_DEFAULTS.keys())


class PreferencesUpdateRequest(BaseModel):
    preferences: dict = Field(default_factory=dict)


class PreferencesResetRequest(BaseModel):
    confirm: bool = False


def preferences_extract_user_id(user):
    if isinstance(user, dict):
        value = user.get("id") or user.get("user_id")
    else:
        value = (
            getattr(user, "id", None)
            or getattr(user, "user_id", None)
        )

    if value is None:
        raise HTTPException(
            status_code=401,
            detail="User identity unavailable"
        )

    return str(value)


def preferences_require_schema(cursor):
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS mg_user_preferences (
            user_id TEXT PRIMARY KEY,
            preferences JSONB NOT NULL DEFAULT '{}'::jsonb,
            version INTEGER NOT NULL DEFAULT 1,
            created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
            updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
        )
    """)

    cursor.execute("""
        CREATE INDEX IF NOT EXISTS
        idx_mg_user_preferences_updated
        ON mg_user_preferences(updated_at DESC)
    """)


def preferences_validate(data):
    if not isinstance(data, dict):
        raise HTTPException(
            status_code=400,
            detail="Preferences must be an object"
        )

    if len(data) > len(PREFERENCES_ALLOWED):
        raise HTTPException(
            status_code=400,
            detail="Too many preference fields"
        )

    result = {}

    for key, value in data.items():
        if key not in PREFERENCES_ALLOWED:
            raise HTTPException(
                status_code=400,
                detail="Unsupported preference: " + str(key)
            )

        default = PREFERENCES_DEFAULTS[key]

        if isinstance(default, bool):
            if not isinstance(value, bool):
                raise HTTPException(
                    status_code=422,
                    detail="Invalid boolean preference: " + key
                )

        elif key == "theme":
            if value not in ("dark", "light", "system"):
                raise HTTPException(
                    status_code=422,
                    detail="Invalid theme"
                )

        elif key == "language":
            if value not in ("fa", "en", "az", "ar", "tr"):
                raise HTTPException(
                    status_code=422,
                    detail="Unsupported language"
                )

        elif key == "font_size":
            if value not in ("small", "medium", "large"):
                raise HTTPException(
                    status_code=422,
                    detail="Invalid font size"
                )

        elif key == "last_seen_visibility":
            if value not in ("everyone", "contacts", "nobody"):
                raise HTTPException(
                    status_code=422,
                    detail="Invalid last seen visibility"
                )

        elif key == "media_auto_download":
            if value not in ("never", "wifi", "always"):
                raise HTTPException(
                    status_code=422,
                    detail="Invalid media download setting"
                )

        elif key == "chat_background":
            if not isinstance(value, str) or len(value) > 100:
                raise HTTPException(
                    status_code=422,
                    detail="Invalid chat background"
                )

        result[key] = value

    return result


def preferences_load(cursor, user_id):
    cursor.execute("""
        SELECT preferences, version, updated_at
        FROM mg_user_preferences
        WHERE user_id = %s
    """, (user_id,))

    row = cursor.fetchone()

    if not row:
        return {
            "preferences": dict(PREFERENCES_DEFAULTS),
            "version": 0,
            "updated_at": None
        }

    stored = row[0]

    if isinstance(stored, str):
        try:
            stored = preferences_json.loads(stored)
        except Exception:
            stored = {}

    if not isinstance(stored, dict):
        stored = {}

    merged = dict(PREFERENCES_DEFAULTS)
    merged.update(stored)

    return {
        "preferences": merged,
        "version": row[1],
        "updated_at": (
            row[2].isoformat() if row[2] else None
        )
    }


@app.post("/api/v1/admin/migrations/preferences/apply")
def apply_preferences_migration(
    authorization: Optional[str] = Header(default=None)
):
    global_admin_check(authorization)

    with get_db() as conn:
        with conn.cursor() as cursor:
            preferences_require_schema(cursor)

    return {
        "success": True,
        "engine": "USER PREFERENCES",
        "version": PREFERENCES_ENGINE_VERSION
    }


@app.get("/api/v1/users/me/preferences")
def get_my_preferences(
    authorization: Optional[str] = Header(default=None)
):
    user = global_user(authorization)
    user_id = preferences_extract_user_id(user)

    with get_db() as conn:
        with conn.cursor() as cursor:
            preferences_require_schema(cursor)

            result = preferences_load(cursor, user_id)

    return {
        "success": True,
        **result
    }


@app.patch("/api/v1/users/me/preferences")
def update_my_preferences(
    data: PreferencesUpdateRequest,
    authorization: Optional[str] = Header(default=None)
):
    user = global_user(authorization)
    user_id = preferences_extract_user_id(user)

    updates = preferences_validate(data.preferences)

    if not updates:
        raise HTTPException(
            status_code=400,
            detail="No preference changes supplied"
        )

    with get_db() as conn:
        with conn.cursor() as cursor:
            preferences_require_schema(cursor)

            current = preferences_load(cursor, user_id)
            merged = dict(current["preferences"])
            merged.update(updates)

            serialized = preferences_json.dumps(
                merged,
                ensure_ascii=False,
                separators=(",", ":")
            )

            cursor.execute("""
                INSERT INTO mg_user_preferences (
                    user_id,
                    preferences,
                    version
                )
                VALUES (%s, %s::jsonb, 1)

                ON CONFLICT (user_id)
                DO UPDATE SET
                    preferences = EXCLUDED.preferences,
                    version = mg_user_preferences.version + 1,
                    updated_at = NOW()

                RETURNING version, updated_at
            """, (user_id, serialized))

            row = cursor.fetchone()

    return {
        "success": True,
        "preferences": merged,
        "version": row[0],
        "updated_at": row[1].isoformat()
    }


@app.post("/api/v1/users/me/preferences/reset")
def reset_my_preferences(
    data: PreferencesResetRequest,
    authorization: Optional[str] = Header(default=None)
):
    user = global_user(authorization)
    user_id = preferences_extract_user_id(user)

    if data.confirm is not True:
        raise HTTPException(
            status_code=400,
            detail="Explicit confirmation required"
        )

    serialized = preferences_json.dumps(
        PREFERENCES_DEFAULTS,
        ensure_ascii=False
    )

    with get_db() as conn:
        with conn.cursor() as cursor:
            preferences_require_schema(cursor)

            cursor.execute("""
                INSERT INTO mg_user_preferences (
                    user_id,
                    preferences,
                    version
                )
                VALUES (%s, %s::jsonb, 1)

                ON CONFLICT (user_id)
                DO UPDATE SET
                    preferences = EXCLUDED.preferences,
                    version = mg_user_preferences.version + 1,
                    updated_at = NOW()

                RETURNING version, updated_at
            """, (user_id, serialized))

            row = cursor.fetchone()

    return {
        "success": True,
        "message": "Preferences reset successfully",
        "preferences": dict(PREFERENCES_DEFAULTS),
        "version": row[0],
        "updated_at": row[1].isoformat()
    }


@app.delete("/api/v1/users/me/preferences")
def delete_my_custom_preferences(
    authorization: Optional[str] = Header(default=None)
):
    user = global_user(authorization)
    user_id = preferences_extract_user_id(user)

    with get_db() as conn:
        with conn.cursor() as cursor:
            preferences_require_schema(cursor)

            cursor.execute("""
                DELETE FROM mg_user_preferences
                WHERE user_id = %s
            """, (user_id,))

    return {
        "success": True,
        "message": "Custom preferences removed",
        "preferences": dict(PREFERENCES_DEFAULTS)
    }


@app.get("/api/v1/admin/preferences/statistics")
def get_preferences_statistics(
    authorization: Optional[str] = Header(default=None)
):
    global_admin_check(authorization)

    with get_db() as conn:
        with conn.cursor() as cursor:
            preferences_require_schema(cursor)

            cursor.execute("""
                SELECT
                    COUNT(*) AS total_users,
                    COUNT(*) FILTER (
                        WHERE updated_at >= NOW() - INTERVAL '24 hours'
                    ) AS recently_updated
                FROM mg_user_preferences
            """)

            summary = cursor.fetchone()

            cursor.execute("""
                SELECT
                    preferences->>'theme' AS theme,
                    COUNT(*) AS total
                FROM mg_user_preferences
                GROUP BY preferences->>'theme'
                ORDER BY total DESC
            """)

            themes = cursor.fetchall()

            cursor.execute("""
                SELECT
                    preferences->>'language' AS language,
                    COUNT(*) AS total
                FROM mg_user_preferences
                GROUP BY preferences->>'language'
                ORDER BY total DESC
            """)

            languages = cursor.fetchall()

    return {
        "success": True,
        "statistics": {
            "total_users": summary[0],
            "recently_updated": summary[1]
        },
        "themes": [
            {"theme": row[0], "users": row[1]}
            for row in themes
        ],
        "languages": [
            {"language": row[0], "users": row[1]}
            for row in languages
        ]
    }

# END OF SECTION 11

# ============================================================
# MASIH GRAM GLOBAL
# SECTION 12 — DEVICE MANAGEMENT ENGINE
# ============================================================

import uuid as device_uuid_lib
import re as device_re
from typing import Optional

from pydantic import BaseModel, Field
from fastapi import Header, HTTPException, Query


DEVICE_ENGINE_VERSION = "12.0.0"


class DeviceRegisterRequest(BaseModel):
    device_name: str = Field(min_length=2, max_length=100)
    platform: str = Field(min_length=2, max_length=40)
    app_version: str = Field(default="unknown", max_length=40)
    device_model: Optional[str] = Field(default=None, max_length=100)


class DeviceRenameRequest(BaseModel):
    device_name: str = Field(min_length=2, max_length=100)


def device_user_id(user):
    if isinstance(user, dict):
        value = user.get("id") or user.get("user_id")
    else:
        value = (
            getattr(user, "id", None)
            or getattr(user, "user_id", None)
        )

    if value is None:
        raise HTTPException(
            status_code=401,
            detail="User identity unavailable"
        )

    return str(value)


def device_validate_name(value):
    value = str(value).strip()

    if not 2 <= len(value) <= 100:
        raise HTTPException(
            status_code=422,
            detail="Invalid device name"
        )

    if not device_re.fullmatch(
        r"[\w\s.\-()]+",
        value,
        flags=device_re.UNICODE
    ):
        raise HTTPException(
            status_code=422,
            detail="Invalid characters in device name"
        )

    return value


def device_require_schema(cursor):
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS mg_managed_devices (
            id UUID PRIMARY KEY,
            user_id TEXT NOT NULL,
            device_name VARCHAR(100) NOT NULL,
            platform VARCHAR(40) NOT NULL,
            app_version VARCHAR(40) NOT NULL DEFAULT 'unknown',
            device_model VARCHAR(100),
            created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
            last_seen_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
            revoked_at TIMESTAMPTZ
        )
    """)

    cursor.execute("""
        CREATE INDEX IF NOT EXISTS
        idx_mg_managed_devices_user
        ON mg_managed_devices(user_id, created_at DESC)
    """)

    cursor.execute("""
        CREATE INDEX IF NOT EXISTS
        idx_mg_managed_devices_active
        ON mg_managed_devices(user_id, last_seen_at DESC)
        WHERE revoked_at IS NULL
    """)


def device_row(row):
    return {
        "device_id": str(row[0]),
        "device_name": row[1],
        "platform": row[2],
        "app_version": row[3],
        "device_model": row[4],
        "created_at": row[5].isoformat() if row[5] else None,
        "last_seen_at": row[6].isoformat() if row[6] else None,
        "revoked": row[7] is not None
    }


@app.post("/api/v1/admin/migrations/devices/apply")
def apply_device_migration(
    authorization: Optional[str] = Header(default=None)
):
    global_admin_check(authorization)

    with get_db() as conn:
        with conn.cursor() as cursor:
            device_require_schema(cursor)

    return {
        "success": True,
        "engine": "DEVICE MANAGEMENT",
        "version": DEVICE_ENGINE_VERSION
    }


@app.post("/api/v1/devices/register")
def register_managed_device(
    data: DeviceRegisterRequest,
    authorization: Optional[str] = Header(default=None)
):
    user = global_user(authorization)
    user_id = device_user_id(user)

    device_name = device_validate_name(data.device_name)
    platform = data.platform.strip().lower()

    if platform not in (
        "android", "ios", "windows",
        "macos", "linux", "web", "other"
    ):
        raise HTTPException(
            status_code=422,
            detail="Unsupported platform"
        )

    device_id = str(device_uuid_lib.uuid4())

    with get_db() as conn:
        with conn.cursor() as cursor:
            device_require_schema(cursor)

            cursor.execute("""
                INSERT INTO mg_managed_devices (
                    id,
                    user_id,
                    device_name,
                    platform,
                    app_version,
                    device_model
                )
                VALUES (%s, %s, %s, %s, %s, %s)
                RETURNING
                    id, device_name, platform,
                    app_version, device_model,
                    created_at, last_seen_at, revoked_at
            """, (
                device_id,
                user_id,
                device_name,
                platform,
                data.app_version.strip() or "unknown",
                data.device_model.strip()
                if data.device_model else None
            ))

            row = cursor.fetchone()

    return {
        "success": True,
        "device": device_row(row)
    }


@app.get("/api/v1/devices")
def list_managed_devices(
    include_revoked: bool = Query(default=False),
    authorization: Optional[str] = Header(default=None)
):
    user = global_user(authorization)
    user_id = device_user_id(user)

    with get_db() as conn:
        with conn.cursor() as cursor:
            device_require_schema(cursor)

            if include_revoked:
                cursor.execute("""
                    SELECT
                        id, device_name, platform,
                        app_version, device_model,
                        created_at, last_seen_at, revoked_at
                    FROM mg_managed_devices
                    WHERE user_id = %s
                    ORDER BY created_at DESC
                    LIMIT 200
                """, (user_id,))
            else:
                cursor.execute("""
                    SELECT
                        id, device_name, platform,
                        app_version, device_model,
                        created_at, last_seen_at, revoked_at
                    FROM mg_managed_devices
                    WHERE user_id = %s
                    AND revoked_at IS NULL
                    ORDER BY last_seen_at DESC
                    LIMIT 200
                """, (user_id,))

            rows = cursor.fetchall()

    return {
        "success": True,
        "devices": [device_row(row) for row in rows],
        "total": len(rows)
    }


@app.patch("/api/v1/devices/{device_id}/rename")
def rename_managed_device(
    device_id: str,
    data: DeviceRenameRequest,
    authorization: Optional[str] = Header(default=None)
):
    user = global_user(authorization)
    user_id = device_user_id(user)

    try:
        parsed_id = str(device_uuid_lib.UUID(device_id))
    except (ValueError, TypeError, AttributeError):
        raise HTTPException(
            status_code=400,
            detail="Invalid device ID"
        )

    device_name = device_validate_name(data.device_name)

    with get_db() as conn:
        with conn.cursor() as cursor:
            device_require_schema(cursor)

            cursor.execute("""
                UPDATE mg_managed_devices
                SET device_name = %s
                WHERE id = %s
                AND user_id = %s
                AND revoked_at IS NULL
                RETURNING id
            """, (device_name, parsed_id, user_id))

            row = cursor.fetchone()

    if not row:
        raise HTTPException(
            status_code=404,
            detail="Active device not found"
        )

    return {
        "success": True,
        "device_id": parsed_id,
        "device_name": device_name
    }


@app.post("/api/v1/devices/{device_id}/revoke")
def revoke_managed_device(
    device_id: str,
    authorization: Optional[str] = Header(default=None)
):
    user = global_user(authorization)
    user_id = device_user_id(user)

    try:
        parsed_id = str(device_uuid_lib.UUID(device_id))
    except (ValueError, TypeError, AttributeError):
        raise HTTPException(
            status_code=400,
            detail="Invalid device ID"
        )

    with get_db() as conn:
        with conn.cursor() as cursor:
            device_require_schema(cursor)

            cursor.execute("""
                UPDATE mg_managed_devices
                SET revoked_at = NOW()
                WHERE id = %s
                AND user_id = %s
                AND revoked_at IS NULL
                RETURNING id
            """, (parsed_id, user_id))

            row = cursor.fetchone()

    if not row:
        raise HTTPException(
            status_code=404,
            detail="Active device not found"
        )

    return {
        "success": True,
        "device_id": parsed_id,
        "revoked": True
    }


@app.delete("/api/v1/devices/{device_id}")
def delete_managed_device(
    device_id: str,
    authorization: Optional[str] = Header(default=None)
):
    user = global_user(authorization)
    user_id = device_user_id(user)

    try:
        parsed_id = str(device_uuid_lib.UUID(device_id))
    except (ValueError, TypeError, AttributeError):
        raise HTTPException(
            status_code=400,
            detail="Invalid device ID"
        )

    with get_db() as conn:
        with conn.cursor() as cursor:
            device_require_schema(cursor)

            cursor.execute("""
                DELETE FROM mg_managed_devices
                WHERE id = %s
                AND user_id = %s
                RETURNING id
            """, (parsed_id, user_id))

            row = cursor.fetchone()

    if not row:
        raise HTTPException(
            status_code=404,
            detail="Device not found"
        )

    return {
        "success": True,
        "deleted": True,
        "device_id": parsed_id
    }


@app.post("/api/v1/devices/{device_id}/heartbeat")
def managed_device_heartbeat(
    device_id: str,
    authorization: Optional[str] = Header(default=None)
):
    user = global_user(authorization)
    user_id = device_user_id(user)

    try:
        parsed_id = str(device_uuid_lib.UUID(device_id))
    except (ValueError, TypeError, AttributeError):
        raise HTTPException(
            status_code=400,
            detail="Invalid device ID"
        )

    with get_db() as conn:
        with conn.cursor() as cursor:
            device_require_schema(cursor)

            cursor.execute("""
                UPDATE mg_managed_devices
                SET last_seen_at = NOW()
                WHERE id = %s
                AND user_id = %s
                AND revoked_at IS NULL
                RETURNING last_seen_at
            """, (parsed_id, user_id))

            row = cursor.fetchone()

    if not row:
        raise HTTPException(
            status_code=404,
            detail="Active device not found"
        )

    return {
        "success": True,
        "device_id": parsed_id,
        "last_seen_at": row[0].isoformat()
    }


# END OF SECTION 12

# ============================================================
# MASIH GRAM GLOBAL
# SECTION 13 — STORAGE METADATA ENGINE
# ============================================================

import uuid as storage_uuid_lib
import re as storage_re

from typing import Optional
from pydantic import BaseModel, Field
from fastapi import Header, HTTPException, Query


STORAGE_ENGINE_VERSION = "13.0.0"
STORAGE_MAX_FILE_SIZE = 2 * 1024 * 1024 * 1024

STORAGE_CATEGORIES = {
    "image", "video", "audio", "document", "other"
}


class StorageRegisterRequest(BaseModel):
    file_name: str = Field(min_length=1, max_length=255)
    file_category: str
    mime_type: str = Field(min_length=3, max_length=150)
    file_size: int = Field(gt=0, le=STORAGE_MAX_FILE_SIZE)
    storage_key: str = Field(min_length=8, max_length=500)
    checksum: Optional[str] = Field(default=None, max_length=128)
    description: Optional[str] = Field(default=None, max_length=1000)


class StorageUpdateRequest(BaseModel):
    file_name: Optional[str] = Field(default=None, max_length=255)
    description: Optional[str] = Field(default=None, max_length=1000)


def storage_user_id(user):
    if isinstance(user, dict):
        value = user.get("id") or user.get("user_id")
    else:
        value = (
            getattr(user, "id", None)
            or getattr(user, "user_id", None)
        )

    if value is None:
        raise HTTPException(
            status_code=401,
            detail="User identity unavailable"
        )

    return str(value)


def storage_validate_name(value):
    value = str(value).strip()

    if not value or len(value) > 255:
        raise HTTPException(
            status_code=422,
            detail="Invalid file name"
        )

    if "/" in value or "\\" in value:
        raise HTTPException(
            status_code=422,
            detail="File name must not contain a path"
        )

    return value


def storage_validate_key(value):
    value = str(value).strip()

    if not 8 <= len(value) <= 500:
        raise HTTPException(
            status_code=422,
            detail="Invalid storage key"
        )

    if not storage_re.fullmatch(r"[A-Za-z0-9_.:/-]+", value):
        raise HTTPException(
            status_code=422,
            detail="Invalid storage key characters"
        )

    return value


def storage_require_schema(cursor):
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS mg_storage_objects (
            id UUID PRIMARY KEY,
            user_id TEXT NOT NULL,
            file_name VARCHAR(255) NOT NULL,
            file_category VARCHAR(30) NOT NULL,
            mime_type VARCHAR(150) NOT NULL,
            file_size BIGINT NOT NULL CHECK (file_size > 0),
            storage_key VARCHAR(500) NOT NULL,
            checksum VARCHAR(128),
            description VARCHAR(1000),
            created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
            updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
            deleted_at TIMESTAMPTZ
        )
    """)

    cursor.execute("""
        CREATE UNIQUE INDEX IF NOT EXISTS
        idx_mg_storage_active_key
        ON mg_storage_objects(user_id, storage_key)
        WHERE deleted_at IS NULL
    """)

    cursor.execute("""
        CREATE INDEX IF NOT EXISTS
        idx_mg_storage_user_created
        ON mg_storage_objects(user_id, created_at DESC)
    """)

    cursor.execute("""
        CREATE INDEX IF NOT EXISTS
        idx_mg_storage_category
        ON mg_storage_objects(user_id, file_category)
        WHERE deleted_at IS NULL
    """)


def storage_row(row):
    return {
        "file_id": str(row[0]),
        "file_name": row[1],
        "file_category": row[2],
        "mime_type": row[3],
        "file_size": row[4],
        "storage_key": row[5],
        "checksum": row[6],
        "description": row[7],
        "created_at": row[8].isoformat() if row[8] else None,
        "updated_at": row[9].isoformat() if row[9] else None
    }


@app.post("/api/v1/admin/migrations/storage/apply")
def apply_storage_migration(
    authorization: Optional[str] = Header(default=None)
):
    global_admin_check(authorization)

    with get_db() as conn:
        with conn.cursor() as cursor:
            storage_require_schema(cursor)

    return {
        "success": True,
        "engine": "STORAGE METADATA ENGINE",
        "version": STORAGE_ENGINE_VERSION
    }


@app.post("/api/v1/storage/register")
def register_storage_object(
    data: StorageRegisterRequest,
    authorization: Optional[str] = Header(default=None)
):
    user = global_user(authorization)
    user_id = storage_user_id(user)

    file_name = storage_validate_name(data.file_name)
    storage_key = storage_validate_key(data.storage_key)

    category = data.file_category.strip().lower()

    if category not in STORAGE_CATEGORIES:
        raise HTTPException(
            status_code=422,
            detail="Unsupported file category"
        )

    mime_type = data.mime_type.strip().lower()

    if "/" not in mime_type or any(ch.isspace() for ch in mime_type):
        raise HTTPException(
            status_code=422,
            detail="Invalid MIME type"
        )

    if data.checksum and not storage_re.fullmatch(
        r"[A-Fa-f0-9]{32,128}",
        data.checksum
    ):
        raise HTTPException(
            status_code=422,
            detail="Invalid checksum"
        )

    file_id = str(storage_uuid_lib.uuid4())

    with get_db() as conn:
        with conn.cursor() as cursor:
            storage_require_schema(cursor)

            cursor.execute("""
                INSERT INTO mg_storage_objects (
                    id, user_id, file_name, file_category,
                    mime_type, file_size, storage_key,
                    checksum, description
                )
                VALUES (
                    %s, %s, %s, %s, %s,
                    %s, %s, %s, %s
                )
                RETURNING
                    id, file_name, file_category,
                    mime_type, file_size, storage_key,
                    checksum, description, created_at, updated_at
            """, (
                file_id,
                user_id,
                file_name,
                category,
                mime_type,
                data.file_size,
                storage_key,
                data.checksum,
                data.description
            ))

            row = cursor.fetchone()

    return {
        "success": True,
        "file": storage_row(row)
    }


@app.get("/api/v1/storage/files")
def list_storage_objects(
    category: Optional[str] = Query(default=None, max_length=30),
    limit: int = Query(default=50, ge=1, le=100),
    offset: int = Query(default=0, ge=0, le=100000),
    authorization: Optional[str] = Header(default=None)
):
    user = global_user(authorization)
    user_id = storage_user_id(user)

    if category and category not in STORAGE_CATEGORIES:
        raise HTTPException(
            status_code=422,
            detail="Invalid category"
        )

    with get_db() as conn:
        with conn.cursor() as cursor:
            storage_require_schema(cursor)

            if category:
                cursor.execute("""
                    SELECT
                        id, file_name, file_category,
                        mime_type, file_size, storage_key,
                        checksum, description, created_at, updated_at
                    FROM mg_storage_objects
                    WHERE user_id = %s
                    AND file_category = %s
                    AND deleted_at IS NULL
                    ORDER BY created_at DESC
                    LIMIT %s OFFSET %s
                """, (user_id, category, limit, offset))
            else:
                cursor.execute("""
                    SELECT
                        id, file_name, file_category,
                        mime_type, file_size, storage_key,
                        checksum, description, created_at, updated_at
                    FROM mg_storage_objects
                    WHERE user_id = %s
                    AND deleted_at IS NULL
                    ORDER BY created_at DESC
                    LIMIT %s OFFSET %s
                """, (user_id, limit, offset))

            rows = cursor.fetchall()

    return {
        "success": True,
        "files": [storage_row(row) for row in rows],
        "limit": limit,
        "offset": offset
    }


@app.patch("/api/v1/storage/files/{file_id}")
def update_storage_object(
    file_id: str,
    data: StorageUpdateRequest,
    authorization: Optional[str] = Header(default=None)
):
    user = global_user(authorization)
    user_id = storage_user_id(user)

    try:
        parsed_id = str(storage_uuid_lib.UUID(file_id))
    except (ValueError, TypeError, AttributeError):
        raise HTTPException(
            status_code=400,
            detail="Invalid file ID"
        )

    updates = data.model_dump(exclude_unset=True)

    if not updates:
        raise HTTPException(
            status_code=400,
            detail="No changes supplied"
        )

    if "file_name" in updates and updates["file_name"] is not None:
        updates["file_name"] = storage_validate_name(
            updates["file_name"]
        )

    if "description" in updates and updates["description"] is not None:
        updates["description"] = updates["description"].strip()

    assignments = []
    params = []

    for key in ("file_name", "description"):
        if key in updates:
            assignments.append(key + " = %s")
            params.append(updates[key])

    if not assignments:
        raise HTTPException(
            status_code=400,
            detail="No valid changes supplied"
        )

    assignments.append("updated_at = NOW()")

    params.extend([parsed_id, user_id])

    with get_db() as conn:
        with conn.cursor() as cursor:
            storage_require_schema(cursor)

            cursor.execute("""
                UPDATE mg_storage_objects
                SET """ + ", ".join(assignments) + """
                WHERE id = %s
                AND user_id = %s
                AND deleted_at IS NULL
                RETURNING
                    id, file_name, file_category,
                    mime_type, file_size, storage_key,
                    checksum, description, created_at, updated_at
            """, tuple(params))

            row = cursor.fetchone()

    if not row:
        raise HTTPException(
            status_code=404,
            detail="File not found"
        )

    return {
        "success": True,
        "file": storage_row(row)
    }


@app.delete("/api/v1/storage/files/{file_id}")
def delete_storage_object(
    file_id: str,
    authorization: Optional[str] = Header(default=None)
):
    user = global_user(authorization)
    user_id = storage_user_id(user)

    try:
        parsed_id = str(storage_uuid_lib.UUID(file_id))
    except (ValueError, TypeError, AttributeError):
        raise HTTPException(
            status_code=400,
            detail="Invalid file ID"
        )

    with get_db() as conn:
        with conn.cursor() as cursor:
            storage_require_schema(cursor)

            cursor.execute("""
                UPDATE mg_storage_objects
                SET deleted_at = NOW(),
                    updated_at = NOW()
                WHERE id = %s
                AND user_id = %s
                AND deleted_at IS NULL
                RETURNING id
            """, (parsed_id, user_id))

            row = cursor.fetchone()

    if not row:
        raise HTTPException(
            status_code=404,
            detail="File not found"
        )

    return {
        "success": True,
        "file_id": parsed_id,
        "deleted": True
    }


@app.get("/api/v1/storage/statistics")
def get_storage_statistics(
    authorization: Optional[str] = Header(default=None)
):
    user = global_user(authorization)
    user_id = storage_user_id(user)

    with get_db() as conn:
        with conn.cursor() as cursor:
            storage_require_schema(cursor)

            cursor.execute("""
                SELECT
                    COUNT(*),
                    COALESCE(SUM(file_size), 0),
                    COUNT(*) FILTER (
                        WHERE file_category = 'image'
                    ),
                    COUNT(*) FILTER (
                        WHERE file_category = 'video'
                    ),
                    COUNT(*) FILTER (
                        WHERE file_category = 'audio'
                    ),
                    COUNT(*) FILTER (
                        WHERE file_category = 'document'
                    )
                FROM mg_storage_objects
                WHERE user_id = %s
                AND deleted_at IS NULL
            """, (user_id,))

            row = cursor.fetchone()

    return {
        "success": True,
        "statistics": {
            "file_count": row[0],
            "total_bytes": row[1],
            "image_count": row[2],
            "video_count": row[3],
            "audio_count": row[4],
            "document_count": row[5]
        }
    }


# END OF SECTION 13

# ============================================================
# MASIH GRAM GLOBAL
# SECTION 14 — NOTIFICATION PREFERENCES ENGINE
# ============================================================

import json as np_json
from typing import Optional
from datetime import datetime, timezone
from pydantic import BaseModel, Field
from fastapi import Header, HTTPException


NP_VERSION = "14.0.0"

NP_DEFAULTS = {
    "enabled": True,
    "messages": True,
    "groups": True,
    "calls": True,
    "mentions": True,
    "reactions": True,
    "follows": True,
    "security": True,
    "marketing": False,
    "sound": True,
    "vibration": True,
    "preview": True,
    "quiet_mode": False,
    "quiet_start": "22:00",
    "quiet_end": "08:00"
}

NP_BOOL_FIELDS = {
    "enabled", "messages", "groups", "calls",
    "mentions", "reactions", "follows", "security",
    "marketing", "sound", "vibration", "preview",
    "quiet_mode"
}


class NotificationPreferencesUpdate(BaseModel):
    preferences: dict = Field(default_factory=dict)


def np_user_id(user):
    if isinstance(user, dict):
        value = user.get("id") or user.get("user_id")
    else:
        value = (
            getattr(user, "id", None)
            or getattr(user, "user_id", None)
        )

    if value is None:
        raise HTTPException(
            status_code=401,
            detail="User identity unavailable"
        )

    return str(value)


def np_validate_time(value, field):
    if not isinstance(value, str):
        raise HTTPException(
            status_code=422,
            detail="Invalid " + field
        )

    try:
        datetime.strptime(value, "%H:%M")
    except ValueError:
        raise HTTPException(
            status_code=422,
            detail="Time must use HH:MM format"
        )

    return value


def np_validate_preferences(data):
    if not isinstance(data, dict):
        raise HTTPException(
            status_code=422,
            detail="Preferences must be an object"
        )

    if not data:
        raise HTTPException(
            status_code=400,
            detail="No preferences supplied"
        )

    result = {}

    for key, value in data.items():
        if key not in NP_DEFAULTS:
            raise HTTPException(
                status_code=422,
                detail="Unknown preference: " + str(key)
            )

        if key in NP_BOOL_FIELDS:
            if not isinstance(value, bool):
                raise HTTPException(
                    status_code=422,
                    detail="Invalid boolean: " + key
                )
            result[key] = value

        elif key in ("quiet_start", "quiet_end"):
            result[key] = np_validate_time(value, key)

    return result


def np_require_schema(cursor):
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS mg_notification_preferences (
            user_id TEXT PRIMARY KEY,
            preferences JSONB NOT NULL DEFAULT '{}'::jsonb,
            revision BIGINT NOT NULL DEFAULT 1,
            created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
            updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
        )
    """)

    cursor.execute("""
        CREATE INDEX IF NOT EXISTS
        idx_mg_notification_preferences_updated
        ON mg_notification_preferences(updated_at DESC)
    """)


def np_load(cursor, user_id):
    cursor.execute("""
        SELECT preferences, revision, updated_at
        FROM mg_notification_preferences
        WHERE user_id = %s
    """, (user_id,))

    row = cursor.fetchone()

    if not row:
        return {
            "preferences": dict(NP_DEFAULTS),
            "revision": 0,
            "updated_at": None
        }

    stored = row[0]

    if isinstance(stored, str):
        try:
            stored = np_json.loads(stored)
        except (ValueError, TypeError):
            stored = {}

    if not isinstance(stored, dict):
        stored = {}

    merged = dict(NP_DEFAULTS)
    merged.update(stored)

    return {
        "preferences": merged,
        "revision": row[1],
        "updated_at": (
            row[2].isoformat() if row[2] else None
        )
    }


@app.post("/api/v1/admin/migrations/notification-preferences/apply")
def np_apply_migration(
    authorization: Optional[str] = Header(default=None)
):
    global_admin_check(authorization)

    with get_db() as conn:
        with conn.cursor() as cursor:
            np_require_schema(cursor)

    return {
        "success": True,
        "engine": "NOTIFICATION PREFERENCES",
        "version": NP_VERSION
    }


@app.get("/api/v1/notifications/preferences")
def np_get_preferences(
    authorization: Optional[str] = Header(default=None)
):
    user = global_user(authorization)
    user_id = np_user_id(user)

    with get_db() as conn:
        with conn.cursor() as cursor:
            np_require_schema(cursor)
            result = np_load(cursor, user_id)

    return {
        "success": True,
        **result
    }


@app.patch("/api/v1/notifications/preferences")
def np_update_preferences(
    data: NotificationPreferencesUpdate,
    authorization: Optional[str] = Header(default=None)
):
    user = global_user(authorization)
    user_id = np_user_id(user)

    updates = np_validate_preferences(data.preferences)

    with get_db() as conn:
        with conn.cursor() as cursor:
            np_require_schema(cursor)

            current = np_load(cursor, user_id)
            merged = dict(current["preferences"])
            merged.update(updates)

            serialized = np_json.dumps(
                merged,
                ensure_ascii=False,
                separators=(",", ":")
            )

            cursor.execute("""
                INSERT INTO mg_notification_preferences (
                    user_id, preferences, revision
                )
                VALUES (%s, %s::jsonb, 1)
                ON CONFLICT (user_id)
                DO UPDATE SET
                    preferences = EXCLUDED.preferences,
                    revision =
                        mg_notification_preferences.revision + 1,
                    updated_at = NOW()
                RETURNING revision, updated_at
            """, (user_id, serialized))

            row = cursor.fetchone()

    return {
        "success": True,
        "preferences": merged,
        "revision": row[0],
        "updated_at": row[1].isoformat()
    }


@app.post("/api/v1/notifications/preferences/reset")
def np_reset_preferences(
    authorization: Optional[str] = Header(default=None)
):
    user = global_user(authorization)
    user_id = np_user_id(user)

    serialized = np_json.dumps(
        NP_DEFAULTS,
        ensure_ascii=False,
        separators=(",", ":")
    )

    with get_db() as conn:
        with conn.cursor() as cursor:
            np_require_schema(cursor)

            cursor.execute("""
                INSERT INTO mg_notification_preferences (
                    user_id, preferences, revision
                )
                VALUES (%s, %s::jsonb, 1)
                ON CONFLICT (user_id)
                DO UPDATE SET
                    preferences = EXCLUDED.preferences,
                    revision =
                        mg_notification_preferences.revision + 1,
                    updated_at = NOW()
                RETURNING revision, updated_at
            """, (user_id, serialized))

            row = cursor.fetchone()

    return {
        "success": True,
        "preferences": dict(NP_DEFAULTS),
        "revision": row[0],
        "updated_at": row[1].isoformat()
    }


@app.delete("/api/v1/notifications/preferences")
def np_delete_preferences(
    authorization: Optional[str] = Header(default=None)
):
    user = global_user(authorization)
    user_id = np_user_id(user)

    with get_db() as conn:
        with conn.cursor() as cursor:
            np_require_schema(cursor)

            cursor.execute("""
                DELETE FROM mg_notification_preferences
                WHERE user_id = %s
            """, (user_id,))

    return {
        "success": True,
        "preferences": dict(NP_DEFAULTS)
    }


# END OF SECTION 14

# ============================================================
# MASIH GRAM GLOBAL
# SECTION 15 — ACCOUNT ACTIVITY HISTORY ENGINE
# ============================================================

import uuid as activity_uuid_lib
import re as activity_re
from typing import Optional
from datetime import datetime, timezone, timedelta
from pydantic import BaseModel, Field
from fastapi import Header, HTTPException, Query

ACTIVITY_ENGINE_VERSION = "15.0.0"
ACTIVITY_MAX_PAGE_SIZE = 100

ACTIVITY_ALLOWED_TYPES = {
    "login",
    "logout",
    "login_failed",
    "password_changed",
    "profile_updated",
    "device_registered",
    "device_revoked",
    "session_revoked",
    "security_alert"
}


class ActivityCreateRequest(BaseModel):
    event_type: str
    device_name: Optional[str] = None
    platform: Optional[str] = None
    app_version: Optional[str] = None
    details: Optional[dict] = None


def activity_user_id(user):
    if isinstance(user, dict):
        value = user.get("id") or user.get("user_id")
    else:
        value = (
            getattr(user, "id", None)
            or getattr(user, "user_id", None)
        )

    if value is None:
        raise HTTPException(
            status_code=401,
            detail="User identity unavailable"
        )

    return str(value)


def activity_clean_text(value, maximum=120):
    if value is None:
        return None

    if not isinstance(value, str):
        raise HTTPException(
            status_code=422,
            detail="Invalid text value"
        )

    value = value.strip()

    if len(value) > maximum:
        raise HTTPException(
            status_code=422,
            detail="Text value is too long"
        )

    return value or None


def activity_validate_details(details):
    if details is None:
        return {}

    if not isinstance(details, dict):
        raise HTTPException(
            status_code=422,
            detail="Details must be an object"
        )

    # Avoid storing arbitrary or sensitive client data.
    allowed = {
        "method",
        "source",
        "reason",
        "location_label"
    }

    result = {}

    for key, value in details.items():
        if key not in allowed:
            continue

        if not isinstance(value, (str, int, bool)):
            continue

        if isinstance(value, str):
            value = value.strip()[:160]

        result[key] = value

    return result


def activity_require_schema(cursor):
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS mg_account_activity (
            id BIGSERIAL PRIMARY KEY,
            event_id UUID NOT NULL UNIQUE,
            user_id TEXT NOT NULL,
            event_type VARCHAR(40) NOT NULL,
            device_name VARCHAR(120),
            platform VARCHAR(40),
            app_version VARCHAR(40),
            ip_address INET,
            user_agent TEXT,
            details JSONB NOT NULL DEFAULT '{}'::jsonb,
            created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
        )
    """)

    cursor.execute("""
        CREATE INDEX IF NOT EXISTS
        idx_mg_account_activity_user_created
        ON mg_account_activity(user_id, created_at DESC)
    """)

    cursor.execute("""
        CREATE INDEX IF NOT EXISTS
        idx_mg_account_activity_type_created
        ON mg_account_activity(event_type, created_at DESC)
    """)


def activity_record(
    cursor,
    user_id,
    event_type,
    device_name=None,
    platform=None,
    app_version=None,
    ip_address=None,
    user_agent=None,
    details=None
):
    if event_type not in ACTIVITY_ALLOWED_TYPES:
        raise ValueError("Unsupported activity event type")

    cursor.execute("""
        INSERT INTO mg_account_activity (
            event_id,
            user_id,
            event_type,
            device_name,
            platform,
            app_version,
            ip_address,
            user_agent,
            details
        )
        VALUES (
            %s, %s, %s, %s, %s, %s,
            %s, %s, %s::jsonb
        )
        RETURNING id, event_id, created_at
    """, (
        str(activity_uuid_lib.uuid4()),
        str(user_id),
        event_type,
        activity_clean_text(device_name),
        activity_clean_text(platform, 40),
        activity_clean_text(app_version, 40),
        ip_address,
        activity_clean_text(user_agent, 500),
        activity_json.dumps(
            activity_validate_details(details),
            ensure_ascii=False
        )
    ))

    return cursor.fetchone()


@app.post("/api/v1/admin/migrations/account-activity/apply")
def activity_apply_migration(
    authorization: Optional[str] = Header(default=None)
):
    global_admin_check(authorization)

    with get_db() as conn:
        with conn.cursor() as cursor:
            activity_require_schema(cursor)

    return {
        "success": True,
        "engine": "ACCOUNT ACTIVITY HISTORY",
        "version": ACTIVITY_ENGINE_VERSION
    }


@app.post("/api/v1/account/activity")
def activity_create(
    data: ActivityCreateRequest,
    request: Request,
    authorization: Optional[str] = Header(default=None)
):
    user = global_user(authorization)
    user_id = activity_user_id(user)

    if data.event_type not in ACTIVITY_ALLOWED_TYPES:
        raise HTTPException(
            status_code=422,
            detail="Unsupported activity event type"
        )

    # Clients may report ordinary activity only.
    # Security-critical events must be recorded by trusted
    # authentication and session-management code.
    client_allowed = {
        "profile_updated",
        "device_registered"
    }

    if data.event_type not in client_allowed:
        raise HTTPException(
            status_code=403,
            detail="This event must be recorded by the server"
        )

    forwarded = request.headers.get("x-forwarded-for")
    ip_address = (
        forwarded.split(",")[0].strip()
        if forwarded else (
            request.client.host if request.client else None
        )
    )

    if ip_address:
        try:
            import ipaddress
            ip_address = str(ipaddress.ip_address(ip_address))
        except ValueError:
            ip_address = None

    user_agent = request.headers.get("user-agent")

    with get_db() as conn:
        with conn.cursor() as cursor:
            activity_require_schema(cursor)

            row = activity_record(
                cursor=cursor,
                user_id=user_id,
                event_type=data.event_type,
                device_name=data.device_name,
                platform=data.platform,
                app_version=data.app_version,
                ip_address=ip_address,
                user_agent=user_agent,
                details=data.details
            )

    return {
        "success": True,
        "event_id": str(row[1]),
        "created_at": row[2].isoformat()
    }


@app.get("/api/v1/account/activity")
def activity_list(
    event_type: Optional[str] = Query(default=None),
    limit: int = Query(default=30, ge=1, le=100),
    offset: int = Query(default=0, ge=0),
    authorization: Optional[str] = Header(default=None)
):
    user = global_user(authorization)
    user_id = activity_user_id(user)

    if event_type and event_type not in ACTIVITY_ALLOWED_TYPES:
        raise HTTPException(
            status_code=422,
            detail="Invalid event type"
        )

    with get_db() as conn:
        with conn.cursor() as cursor:
            activity_require_schema(cursor)

            if event_type:
                cursor.execute("""
                    SELECT
                        id, event_id, event_type,
                        device_name, platform, app_version,
                        ip_address::text, user_agent,
                        details, created_at
                    FROM mg_account_activity
                    WHERE user_id = %s
                      AND event_type = %s
                    ORDER BY created_at DESC, id DESC
                    LIMIT %s OFFSET %s
                """, (
                    user_id,
                    event_type,
                    limit,
                    offset
                ))
            else:
                cursor.execute("""
                    SELECT
                        id, event_id, event_type,
                        device_name, platform, app_version,
                        ip_address::text, user_agent,
                        details, created_at
                    FROM mg_account_activity
                    WHERE user_id = %s
                    ORDER BY created_at DESC, id DESC
                    LIMIT %s OFFSET %s
                """, (
                    user_id,
                    limit,
                    offset
                ))

            rows = cursor.fetchall()

            cursor.execute("""
                SELECT COUNT(*)
                FROM mg_account_activity
                WHERE user_id = %s
                  AND (%s IS NULL OR event_type = %s)
            """, (
                user_id,
                event_type,
                event_type
            ))

            total = cursor.fetchone()[0]

    items = []

    for row in rows:
        items.append({
            "id": row[0],
            "event_id": str(row[1]),
            "event_type": row[2],
            "device_name": row[3],
            "platform": row[4],
            "app_version": row[5],
            "ip_address": row[6],
            "user_agent": row[7],
            "details": row[8],
            "created_at": (
                row[9].isoformat() if row[9] else None
            )
        })

    return {
        "success": True,
        "total": total,
        "limit": limit,
        "offset": offset,
        "items": items
    }


@app.delete("/api/v1/account/activity")
def activity_clear_own(
    authorization: Optional[str] = Header(default=None)
):
    user = global_user(authorization)
    user_id = activity_user_id(user)

    with get_db() as conn:
        with conn.cursor() as cursor:
            activity_require_schema(cursor)

            cursor.execute("""
                DELETE FROM mg_account_activity
                WHERE user_id = %s
            """, (user_id,))

            deleted = cursor.rowcount

    return {
        "success": True,
        "deleted_count": deleted
    }


@app.post("/api/v1/admin/account-activity/cleanup")
def activity_admin_cleanup(
    days: int = Query(default=365, ge=30, le=3650),
    authorization: Optional[str] = Header(default=None)
):
    global_admin_check(authorization)

    with get_db() as conn:
        with conn.cursor() as cursor:
            activity_require_schema(cursor)

            cursor.execute("""
                DELETE FROM mg_account_activity
                WHERE created_at < NOW() - (%s * INTERVAL '1 day')
            """, (days,))

            deleted = cursor.rowcount

    return {
        "success": True,
        "retention_days": days,
        "deleted_count": deleted
    }


# END OF SECTION 15

# ============================================================
# MASIH GRAM GLOBAL
# SECTION 16 — USER DATA EXPORT ENGINE
# ============================================================

import json as export_json
import uuid as export_uuid
from datetime import datetime, timezone, timedelta
from typing import Optional
from fastapi import Header, HTTPException
from pydantic import BaseModel, Field


EXPORT_ENGINE_VERSION = "16.0.0"
EXPORT_MAX_REQUESTS_PER_DAY = 3
EXPORT_MAX_RECORDS_PER_TABLE = 5000


class ExportRequestModel(BaseModel):
    include_profile: bool = True
    include_posts: bool = True
    include_comments: bool = True
    include_preferences: bool = True
    include_activity: bool = True


def export_user_id(user):
    if isinstance(user, dict):
        value = user.get("id") or user.get("user_id")
    else:
        value = (
            getattr(user, "id", None)
            or getattr(user, "user_id", None)
        )

    if value is None:
        raise HTTPException(
            status_code=401,
            detail="User identity unavailable"
        )

    return str(value)


def export_require_schema(cursor):
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS mg_data_export_requests (
            id UUID PRIMARY KEY,
            user_id TEXT NOT NULL,
            status VARCHAR(20) NOT NULL DEFAULT 'completed',
            options JSONB NOT NULL DEFAULT '{}'::jsonb,
            result JSONB,
            created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
            completed_at TIMESTAMPTZ
        )
    """)

    cursor.execute("""
        CREATE INDEX IF NOT EXISTS
        idx_mg_data_export_user_created
        ON mg_data_export_requests(user_id, created_at DESC)
    """)


def export_safe_rows(cursor, query, params, columns):
    cursor.execute(query, params)
    rows = cursor.fetchmany(EXPORT_MAX_RECORDS_PER_TABLE + 1)

    if len(rows) > EXPORT_MAX_RECORDS_PER_TABLE:
        raise HTTPException(
            status_code=413,
            detail="Export contains too many records"
        )

    result = []

    for row in rows:
        item = {}

        for index, column in enumerate(columns):
            value = row[index]

            if isinstance(value, datetime):
                value = value.isoformat()
            elif isinstance(value, (dict, list)):
                pass
            elif hasattr(value, "hex") and not isinstance(value, str):
                value = str(value)

            item[column] = value

        result.append(item)

    return result


@app.post("/api/v1/users/me/data-export")
def export_create(
    data: ExportRequestModel,
    authorization: Optional[str] = Header(default=None)
):
    user = global_user(authorization)
    user_id = export_user_id(user)

    options = data.dict()

    with get_db() as conn:
        with conn.cursor() as cursor:
            export_require_schema(cursor)

            cursor.execute("""
                SELECT COUNT(*)
                FROM mg_data_export_requests
                WHERE user_id = %s
                  AND created_at >= NOW() - INTERVAL '1 day'
            """, (user_id,))

            if cursor.fetchone()[0] >= EXPORT_MAX_REQUESTS_PER_DAY:
                raise HTTPException(
                    status_code=429,
                    detail="Daily export request limit reached"
                )

            export_data = {
                "format": "MASIH_GRAM_USER_EXPORT",
                "version": EXPORT_ENGINE_VERSION,
                "generated_at": datetime.now(
                    timezone.utc
                ).isoformat(),
                "account": {
                    "user_id": user_id
                },
                "data": {}
            }

            if data.include_profile:
                cursor.execute("""
                    SELECT
                        display_name,
                        bio,
                        avatar_url,
                        cover_url,
                        language,
                        timezone,
                        profile_visibility
                    FROM mg_user_profiles
                    WHERE user_id = %s
                """, (user_id,))

                row = cursor.fetchone()

                export_data["data"]["profile"] = (
                    {
                        "display_name": row[0],
                        "bio": row[1],
                        "avatar_url": row[2],
                        "cover_url": row[3],
                        "language": row[4],
                        "timezone": row[5],
                        "profile_visibility": row[6]
                    } if row else None
                )

            if data.include_posts:
                export_data["data"]["posts"] = export_safe_rows(
                    cursor,
                    """
                    SELECT id, content, media_url,
                           visibility, created_at
                    FROM mg_social_posts
                    WHERE user_id = %s
                    ORDER BY created_at DESC
                    LIMIT %s
                    """,
                    (user_id, EXPORT_MAX_RECORDS_PER_TABLE),
                    [
                        "id", "content", "media_url",
                        "visibility", "created_at"
                    ]
                )

            if data.include_comments:
                export_data["data"]["comments"] = export_safe_rows(
                    cursor,
                    """
                    SELECT id, post_id, content, created_at
                    FROM mg_social_comments
                    WHERE user_id = %s
                    ORDER BY created_at DESC
                    LIMIT %s
                    """,
                    (user_id, EXPORT_MAX_RECORDS_PER_TABLE),
                    ["id", "post_id", "content", "created_at"]
                )

            if data.include_preferences:
                cursor.execute("""
                    SELECT preferences
                    FROM mg_user_preferences
                    WHERE user_id = %s
                """, (user_id,))

                row = cursor.fetchone()

                export_data["data"]["preferences"] = (
                    row[0] if row else {}
                )

                cursor.execute("""
                    SELECT preferences
                    FROM mg_notification_preferences
                    WHERE user_id = %s
                """, (user_id,))

                row = cursor.fetchone()

                export_data["data"]["notification_preferences"] = (
                    row[0] if row else {}
                )

            if data.include_activity:
                export_data["data"]["activity"] = export_safe_rows(
                    cursor,
                    """
                    SELECT event_type, device_name, platform,
                           app_version, created_at
                    FROM mg_account_activity
                    WHERE user_id = %s
                    ORDER BY created_at DESC
                    LIMIT %s
                    """,
                    (user_id, EXPORT_MAX_RECORDS_PER_TABLE),
                    [
                        "event_type", "device_name",
                        "platform", "app_version", "created_at"
                    ]
                )

            request_id = str(export_uuid.uuid4())

            cursor.execute("""
                INSERT INTO mg_data_export_requests (
                    id, user_id, status, options,
                    result, completed_at
                )
                VALUES (
                    %s, %s, 'completed',
                    %s::jsonb, %s::jsonb, NOW()
                )
            """, (
                request_id,
                user_id,
                export_json.dumps(options),
                export_json.dumps(
                    export_data,
                    ensure_ascii=False,
                    default=str
                )
            ))

    return {
        "success": True,
        "request_id": request_id,
        "status": "completed",
        "format": "JSON",
        "data": export_data
    }


@app.get("/api/v1/users/me/data-export/{request_id}")
def export_get(
    request_id: str,
    authorization: Optional[str] = Header(default=None)
):
    user = global_user(authorization)
    user_id = export_user_id(user)

    try:
        request_uuid = str(export_uuid.UUID(request_id))
    except (ValueError, TypeError, AttributeError):
        raise HTTPException(
            status_code=422,
            detail="Invalid export request ID"
        )

    with get_db() as conn:
        with conn.cursor() as cursor:
            export_require_schema(cursor)

            cursor.execute("""
                SELECT id, status, options,
                       result, created_at, completed_at
                FROM mg_data_export_requests
                WHERE id = %s AND user_id = %s
            """, (request_uuid, user_id))

            row = cursor.fetchone()

    if not row:
        raise HTTPException(
            status_code=404,
            detail="Export request not found"
        )

    return {
        "success": True,
        "request_id": str(row[0]),
        "status": row[1],
        "options": row[2],
        "data": row[3],
        "created_at": (
            row[4].isoformat() if row[4] else None
        ),
        "completed_at": (
            row[5].isoformat() if row[5] else None
        )
    }


@app.get("/api/v1/users/me/data-exports")
def export_list(
    limit: int = 20,
    offset: int = 0,
    authorization: Optional[str] = Header(default=None)
):
    user = global_user(authorization)
    user_id = export_user_id(user)

    if not 1 <= limit <= 100 or offset < 0:
        raise HTTPException(
            status_code=422,
            detail="Invalid pagination"
        )

    with get_db() as conn:
        with conn.cursor() as cursor:
            export_require_schema(cursor)

            cursor.execute("""
                SELECT id, status, options,
                       created_at, completed_at
                FROM mg_data_export_requests
                WHERE user_id = %s
                ORDER BY created_at DESC
                LIMIT %s OFFSET %s
            """, (user_id, limit, offset))

            rows = cursor.fetchall()

    return {
        "success": True,
        "items": [
            {
                "request_id": str(row[0]),
                "status": row[1],
                "options": row[2],
                "created_at": (
                    row[3].isoformat() if row[3] else None
                ),
                "completed_at": (
                    row[4].isoformat() if row[4] else None
                )
            }
            for row in rows
        ],
        "limit": limit,
        "offset": offset
    }


@app.delete("/api/v1/users/me/data-exports/{request_id}")
def export_delete(
    request_id: str,
    authorization: Optional[str] = Header(default=None)
):
    user = global_user(authorization)
    user_id = export_user_id(user)

    try:
        request_uuid = str(export_uuid.UUID(request_id))
    except (ValueError, TypeError, AttributeError):
        raise HTTPException(
            status_code=422,
            detail="Invalid export request ID"
        )

    with get_db() as conn:
        with conn.cursor() as cursor:
            export_require_schema(cursor)

            cursor.execute("""
                DELETE FROM mg_data_export_requests
                WHERE id = %s AND user_id = %s
            """, (request_uuid, user_id))

            deleted = cursor.rowcount

    if not deleted:
        raise HTTPException(
            status_code=404,
            detail="Export request not found"
        )

    return {
        "success": True,
        "deleted": True
    }


# END OF SECTION 16

# ============================================================
# MASIH GRAM GLOBAL
# SECTION 17
# ADVANCED API KEY & ACCESS CONTROL ENGINE
# ============================================================

import secrets as mg17_secrets
import hashlib as mg17_hashlib
import uuid as mg17_uuid
import re as mg17_re
from datetime import datetime, timezone, timedelta
from typing import Optional

from pydantic import BaseModel, Field
from fastapi import Header, HTTPException, Query


MG17_VERSION = "17.0.0"
MG17_PREFIX = "mgk_"
MG17_MAX_DAILY_LIMIT = 100000
MG17_MAX_ACTIVE_KEYS = 20


class MG17CreateKey(BaseModel):
    name: str = Field(min_length=2, max_length=80)
    daily_limit: int = Field(default=1000, ge=1, le=100000)
    expires_in_days: int = Field(default=30, ge=1, le=365)


class MG17KeyStatus(BaseModel):
    active: bool


def mg17_hash(value: str) -> str:
    return mg17_hashlib.sha256(
        value.encode("utf-8")
    ).hexdigest()


def mg17_user_id(user):
    if isinstance(user, dict):
        value = user.get("id") or user.get("user_id")
    else:
        value = (
            getattr(user, "id", None)
            or getattr(user, "user_id", None)
        )

    if value is None:
        raise HTTPException(
            status_code=401,
            detail="Authentication required"
        )

    return str(value)


def mg17_require_user(authorization):
    if not authorization:
        raise HTTPException(
            status_code=401,
            detail="Authentication required"
        )

    # Uses the existing authentication verifier without
    # depending on any social or feature-engine tables.
    user = global_user(authorization)
    return mg17_user_id(user)


def mg17_require_schema(cursor):
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS mg17_access_keys (
            id UUID PRIMARY KEY,
            user_id TEXT NOT NULL,
            name VARCHAR(80) NOT NULL,
            key_hash CHAR(64) NOT NULL UNIQUE,
            key_prefix VARCHAR(16) NOT NULL,
            daily_limit INTEGER NOT NULL DEFAULT 1000,
            active BOOLEAN NOT NULL DEFAULT TRUE,
            expires_at TIMESTAMPTZ NOT NULL,
            created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
            last_used_at TIMESTAMPTZ,
            revoked_at TIMESTAMPTZ
        )
    """)

    cursor.execute("""
        CREATE INDEX IF NOT EXISTS
        mg17_access_keys_user_idx
        ON mg17_access_keys(user_id, created_at DESC)
    """)

    cursor.execute("""
        CREATE TABLE IF NOT EXISTS mg17_access_usage (
            id BIGSERIAL PRIMARY KEY,
            key_id UUID NOT NULL
                REFERENCES mg17_access_keys(id)
                ON DELETE CASCADE,
            used_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
        )
    """)

    cursor.execute("""
        CREATE INDEX IF NOT EXISTS
        mg17_access_usage_key_date_idx
        ON mg17_access_usage(key_id, used_at DESC)
    """)


def mg17_validate_key_name(name):
    if not isinstance(name, str):
        raise HTTPException(
            status_code=422,
            detail="Invalid key name"
        )

    name = name.strip()

    if not 2 <= len(name) <= 80:
        raise HTTPException(
            status_code=422,
            detail="Key name must contain 2 to 80 characters"
        )

    return name


@app.post("/api/v1/access-keys")
def mg17_create_key(
    data: MG17CreateKey,
    authorization: Optional[str] = Header(default=None)
):
    user_id = mg17_require_user(authorization)
    name = mg17_validate_key_name(data.name)

    raw_key = MG17_PREFIX + mg17_secrets.token_urlsafe(40)
    key_hash = mg17_hash(raw_key)
    key_prefix = raw_key[:12]

    expires_at = (
        datetime.now(timezone.utc)
        + timedelta(days=data.expires_in_days)
    )

    with get_db() as conn:
        with conn.cursor() as cursor:
            mg17_require_schema(cursor)

            cursor.execute("""
                SELECT COUNT(*)
                FROM mg17_access_keys
                WHERE user_id = %s
                  AND active = TRUE
                  AND expires_at > NOW()
            """, (user_id,))

            active_count = cursor.fetchone()[0]

            if active_count >= MG17_MAX_ACTIVE_KEYS:
                raise HTTPException(
                    status_code=429,
                    detail="Maximum active key limit reached"
                )

            cursor.execute("""
                INSERT INTO mg17_access_keys (
                    id, user_id, name, key_hash,
                    key_prefix, daily_limit, expires_at
                )
                VALUES (%s, %s, %s, %s, %s, %s, %s)
                RETURNING id, created_at
            """, (
                str(mg17_uuid.uuid4()),
                user_id,
                name,
                key_hash,
                key_prefix,
                data.daily_limit,
                expires_at
            ))

            row = cursor.fetchone()

    return {
        "success": True,
        "id": str(row[0]),
        "name": name,
        "api_key": raw_key,
        "prefix": key_prefix,
        "daily_limit": data.daily_limit,
        "expires_at": expires_at.isoformat(),
        "created_at": row[1].isoformat(),
        "warning": "The complete API key is shown only once."
    }


@app.get("/api/v1/access-keys")
def mg17_list_keys(
    authorization: Optional[str] = Header(default=None)
):
    user_id = mg17_require_user(authorization)

    with get_db() as conn:
        with conn.cursor() as cursor:
            mg17_require_schema(cursor)

            cursor.execute("""
                SELECT
                    id, name, key_prefix, daily_limit,
                    active, expires_at, created_at,
                    last_used_at, revoked_at
                FROM mg17_access_keys
                WHERE user_id = %s
                ORDER BY created_at DESC
            """, (user_id,))

            rows = cursor.fetchall()

    return {
        "success": True,
        "items": [
            {
                "id": str(row[0]),
                "name": row[1],
                "prefix": row[2],
                "daily_limit": row[3],
                "active": row[4],
                "expired": row[5] <= datetime.now(timezone.utc),
                "expires_at": row[5].isoformat(),
                "created_at": row[6].isoformat(),
                "last_used_at": (
                    row[7].isoformat() if row[7] else None
                ),
                "revoked_at": (
                    row[8].isoformat() if row[8] else None
                )
            }
            for row in rows
        ]
    }


@app.post("/api/v1/access-keys/{key_id}/revoke")
def mg17_revoke_key(
    key_id: str,
    authorization: Optional[str] = Header(default=None)
):
    user_id = mg17_require_user(authorization)

    try:
        key_id = str(mg17_uuid.UUID(key_id))
    except (ValueError, TypeError, AttributeError):
        raise HTTPException(
            status_code=422,
            detail="Invalid key ID"
        )

    with get_db() as conn:
        with conn.cursor() as cursor:
            mg17_require_schema(cursor)

            cursor.execute("""
                UPDATE mg17_access_keys
                SET active = FALSE,
                    revoked_at = NOW()
                WHERE id = %s
                  AND user_id = %s
                  AND active = TRUE
                RETURNING id
            """, (key_id, user_id))

            row = cursor.fetchone()

    if not row:
        raise HTTPException(
            status_code=404,
            detail="Active key not found"
        )

    return {
        "success": True,
        "revoked": True,
        "key_id": str(row[0])
    }


@app.delete("/api/v1/access-keys/{key_id}")
def mg17_delete_key(
    key_id: str,
    authorization: Optional[str] = Header(default=None)
):
    user_id = mg17_require_user(authorization)

    try:
        key_id = str(mg17_uuid.UUID(key_id))
    except (ValueError, TypeError, AttributeError):
        raise HTTPException(
            status_code=422,
            detail="Invalid key ID"
        )

    with get_db() as conn:
        with conn.cursor() as cursor:
            mg17_require_schema(cursor)

            cursor.execute("""
                DELETE FROM mg17_access_keys
                WHERE id = %s AND user_id = %s
                RETURNING id
            """, (key_id, user_id))

            row = cursor.fetchone()

    if not row:
        raise HTTPException(
            status_code=404,
            detail="Key not found"
        )

    return {
        "success": True,
        "deleted": True
    }


@app.get("/api/v1/access-keys/{key_id}/statistics")
def mg17_key_statistics(
    key_id: str,
    authorization: Optional[str] = Header(default=None)
):
    user_id = mg17_require_user(authorization)

    try:
        key_id = str(mg17_uuid.UUID(key_id))
    except (ValueError, TypeError, AttributeError):
        raise HTTPException(
            status_code=422,
            detail="Invalid key ID"
        )

    with get_db() as conn:
        with conn.cursor() as cursor:
            mg17_require_schema(cursor)

            cursor.execute("""
                SELECT
                    k.id,
                    k.name,
                    k.daily_limit,
                    k.active,
                    k.expires_at,
                    COUNT(u.id) FILTER (
                        WHERE u.used_at >= NOW() - INTERVAL '24 hours'
                    ),
                    COUNT(u.id)
                FROM mg17_access_keys k
                LEFT JOIN mg17_access_usage u
                    ON u.key_id = k.id
                WHERE k.id = %s
                  AND k.user_id = %s
                GROUP BY k.id
            """, (key_id, user_id))

            row = cursor.fetchone()

    if not row:
        raise HTTPException(
            status_code=404,
            detail="Key not found"
        )

    return {
        "success": True,
        "key_id": str(row[0]),
        "name": row[1],
        "daily_limit": row[2],
        "active": row[3],
        "expires_at": row[4].isoformat(),
        "requests_last_24_hours": row[5],
        "requests_total": row[6],
        "remaining_daily": max(0, row[2] - row[5])
    }


@app.post("/api/v1/access-keys/verify")
def mg17_verify_key(
    x_api_key: str = Header(..., alias="X-API-Key")
):
    if not isinstance(x_api_key, str):
        raise HTTPException(
            status_code=401,
            detail="Invalid API key"
        )

    if not x_api_key.startswith(MG17_PREFIX):
        raise HTTPException(
            status_code=401,
            detail="Invalid API key"
        )

    key_hash = mg17_hash(x_api_key)

    with get_db() as conn:
        with conn.cursor() as cursor:
            mg17_require_schema(cursor)

            cursor.execute("""
                SELECT id, user_id, daily_limit, expires_at
                FROM mg17_access_keys
                WHERE key_hash = %s
                  AND active = TRUE
                  AND expires_at > NOW()
                FOR UPDATE
            """, (key_hash,))

            row = cursor.fetchone()

            if not row:
                raise HTTPException(
                    status_code=401,
                    detail="Invalid or expired API key"
                )

            cursor.execute("""
                SELECT COUNT(*)
                FROM mg17_access_usage
                WHERE key_id = %s
                  AND used_at >= NOW() - INTERVAL '24 hours'
            """, (str(row[0]),))

            used = cursor.fetchone()[0]

            if used >= row[2]:
                raise HTTPException(
                    status_code=429,
                    detail="API key daily limit reached"
                )

            cursor.execute("""
                INSERT INTO mg17_access_usage (key_id)
                VALUES (%s)
            """, (str(row[0]),))

            cursor.execute("""
                UPDATE mg17_access_keys
                SET last_used_at = NOW()
                WHERE id = %s
            """, (str(row[0]),))

    return {
        "success": True,
        "valid": True,
        "owner_id": row[1],
        "expires_at": row[3].isoformat()
    }


# END OF SECTION 17

# ============================================================
# MASIH GRAM GLOBAL
# SECTION 18 — SYSTEM HEALTH & DIAGNOSTICS ENGINE
# ============================================================

import time as mg18_time
import uuid as mg18_uuid
import json as mg18_json
from datetime import datetime, timezone
from typing import Optional
from pydantic import BaseModel, Field
from fastapi import Header, HTTPException, Query


MG18_VERSION = "18.0.0"
MG18_HISTORY_LIMIT = 5000


class MG18DiagnosticEvent(BaseModel):
    component: str = Field(min_length=2, max_length=80)
    severity: str = Field(default="info")
    message: str = Field(min_length=1, max_length=500)


def mg18_require_schema(cursor):
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS mg18_health_history (
            id BIGSERIAL PRIMARY KEY,
            check_id UUID NOT NULL UNIQUE,
            component VARCHAR(80) NOT NULL,
            status VARCHAR(20) NOT NULL,
            response_ms DOUBLE PRECISION,
            message TEXT,
            created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
        )
    """)

    cursor.execute("""
        CREATE INDEX IF NOT EXISTS
        mg18_health_history_created_idx
        ON mg18_health_history(created_at DESC)
    """)

    cursor.execute("""
        CREATE INDEX IF NOT EXISTS
        mg18_health_history_component_idx
        ON mg18_health_history(component, created_at DESC)
    """)


def mg18_record(cursor, component, status, response_ms, message):
    cursor.execute("""
        INSERT INTO mg18_health_history (
            check_id,
            component,
            status,
            response_ms,
            message
        )
        VALUES (%s, %s, %s, %s, %s)
        RETURNING id, created_at
    """, (
        str(mg18_uuid.uuid4()),
        component,
        status,
        response_ms,
        message
    ))

    return cursor.fetchone()


def mg18_admin(authorization):
    if not authorization:
        raise HTTPException(
            status_code=401,
            detail="Authentication required"
        )

    # Uses the project's existing admin authorization.
    global_admin_check(authorization)


@app.get("/api/v1/system/health")
def mg18_health():
    started = mg18_time.perf_counter()

    try:
        with get_db() as conn:
            with conn.cursor() as cursor:
                cursor.execute("SELECT 1")
                database_ok = cursor.fetchone()[0] == 1

                cursor.execute("""
                    SELECT pg_database_size(current_database())
                """)
                database_size = cursor.fetchone()[0]

        elapsed = (
            mg18_time.perf_counter() - started
        ) * 1000

        return {
            "success": True,
            "service": "MASIH GRAM",
            "version": MG18_VERSION,
            "status": "healthy" if database_ok else "degraded",
            "database": {
                "status": "connected",
                "response_ms": round(elapsed, 3),
                "size_bytes": database_size
            },
            "checked_at": datetime.now(
                timezone.utc
            ).isoformat()
        }

    except Exception:
        return {
            "success": False,
            "service": "MASIH GRAM",
            "version": MG18_VERSION,
            "status": "unhealthy",
            "database": {
                "status": "unavailable"
            },
            "checked_at": datetime.now(
                timezone.utc
            ).isoformat()
        }


@app.get("/api/v1/system/health/database")
def mg18_database_health():
    started = mg18_time.perf_counter()

    try:
        with get_db() as conn:
            with conn.cursor() as cursor:
                cursor.execute("""
                    SELECT
                        current_database(),
                        current_user,
                        pg_database_size(current_database()),
                        NOW()
                """)

                row = cursor.fetchone()

        elapsed = (
            mg18_time.perf_counter() - started
        ) * 1000

        return {
            "success": True,
            "database": row[0],
            "database_user": row[1],
            "size_bytes": row[2],
            "server_time": row[3].isoformat(),
            "response_ms": round(elapsed, 3),
            "status": "connected"
        }

    except Exception:
        raise HTTPException(
            status_code=503,
            detail="Database health check failed"
        )


@app.post("/api/v1/admin/migrations/system-health/apply")
def mg18_apply_migration(
    authorization: Optional[str] = Header(default=None)
):
    mg18_admin(authorization)

    with get_db() as conn:
        with conn.cursor() as cursor:
            mg18_require_schema(cursor)

    return {
        "success": True,
        "engine": "SYSTEM HEALTH",
        "version": MG18_VERSION
    }


@app.post("/api/v1/admin/system-health/events")
def mg18_create_event(
    data: MG18DiagnosticEvent,
    authorization: Optional[str] = Header(default=None)
):
    mg18_admin(authorization)

    if data.severity not in (
        "info", "warning", "error", "critical"
    ):
        raise HTTPException(
            status_code=422,
            detail="Invalid severity"
        )

    component = data.component.strip()
    message = data.message.strip()

    if not component or not message:
        raise HTTPException(
            status_code=422,
            detail="Component and message are required"
        )

    with get_db() as conn:
        with conn.cursor() as cursor:
            mg18_require_schema(cursor)

            row = mg18_record(
                cursor,
                component,
                data.severity,
                None,
                message
            )

    return {
        "success": True,
        "event_id": row[0],
        "created_at": row[1].isoformat()
    }


@app.get("/api/v1/admin/system-health/history")
def mg18_history(
    limit: int = Query(default=50, ge=1, le=200),
    offset: int = Query(default=0, ge=0),
    component: Optional[str] = Query(default=None),
    authorization: Optional[str] = Header(default=None)
):
    mg18_admin(authorization)

    with get_db() as conn:
        with conn.cursor() as cursor:
            mg18_require_schema(cursor)

            cursor.execute("""
                SELECT
                    id,
                    check_id,
                    component,
                    status,
                    response_ms,
                    message,
                    created_at
                FROM mg18_health_history
                WHERE (%s IS NULL OR component = %s)
                ORDER BY created_at DESC, id DESC
                LIMIT %s OFFSET %s
            """, (
                component,
                component,
                limit,
                offset
            ))

            rows = cursor.fetchall()

            cursor.execute("""
                SELECT COUNT(*)
                FROM mg18_health_history
                WHERE (%s IS NULL OR component = %s)
            """, (component, component))

            total = cursor.fetchone()[0]

    return {
        "success": True,
        "total": total,
        "limit": limit,
        "offset": offset,
        "items": [
            {
                "id": row[0],
                "check_id": str(row[1]),
                "component": row[2],
                "status": row[3],
                "response_ms": row[4],
                "message": row[5],
                "created_at": (
                    row[6].isoformat() if row[6] else None
                )
            }
            for row in rows
        ]
    }


@app.get("/api/v1/admin/system-health/statistics")
def mg18_statistics(
    authorization: Optional[str] = Header(default=None)
):
    mg18_admin(authorization)

    with get_db() as conn:
        with conn.cursor() as cursor:
            mg18_require_schema(cursor)

            cursor.execute("""
                SELECT
                    COUNT(*),
                    COUNT(*) FILTER (WHERE status = 'error'),
                    COUNT(*) FILTER (WHERE status = 'warning'),
                    COUNT(*) FILTER (WHERE status = 'critical'),
                    AVG(response_ms)
                FROM mg18_health_history
                WHERE created_at >= NOW() - INTERVAL '24 hours'
            """)

            row = cursor.fetchone()

            cursor.execute("""
                SELECT component, COUNT(*)
                FROM mg18_health_history
                WHERE created_at >= NOW() - INTERVAL '24 hours'
                GROUP BY component
                ORDER BY COUNT(*) DESC
                LIMIT 20
            """)

            components = cursor.fetchall()

    return {
        "success": True,
        "period": "24_hours",
        "total_events": row[0],
        "errors": row[1],
        "warnings": row[2],
        "critical": row[3],
        "average_response_ms": (
            round(float(row[4]), 3)
            if row[4] is not None else None
        ),
        "components": [
            {
                "name": item[0],
                "events": item[1]
            }
            for item in components
        ]
    }


@app.delete("/api/v1/admin/system-health/history")
def mg18_clear_history(
    keep_days: int = Query(default=30, ge=1, le=3650),
    authorization: Optional[str] = Header(default=None)
):
    mg18_admin(authorization)

    with get_db() as conn:
        with conn.cursor() as cursor:
            mg18_require_schema(cursor)

            cursor.execute("""
                DELETE FROM mg18_health_history
                WHERE created_at <
                    NOW() - (%s * INTERVAL '1 day')
            """, (keep_days,))

            deleted = cursor.rowcount

    return {
        "success": True,
        "deleted_records": deleted,
        "retained_days": keep_days
    }


# END OF SECTION 18

# ============================================================
# MASIH GRAM GLOBAL
# SECTION 19 — SYSTEM CONFIGURATION ENGINE
# ============================================================

import json as mg19_json
import re as mg19_re
from datetime import datetime, timezone
from typing import Optional
from pydantic import BaseModel, Field
from fastapi import Header, HTTPException, Query


MG19_VERSION = "19.0.0"
MG19_KEY_PATTERN = mg19_re.compile(
    r"^[a-z][a-z0-9_.-]{1,79}$"
)


class MG19ConfigCreate(BaseModel):
    key: str = Field(min_length=2, max_length=80)
    value: object
    description: str = Field(default="", max_length=300)
    enabled: bool = True


class MG19ConfigUpdate(BaseModel):
    value: object
    description: Optional[str] = Field(
        default=None,
        max_length=300
    )
    enabled: Optional[bool] = None


def mg19_admin(authorization):
    if not authorization:
        raise HTTPException(
            status_code=401,
            detail="Authentication required"
        )
    global_admin_check(authorization)


def mg19_validate_key(key):
    if not isinstance(key, str):
        raise HTTPException(
            status_code=422,
            detail="Invalid configuration key"
        )

    key = key.strip().lower()

    if not MG19_KEY_PATTERN.fullmatch(key):
        raise HTTPException(
            status_code=422,
            detail="Configuration key format is invalid"
        )

    return key


def mg19_validate_value(value):
    try:
        encoded = mg19_json.dumps(
            value,
            ensure_ascii=False,
            allow_nan=False
        )
    except (TypeError, ValueError):
        raise HTTPException(
            status_code=422,
            detail="Configuration value must be valid JSON"
        )

    if len(encoded.encode("utf-8")) > 16384:
        raise HTTPException(
            status_code=413,
            detail="Configuration value is too large"
        )

    return encoded


def mg19_require_schema(cursor):
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS mg19_system_configs (
            config_key VARCHAR(80) PRIMARY KEY,
            config_value JSONB NOT NULL,
            description VARCHAR(300) NOT NULL DEFAULT '',
            enabled BOOLEAN NOT NULL DEFAULT TRUE,
            revision BIGINT NOT NULL DEFAULT 1,
            updated_by TEXT,
            created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
            updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
        )
    """)

    cursor.execute("""
        CREATE TABLE IF NOT EXISTS mg19_config_history (
            id BIGSERIAL PRIMARY KEY,
            config_key VARCHAR(80) NOT NULL,
            old_value JSONB,
            new_value JSONB NOT NULL,
            old_enabled BOOLEAN,
            new_enabled BOOLEAN NOT NULL,
            changed_by TEXT,
            revision BIGINT NOT NULL,
            created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
        )
    """)

    cursor.execute("""
        CREATE INDEX IF NOT EXISTS
        mg19_config_history_key_idx
        ON mg19_config_history(config_key, created_at DESC)
    """)


@app.post("/api/v1/admin/migrations/configuration/apply")
def mg19_apply_migration(
    authorization: Optional[str] = Header(default=None)
):
    mg19_admin(authorization)

    with get_db() as conn:
        with conn.cursor() as cursor:
            mg19_require_schema(cursor)

    return {
        "success": True,
        "engine": "SYSTEM CONFIGURATION",
        "version": MG19_VERSION
    }


@app.post("/api/v1/admin/configuration")
def mg19_create_config(
    data: MG19ConfigCreate,
    authorization: Optional[str] = Header(default=None)
):
    mg19_admin(authorization)

    key = mg19_validate_key(data.key)
    encoded = mg19_validate_value(data.value)
    description = data.description.strip()

    with get_db() as conn:
        with conn.cursor() as cursor:
            mg19_require_schema(cursor)

            cursor.execute("""
                INSERT INTO mg19_system_configs (
                    config_key,
                    config_value,
                    description,
                    enabled,
                    updated_by
                )
                VALUES (%s, %s::jsonb, %s, %s, 'admin')
                ON CONFLICT (config_key) DO NOTHING
                RETURNING config_key, revision, created_at
            """, (
                key,
                encoded,
                description,
                data.enabled
            ))

            row = cursor.fetchone()

    if not row:
        raise HTTPException(
            status_code=409,
            detail="Configuration key already exists"
        )

    return {
        "success": True,
        "key": row[0],
        "revision": row[1],
        "created_at": row[2].isoformat()
    }


@app.get("/api/v1/configuration")
def mg19_public_configs():
    with get_db() as conn:
        with conn.cursor() as cursor:
            mg19_require_schema(cursor)

            cursor.execute("""
                SELECT config_key, config_value, revision
                FROM mg19_system_configs
                WHERE enabled = TRUE
                ORDER BY config_key
            """)

            rows = cursor.fetchall()

    return {
        "success": True,
        "items": [
            {
                "key": row[0],
                "value": row[1],
                "revision": row[2]
            }
            for row in rows
        ]
    }


@app.get("/api/v1/admin/configuration")
def mg19_admin_configs(
    limit: int = Query(default=100, ge=1, le=500),
    offset: int = Query(default=0, ge=0),
    authorization: Optional[str] = Header(default=None)
):
    mg19_admin(authorization)

    with get_db() as conn:
        with conn.cursor() as cursor:
            mg19_require_schema(cursor)

            cursor.execute("""
                SELECT
                    config_key,
                    config_value,
                    description,
                    enabled,
                    revision,
                    updated_by,
                    created_at,
                    updated_at
                FROM mg19_system_configs
                ORDER BY config_key
                LIMIT %s OFFSET %s
            """, (limit, offset))

            rows = cursor.fetchall()

    return {
        "success": True,
        "items": [
            {
                "key": row[0],
                "value": row[1],
                "description": row[2],
                "enabled": row[3],
                "revision": row[4],
                "updated_by": row[5],
                "created_at": row[6].isoformat(),
                "updated_at": row[7].isoformat()
            }
            for row in rows
        ],
        "limit": limit,
        "offset": offset
    }


@app.put("/api/v1/admin/configuration/{config_key}")
def mg19_update_config(
    config_key: str,
    data: MG19ConfigUpdate,
    authorization: Optional[str] = Header(default=None)
):
    mg19_admin(authorization)

    key = mg19_validate_key(config_key)
    encoded = mg19_validate_value(data.value)

    with get_db() as conn:
        with conn.cursor() as cursor:
            mg19_require_schema(cursor)

            cursor.execute("""
                SELECT config_value, enabled, revision
                FROM mg19_system_configs
                WHERE config_key = %s
                FOR UPDATE
            """, (key,))

            old = cursor.fetchone()

            if not old:
                raise HTTPException(
                    status_code=404,
                    detail="Configuration not found"
                )

            new_enabled = (
                data.enabled
                if data.enabled is not None
                else old[1]
            )

            new_description = data.description

            if new_description is None:
                cursor.execute("""
                    SELECT description
                    FROM mg19_system_configs
                    WHERE config_key = %s
                """, (key,))
                new_description = cursor.fetchone()[0]

            revision = old[2] + 1

            cursor.execute("""
                UPDATE mg19_system_configs
                SET config_value = %s::jsonb,
                    description = %s,
                    enabled = %s,
                    revision = %s,
                    updated_by = 'admin',
                    updated_at = NOW()
                WHERE config_key = %s
            """, (
                encoded,
                new_description,
                new_enabled,
                revision,
                key
            ))

            cursor.execute("""
                INSERT INTO mg19_config_history (
                    config_key,
                    old_value,
                    new_value,
                    old_enabled,
                    new_enabled,
                    changed_by,
                    revision
                )
                VALUES (
                    %s, %s::jsonb, %s::jsonb,
                    %s, %s, 'admin', %s
                )
            """, (
                key,
                mg19_json.dumps(old[0], ensure_ascii=False),
                encoded,
                old[1],
                new_enabled,
                revision
            ))

    return {
        "success": True,
        "key": key,
        "revision": revision,
        "enabled": new_enabled
    }


@app.get("/api/v1/admin/configuration/{config_key}/history")
def mg19_config_history(
    config_key: str,
    limit: int = Query(default=50, ge=1, le=200),
    authorization: Optional[str] = Header(default=None)
):
    mg19_admin(authorization)
    key = mg19_validate_key(config_key)

    with get_db() as conn:
        with conn.cursor() as cursor:
            mg19_require_schema(cursor)

            cursor.execute("""
                SELECT
                    id,
                    old_value,
                    new_value,
                    old_enabled,
                    new_enabled,
                    revision,
                    created_at
                FROM mg19_config_history
                WHERE config_key = %s
                ORDER BY created_at DESC, id DESC
                LIMIT %s
            """, (key, limit))

            rows = cursor.fetchall()

    return {
        "success": True,
        "key": key,
        "items": [
            {
                "id": row[0],
                "old_value": row[1],
                "new_value": row[2],
                "old_enabled": row[3],
                "new_enabled": row[4],
                "revision": row[5],
                "created_at": row[6].isoformat()
            }
            for row in rows
        ]
    }


@app.delete("/api/v1/admin/configuration/{config_key}")
def mg19_delete_config(
    config_key: str,
    authorization: Optional[str] = Header(default=None)
):
    mg19_admin(authorization)
    key = mg19_validate_key(config_key)

    with get_db() as conn:
        with conn.cursor() as cursor:
            mg19_require_schema(cursor)

            cursor.execute("""
                DELETE FROM mg19_system_configs
                WHERE config_key = %s
                RETURNING config_key
            """, (key,))

            row = cursor.fetchone()

    if not row:
        raise HTTPException(
            status_code=404,
            detail="Configuration not found"
        )

    return {
        "success": True,
        "deleted_key": row[0]
    }


# END OF SECTION 19

# ============================================================
# MASIH GRAM GLOBAL — SECTION 20
# GLOBAL ANNOUNCEMENTS & SCHEDULED BROADCAST CENTER
# ============================================================

import uuid as mg20_uuid
from datetime import datetime, timezone
from typing import Optional

from fastapi import Header, HTTPException, Query
from pydantic import BaseModel, Field


MG20_STATUSES = {"draft", "published", "paused", "archived"}
MG20_TARGETS = {"all", "android", "ios"}


# -------------------- MODELS --------------------

class MG20AnnouncementCreate(BaseModel):
    title: str = Field(..., min_length=2, max_length=180)
    body: str = Field(..., min_length=2, max_length=12000)
    priority: int = Field(default=1, ge=1, le=5)
    target: str = Field(default="all", max_length=20)
    starts_at: Optional[datetime] = None
    ends_at: Optional[datetime] = None


class MG20AnnouncementUpdate(BaseModel):
    title: Optional[str] = Field(default=None, min_length=2, max_length=180)
    body: Optional[str] = Field(default=None, min_length=2, max_length=12000)
    priority: Optional[int] = Field(default=None, ge=1, le=5)
    target: Optional[str] = Field(default=None, max_length=20)
    starts_at: Optional[datetime] = None
    ends_at: Optional[datetime] = None


class MG20AnnouncementStatus(BaseModel):
    status: str = Field(..., max_length=20)


# -------------------- HELPERS --------------------

def mg20_clean_text(value):
    if not isinstance(value, str):
        raise HTTPException(status_code=422, detail="Invalid text")
    value = value.strip()
    if not value:
        raise HTTPException(status_code=422, detail="Text cannot be empty")
    return value


def mg20_validate_target(target):
    if target not in MG20_TARGETS:
        raise HTTPException(status_code=422, detail="Invalid announcement target")


def mg20_validate_dates(starts_at, ends_at):
    if starts_at is not None and ends_at is not None:
        start = starts_at
        end = ends_at

        if start.tzinfo is None:
            start = start.replace(tzinfo=timezone.utc)
        if end.tzinfo is None:
            end = end.replace(tzinfo=timezone.utc)

        if end <= start:
            raise HTTPException(
                status_code=422,
                detail="ends_at must be later than starts_at"
            )


def mg20_require_schema(cursor):
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS mg20_announcements (
            id UUID PRIMARY KEY,
            title VARCHAR(180) NOT NULL,
            body TEXT NOT NULL,
            priority INTEGER NOT NULL DEFAULT 1
                CHECK (priority BETWEEN 1 AND 5),
            target VARCHAR(20) NOT NULL DEFAULT 'all'
                CHECK (target IN ('all', 'android', 'ios')),
            status VARCHAR(20) NOT NULL DEFAULT 'draft'
                CHECK (status IN ('draft', 'published', 'paused', 'archived')),
            starts_at TIMESTAMPTZ NULL,
            ends_at TIMESTAMPTZ NULL,
            views_count BIGINT NOT NULL DEFAULT 0,
            created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
            updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
            CHECK (ends_at IS NULL OR starts_at IS NULL OR ends_at > starts_at)
        )
    """)

    cursor.execute("""
        CREATE INDEX IF NOT EXISTS mg20_announcements_public_idx
        ON mg20_announcements (status, starts_at, ends_at, priority DESC)
    """)

    cursor.execute("""
        CREATE INDEX IF NOT EXISTS mg20_announcements_created_idx
        ON mg20_announcements (created_at DESC)
    """)


def mg20_row(cursor, row):
    if row is None:
        return None

    names = [column.name for column in cursor.description]
    return dict(zip(names, row))


def mg20_announcement_not_found():
    raise HTTPException(status_code=404, detail="Announcement not found")


def mg20_check_admin(x_admin_api_key):
    # Uses the existing MASIH GRAM administrator authentication.
    global_admin_check(x_admin_api_key)


# -------------------- MIGRATION --------------------

@app.post("/api/v1/admin/migrations/announcements/apply")
def mg20_apply_migration(
    x_admin_api_key: Optional[str] = Header(default=None)
):
    mg20_check_admin(x_admin_api_key)

    with get_db() as connection:
        with connection.cursor() as cursor:
            mg20_require_schema(cursor)

    return {
        "success": True,
        "module": "global_announcements",
        "version": "20.0"
    }


# -------------------- CREATE ANNOUNCEMENT --------------------

@app.post("/api/v1/admin/announcements")
def mg20_create_announcement(
    data: MG20AnnouncementCreate,
    x_admin_api_key: Optional[str] = Header(default=None)
):
    mg20_check_admin(x_admin_api_key)

    title = mg20_clean_text(data.title)
    body = mg20_clean_text(data.body)
    mg20_validate_target(data.target)
    mg20_validate_dates(data.starts_at, data.ends_at)

    announcement_id = mg20_uuid.uuid4()

    with get_db() as connection:
        with connection.cursor() as cursor:
            mg20_require_schema(cursor)

            cursor.execute("""
                INSERT INTO mg20_announcements (
                    id, title, body, priority, target,
                    status, starts_at, ends_at
                )
                VALUES (%s, %s, %s, %s, %s, 'draft', %s, %s)
                RETURNING id, title, body, priority, target,
                          status, starts_at, ends_at,
                          views_count, created_at, updated_at
            """, (
                announcement_id,
                title,
                body,
                data.priority,
                data.target,
                data.starts_at,
                data.ends_at
            ))

            result = mg20_row(cursor, cursor.fetchone())

    return {"success": True, "announcement": result}


# -------------------- ADMIN ANNOUNCEMENT LIST --------------------

@app.get("/api/v1/admin/announcements")
def mg20_admin_announcements(
    status: Optional[str] = Query(default=None),
    limit: int = Query(default=50, ge=1, le=200),
    offset: int = Query(default=0, ge=0),
    x_admin_api_key: Optional[str] = Header(default=None)
):
    mg20_check_admin(x_admin_api_key)

    if status is not None and status not in MG20_STATUSES:
        raise HTTPException(status_code=422, detail="Invalid status")

    with get_db() as connection:
        with connection.cursor() as cursor:
            mg20_require_schema(cursor)

            if status is None:
                cursor.execute("""
                    SELECT id, title, body, priority, target,
                           status, starts_at, ends_at,
                           views_count, created_at, updated_at
                    FROM mg20_announcements
                    ORDER BY created_at DESC
                    LIMIT %s OFFSET %s
                """, (limit, offset))
            else:
                cursor.execute("""
                    SELECT id, title, body, priority, target,
                           status, starts_at, ends_at,
                           views_count, created_at, updated_at
                    FROM mg20_announcements
                    WHERE status = %s
                    ORDER BY created_at DESC
                    LIMIT %s OFFSET %s
                """, (status, limit, offset))

            rows = [mg20_row(cursor, row) for row in cursor.fetchall()]

    return {
        "success": True,
        "count": len(rows),
        "limit": limit,
        "offset": offset,
        "items": rows
    }


# -------------------- UPDATE ANNOUNCEMENT --------------------

@app.patch("/api/v1/admin/announcements/{announcement_id}")
def mg20_update_announcement(
    announcement_id: str,
    data: MG20AnnouncementUpdate,
    x_admin_api_key: Optional[str] = Header(default=None)
):
    mg20_check_admin(x_admin_api_key)

    try:
        parsed_id = mg20_uuid.UUID(announcement_id)
    except (ValueError, TypeError, AttributeError):
        raise HTTPException(status_code=400, detail="Invalid announcement ID")

    changes = data.dict(exclude_unset=True)

    if not changes:
        raise HTTPException(status_code=422, detail="No update fields provided")

    allowed_fields = {
        "title", "body", "priority", "target",
        "starts_at", "ends_at"
    }

    for key in list(changes.keys()):
        if key not in allowed_fields:
            raise HTTPException(status_code=422, detail="Invalid update field")

    if "title" in changes and changes["title"] is not None:
        changes["title"] = mg20_clean_text(changes["title"])

    if "body" in changes and changes["body"] is not None:
        changes["body"] = mg20_clean_text(changes["body"])

    if "target" in changes and changes["target"] is not None:
        mg20_validate_target(changes["target"])

    with get_db() as connection:
        with connection.cursor() as cursor:
            mg20_require_schema(cursor)

            cursor.execute("""
                SELECT starts_at, ends_at
                FROM mg20_announcements
                WHERE id = %s
                FOR UPDATE
            """, (parsed_id,))

            current = cursor.fetchone()

            if current is None:
                mg20_announcement_not_found()

            new_start = changes.get("starts_at", current[0])
            new_end = changes.get("ends_at", current[1])

            mg20_validate_dates(new_start, new_end)

            assignments = []
            values = []

            for key, value in changes.items():
                assignments.append(key + " = %s")
                values.append(value)

            assignments.append("updated_at = NOW()")
            values.append(parsed_id)

            query = (
                "UPDATE mg20_announcements SET "
                + ", ".join(assignments)
                + " WHERE id = %s "
                + "RETURNING id, title, body, priority, target, status, "
                + "starts_at, ends_at, views_count, created_at, updated_at"
            )

            cursor.execute(query, tuple(values))
            result = mg20_row(cursor, cursor.fetchone())

    return {"success": True, "announcement": result}


# -------------------- PUBLISH / PAUSE / ARCHIVE --------------------

@app.patch("/api/v1/admin/announcements/{announcement_id}/status")
def mg20_change_announcement_status(
    announcement_id: str,
    data: MG20AnnouncementStatus,
    x_admin_api_key: Optional[str] = Header(default=None)
):
    mg20_check_admin(x_admin_api_key)

    if data.status not in MG20_STATUSES:
        raise HTTPException(status_code=422, detail="Invalid status")

    try:
        parsed_id = mg20_uuid.UUID(announcement_id)
    except (ValueError, TypeError, AttributeError):
        raise HTTPException(status_code=400, detail="Invalid announcement ID")

    with get_db() as connection:
        with connection.cursor() as cursor:
            mg20_require_schema(cursor)

            cursor.execute("""
                UPDATE mg20_announcements
                SET status = %s, updated_at = NOW()
                WHERE id = %s
                RETURNING id, title, status, starts_at, ends_at,
                          views_count, updated_at
            """, (data.status, parsed_id))

            result = mg20_row(cursor, cursor.fetchone())

            if result is None:
                mg20_announcement_not_found()

    return {"success": True, "announcement": result}


# -------------------- PUBLIC ANNOUNCEMENTS --------------------

@app.get("/api/v1/announcements")
def mg20_public_announcements(
    platform: str = Query(default="all"),
    limit: int = Query(default=20, ge=1, le=100)
):
    if platform not in MG20_TARGETS:
        raise HTTPException(status_code=422, detail="Invalid platform")

    with get_db() as connection:
        with connection.cursor() as cursor:
            mg20_require_schema(cursor)

            cursor.execute("""
                SELECT id, title, body, priority, target,
                       starts_at, ends_at, created_at
                FROM mg20_announcements
                WHERE status = 'published'
                  AND (starts_at IS NULL OR starts_at <= NOW())
                  AND (ends_at IS NULL OR ends_at > NOW())
                  AND (target = 'all' OR target = %s)
                ORDER BY priority DESC, created_at DESC
                LIMIT %s
            """, (platform, limit))

            rows = [mg20_row(cursor, row) for row in cursor.fetchall()]

    return {
        "success": True,
        "count": len(rows),
        "items": rows
    }


# -------------------- PUBLIC ANNOUNCEMENT DETAIL --------------------

@app.get("/api/v1/announcements/{announcement_id}")
def mg20_public_announcement_detail(announcement_id: str):
    try:
        parsed_id = mg20_uuid.UUID(announcement_id)
    except (ValueError, TypeError, AttributeError):
        raise HTTPException(status_code=400, detail="Invalid announcement ID")

    with get_db() as connection:
        with connection.cursor() as cursor:
            mg20_require_schema(cursor)

            cursor.execute("""
                UPDATE mg20_announcements
                SET views_count = views_count + 1
                WHERE id = %s
                  AND status = 'published'
                  AND (starts_at IS NULL OR starts_at <= NOW())
                  AND (ends_at IS NULL OR ends_at > NOW())
                RETURNING id, title, body, priority, target,
                          starts_at, ends_at, views_count, created_at
            """, (parsed_id,))

            result = mg20_row(cursor, cursor.fetchone())

            if result is None:
                mg20_announcement_not_found()

    return {"success": True, "announcement": result}


# -------------------- DELETE / ARCHIVE --------------------

@app.delete("/api/v1/admin/announcements/{announcement_id}")
def mg20_delete_announcement(
    announcement_id: str,
    x_admin_api_key: Optional[str] = Header(default=None)
):
    mg20_check_admin(x_admin_api_key)

    try:
        parsed_id = mg20_uuid.UUID(announcement_id)
    except (ValueError, TypeError, AttributeError):
        raise HTTPException(status_code=400, detail="Invalid announcement ID")

    with get_db() as connection:
        with connection.cursor() as cursor:
            mg20_require_schema(cursor)

            cursor.execute("""
                UPDATE mg20_announcements
                SET status = 'archived', updated_at = NOW()
                WHERE id = %s
                RETURNING id, status
            """, (parsed_id,))

            result = mg20_row(cursor, cursor.fetchone())

            if result is None:
                mg20_announcement_not_found()

    return {
        "success": True,
        "message": "Announcement archived",
        "announcement": result
    }


# ============================================================
# END OF SECTION 20
# ============================================================

# ============================================================
# MASIH GRAM GLOBAL — SECTION 21
# MAINTENANCE CONTROL CENTER
# ============================================================

import uuid as mg21_uuid
from datetime import datetime, timezone
from typing import Optional

from fastapi import Header, HTTPException
from pydantic import BaseModel, Field


MG21_PLATFORMS = {"all", "android", "ios"}


# -------------------- MODELS --------------------

class MG21MaintenanceUpdate(BaseModel):
    enabled: bool
    title: str = Field(default="تعمیرات سیستم", min_length=2, max_length=150)
    message: str = Field(default="سرویس موقتاً در حال به‌روزرسانی است.", min_length=2, max_length=5000)
    platform: str = Field(default="all", max_length=20)
    starts_at: Optional[datetime] = None
    ends_at: Optional[datetime] = None


# -------------------- HELPERS --------------------

def mg21_require_admin(api_key):
    global_admin_check(api_key)


def mg21_validate(data):
    if data.platform not in MG21_PLATFORMS:
        raise HTTPException(status_code=422, detail="Invalid platform")

    if data.starts_at and data.ends_at:
        start = data.starts_at
        end = data.ends_at

        if start.tzinfo is None:
            start = start.replace(tzinfo=timezone.utc)

        if end.tzinfo is None:
            end = end.replace(tzinfo=timezone.utc)

        if end <= start:
            raise HTTPException(
                status_code=422,
                detail="ends_at must be later than starts_at"
            )


def mg21_require_schema(cursor):
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS mg21_maintenance (
            id SMALLINT PRIMARY KEY CHECK (id = 1),
            enabled BOOLEAN NOT NULL DEFAULT FALSE,
            title VARCHAR(150) NOT NULL,
            message TEXT NOT NULL,
            platform VARCHAR(20) NOT NULL DEFAULT 'all',
            starts_at TIMESTAMPTZ NULL,
            ends_at TIMESTAMPTZ NULL,
            updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
            updated_by VARCHAR(120) NULL,
            CHECK (platform IN ('all', 'android', 'ios')),
            CHECK (
                ends_at IS NULL
                OR starts_at IS NULL
                OR ends_at > starts_at
            )
        )
    """)

    cursor.execute("""
        INSERT INTO mg21_maintenance (
            id, enabled, title, message, platform
        )
        VALUES (
            1, FALSE, 'تعمیرات سیستم',
            'سرویس در وضعیت عادی قرار دارد.', 'all'
        )
        ON CONFLICT (id) DO NOTHING
    """)

    cursor.execute("""
        CREATE TABLE IF NOT EXISTS mg21_maintenance_history (
            id UUID PRIMARY KEY,
            enabled BOOLEAN NOT NULL,
            title VARCHAR(150) NOT NULL,
            message TEXT NOT NULL,
            platform VARCHAR(20) NOT NULL,
            starts_at TIMESTAMPTZ NULL,
            ends_at TIMESTAMPTZ NULL,
            changed_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
            changed_by VARCHAR(120) NULL
        )
    """)


def mg21_row(cursor, row):
    if row is None:
        return None
    return dict(zip(
        [column.name for column in cursor.description],
        row
    ))


def mg21_is_active(row):
    if not row or not row["enabled"]:
        return False

    now = datetime.now(timezone.utc)
    start = row["starts_at"]
    end = row["ends_at"]

    if start is not None:
        if start.tzinfo is None:
            start = start.replace(tzinfo=timezone.utc)
        if now < start:
            return False

    if end is not None:
        if end.tzinfo is None:
            end = end.replace(tzinfo=timezone.utc)
        if now >= end:
            return False

    return True


# -------------------- MIGRATION --------------------

@app.post("/api/v1/admin/migrations/maintenance/apply")
def mg21_apply_migration(
    x_admin_api_key: Optional[str] = Header(default=None)
):
    mg21_require_admin(x_admin_api_key)

    with get_db() as connection:
        with connection.cursor() as cursor:
            mg21_require_schema(cursor)

    return {
        "success": True,
        "module": "maintenance_control",
        "version": "21.0"
    }


# -------------------- ADMIN READ --------------------

@app.get("/api/v1/admin/maintenance")
def mg21_admin_get(
    x_admin_api_key: Optional[str] = Header(default=None)
):
    mg21_require_admin(x_admin_api_key)

    with get_db() as connection:
        with connection.cursor() as cursor:
            mg21_require_schema(cursor)

            cursor.execute("""
                SELECT id, enabled, title, message, platform,
                       starts_at, ends_at, updated_at, updated_by
                FROM mg21_maintenance
                WHERE id = 1
            """)

            result = mg21_row(cursor, cursor.fetchone())

    result["currently_active"] = mg21_is_active(result)

    return {"success": True, "maintenance": result}


# -------------------- ADMIN UPDATE --------------------

@app.put("/api/v1/admin/maintenance")
def mg21_admin_update(
    data: MG21MaintenanceUpdate,
    x_admin_api_key: Optional[str] = Header(default=None)
):
    mg21_require_admin(x_admin_api_key)
    mg21_validate(data)

    title = data.title.strip()
    message = data.message.strip()

    if not title or not message:
        raise HTTPException(status_code=422, detail="Empty title or message")

    with get_db() as connection:
        with connection.cursor() as cursor:
            mg21_require_schema(cursor)

            cursor.execute("""
                SELECT enabled, title, message, platform,
                       starts_at, ends_at
                FROM mg21_maintenance
                WHERE id = 1
                FOR UPDATE
            """)

            previous = cursor.fetchone()

            cursor.execute("""
                UPDATE mg21_maintenance
                SET enabled = %s,
                    title = %s,
                    message = %s,
                    platform = %s,
                    starts_at = %s,
                    ends_at = %s,
                    updated_at = NOW(),
                    updated_by = 'admin'
                WHERE id = 1
                RETURNING id, enabled, title, message, platform,
                          starts_at, ends_at, updated_at
            """, (
                data.enabled,
                title,
                message,
                data.platform,
                data.starts_at,
                data.ends_at
            ))

            result = mg21_row(cursor, cursor.fetchone())

            cursor.execute("""
                INSERT INTO mg21_maintenance_history (
                    id, enabled, title, message, platform,
                    starts_at, ends_at, changed_by
                )
                VALUES (%s, %s, %s, %s, %s, %s, %s, 'admin')
            """, (
                mg21_uuid.uuid4(),
                data.enabled,
                title,
                message,
                data.platform,
                data.starts_at,
                data.ends_at
            ))

    result["currently_active"] = mg21_is_active(result)

    return {
        "success": True,
        "maintenance": result
    }


# -------------------- PUBLIC STATUS --------------------

@app.get("/api/v1/system/maintenance")
def mg21_public_status(
    platform: str = "all"
):
    if platform not in MG21_PLATFORMS:
        raise HTTPException(status_code=422, detail="Invalid platform")

    with get_db() as connection:
        with connection.cursor() as cursor:
            mg21_require_schema(cursor)

            cursor.execute("""
                SELECT enabled, title, message, platform,
                       starts_at, ends_at, updated_at
                FROM mg21_maintenance
                WHERE id = 1
            """)

            result = mg21_row(cursor, cursor.fetchone())

    active = mg21_is_active(result)

    platform_matches = (
        result["platform"] == "all"
        or platform == "all"
        or result["platform"] == platform
    )

    visible = active and platform_matches

    return {
        "success": True,
        "maintenance": {
            "active": visible,
            "title": result["title"] if visible else None,
            "message": result["message"] if visible else None,
            "starts_at": result["starts_at"] if visible else None,
            "ends_at": result["ends_at"] if visible else None,
            "updated_at": result["updated_at"]
        }
    }


# -------------------- ADMIN HISTORY --------------------

@app.get("/api/v1/admin/maintenance/history")
def mg21_admin_history(
    limit: int = 50,
    offset: int = 0,
    x_admin_api_key: Optional[str] = Header(default=None)
):
    mg21_require_admin(x_admin_api_key)

    if limit < 1 or limit > 200:
        raise HTTPException(status_code=422, detail="Invalid limit")

    if offset < 0:
        raise HTTPException(status_code=422, detail="Invalid offset")

    with get_db() as connection:
        with connection.cursor() as cursor:
            mg21_require_schema(cursor)

            cursor.execute("""
                SELECT id, enabled, title, message, platform,
                       starts_at, ends_at, changed_at, changed_by
                FROM mg21_maintenance_history
                ORDER BY changed_at DESC
                LIMIT %s OFFSET %s
            """, (limit, offset))

            rows = [
                mg21_row(cursor, row)
                for row in cursor.fetchall()
            ]

    return {
        "success": True,
        "count": len(rows),
        "items": rows
    }


# ============================================================
# END OF SECTION 21
# ============================================================

# ============================================================
# MASIH GRAM GLOBAL — SECTION 22
# GLOBAL RELEASE & VERSION CONTROL
# ============================================================

import uuid as mg22_uuid
import re as mg22_re
from typing import Optional

from fastapi import Header, HTTPException, Query
from pydantic import BaseModel, Field


MG22_PLATFORMS = {"android", "ios"}
MG22_STATUSES = {"draft", "published", "paused", "archived"}


# -------------------- MODELS --------------------

class MG22ReleaseCreate(BaseModel):
    platform: str
    version: str = Field(..., min_length=1, max_length=40)
    build_number: int = Field(..., ge=1)
    minimum_version: str = Field(..., min_length=1, max_length=40)
    force_update: bool = False
    download_url: Optional[str] = Field(default=None, max_length=2048)
    changelog: str = Field(default="", max_length=12000)


class MG22ReleaseStatus(BaseModel):
    status: str


# -------------------- VALIDATION --------------------

def mg22_valid_version(value):
    if not isinstance(value, str):
        return False
    return bool(mg22_re.fullmatch(r"[0-9]+(?:\.[0-9]+){0,3}", value.strip()))


def mg22_version_tuple(value):
    if not mg22_valid_version(value):
        raise HTTPException(status_code=422, detail="Invalid version format")
    return tuple(int(part) for part in value.strip().split("."))


def mg22_validate_release(data):
    if data.platform not in MG22_PLATFORMS:
        raise HTTPException(status_code=422, detail="Invalid platform")

    if not mg22_valid_version(data.version):
        raise HTTPException(status_code=422, detail="Invalid version")

    if not mg22_valid_version(data.minimum_version):
        raise HTTPException(status_code=422, detail="Invalid minimum version")

    if mg22_version_tuple(data.minimum_version) > mg22_version_tuple(data.version):
        raise HTTPException(
            status_code=422,
            detail="Minimum version cannot exceed release version"
        )

    if data.download_url:
        if not data.download_url.startswith("https://"):
            raise HTTPException(
                status_code=422,
                detail="Download URL must use HTTPS"
            )


def mg22_require_schema(cursor):
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS mg22_releases (
            id UUID PRIMARY KEY,
            platform VARCHAR(20) NOT NULL
                CHECK (platform IN ('android', 'ios')),
            version VARCHAR(40) NOT NULL,
            build_number INTEGER NOT NULL CHECK (build_number >= 1),
            minimum_version VARCHAR(40) NOT NULL,
            force_update BOOLEAN NOT NULL DEFAULT FALSE,
            download_url TEXT NULL,
            changelog TEXT NOT NULL DEFAULT '',
            status VARCHAR(20) NOT NULL DEFAULT 'draft'
                CHECK (status IN ('draft', 'published', 'paused', 'archived')),
            created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
            published_at TIMESTAMPTZ NULL,
            updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
            UNIQUE (platform, version, build_number)
        )
    """)

    cursor.execute("""
        CREATE INDEX IF NOT EXISTS mg22_releases_public_idx
        ON mg22_releases (platform, status, published_at DESC)
    """)


def mg22_row(cursor, row):
    if row is None:
        return None
    return dict(zip(
        [column.name for column in cursor.description],
        row
    ))


def mg22_require_admin(api_key):
    global_admin_check(api_key)


# -------------------- MIGRATION --------------------

@app.post("/api/v1/admin/migrations/releases/apply")
def mg22_apply_migration(
    x_admin_api_key: Optional[str] = Header(default=None)
):
    mg22_require_admin(x_admin_api_key)

    with get_db() as connection:
        with connection.cursor() as cursor:
            mg22_require_schema(cursor)

    return {
        "success": True,
        "module": "release_control",
        "version": "22.0"
    }


# -------------------- CREATE RELEASE --------------------

@app.post("/api/v1/admin/releases")
def mg22_create_release(
    data: MG22ReleaseCreate,
    x_admin_api_key: Optional[str] = Header(default=None)
):
    mg22_require_admin(x_admin_api_key)
    mg22_validate_release(data)

    release_id = mg22_uuid.uuid4()

    with get_db() as connection:
        with connection.cursor() as cursor:
            mg22_require_schema(cursor)

            cursor.execute("""
                INSERT INTO mg22_releases (
                    id, platform, version, build_number,
                    minimum_version, force_update,
                    download_url, changelog, status
                )
                VALUES (%s, %s, %s, %s, %s, %s, %s, %s, 'draft')
                RETURNING id, platform, version, build_number,
                          minimum_version, force_update,
                          download_url, changelog, status,
                          created_at, published_at, updated_at
            """, (
                release_id,
                data.platform,
                data.version.strip(),
                data.build_number,
                data.minimum_version.strip(),
                data.force_update,
                data.download_url,
                data.changelog.strip()
            ))

            result = mg22_row(cursor, cursor.fetchone())

    return {"success": True, "release": result}


# -------------------- ADMIN LIST --------------------

@app.get("/api/v1/admin/releases")
def mg22_admin_list(
    platform: Optional[str] = Query(default=None),
    status: Optional[str] = Query(default=None),
    limit: int = Query(default=50, ge=1, le=200),
    offset: int = Query(default=0, ge=0),
    x_admin_api_key: Optional[str] = Header(default=None)
):
    mg22_require_admin(x_admin_api_key)

    if platform is not None and platform not in MG22_PLATFORMS:
        raise HTTPException(status_code=422, detail="Invalid platform")

    if status is not None and status not in MG22_STATUSES:
        raise HTTPException(status_code=422, detail="Invalid status")

    with get_db() as connection:
        with connection.cursor() as cursor:
            mg22_require_schema(cursor)

            conditions = []
            values = []

            if platform is not None:
                conditions.append("platform = %s")
                values.append(platform)

            if status is not None:
                conditions.append("status = %s")
                values.append(status)

            where = ""
            if conditions:
                where = "WHERE " + " AND ".join(conditions)

            values.extend([limit, offset])

            cursor.execute("""
                SELECT id, platform, version, build_number,
                       minimum_version, force_update,
                       download_url, changelog, status,
                       created_at, published_at, updated_at
                FROM mg22_releases
            """ + where + """
                ORDER BY created_at DESC
                LIMIT %s OFFSET %s
            """, tuple(values))

            rows = [
                mg22_row(cursor, row)
                for row in cursor.fetchall()
            ]

    return {
        "success": True,
        "count": len(rows),
        "items": rows
    }


# -------------------- CHANGE STATUS --------------------

@app.patch("/api/v1/admin/releases/{release_id}/status")
def mg22_change_status(
    release_id: str,
    data: MG22ReleaseStatus,
    x_admin_api_key: Optional[str] = Header(default=None)
):
    mg22_require_admin(x_admin_api_key)

    if data.status not in MG22_STATUSES:
        raise HTTPException(status_code=422, detail="Invalid status")

    try:
        parsed_id = mg22_uuid.UUID(release_id)
    except (ValueError, TypeError, AttributeError):
        raise HTTPException(status_code=400, detail="Invalid release ID")

    with get_db() as connection:
        with connection.cursor() as cursor:
            mg22_require_schema(cursor)

            cursor.execute("""
                UPDATE mg22_releases
                SET status = %s,
                    published_at = CASE
                        WHEN %s = 'published' THEN NOW()
                        ELSE published_at
                    END,
                    updated_at = NOW()
                WHERE id = %s
                RETURNING id, platform, version, build_number,
                          minimum_version, force_update,
                          download_url, status, published_at, updated_at
            """, (data.status, data.status, parsed_id))

            result = mg22_row(cursor, cursor.fetchone())

            if result is None:
                raise HTTPException(status_code=404, detail="Release not found")

    return {"success": True, "release": result}


# -------------------- PUBLIC LATEST RELEASE --------------------

@app.get("/api/v1/releases/latest")
def mg22_latest_release(
    platform: str = Query(...),
    installed_version: str = Query(...)
):
    if platform not in MG22_PLATFORMS:
        raise HTTPException(status_code=422, detail="Invalid platform")

    if not mg22_valid_version(installed_version):
        raise HTTPException(status_code=422, detail="Invalid installed version")

    with get_db() as connection:
        with connection.cursor() as cursor:
            mg22_require_schema(cursor)

            cursor.execute("""
                SELECT id, platform, version, build_number,
                       minimum_version, force_update,
                       download_url, changelog, published_at
                FROM mg22_releases
                WHERE platform = %s
                  AND status = 'published'
                ORDER BY published_at DESC NULLS LAST,
                         created_at DESC
                LIMIT 1
            """, (platform,))

            latest = mg22_row(cursor, cursor.fetchone())

    if latest is None:
        return {
            "success": True,
            "update_available": False,
            "release": None
        }

    installed = mg22_version_tuple(installed_version)
    latest_version = mg22_version_tuple(latest["version"])
    minimum = mg22_version_tuple(latest["minimum_version"])

    update_available = installed < latest_version
    force_update = installed < minimum

    return {
        "success": True,
        "update_available": update_available,
        "force_update": force_update,
        "release": latest
    }


# -------------------- ARCHIVE RELEASE --------------------

@app.delete("/api/v1/admin/releases/{release_id}")
def mg22_archive_release(
    release_id: str,
    x_admin_api_key: Optional[str] = Header(default=None)
):
    mg22_require_admin(x_admin_api_key)

    try:
        parsed_id = mg22_uuid.UUID(release_id)
    except (ValueError, TypeError, AttributeError):
        raise HTTPException(status_code=400, detail="Invalid release ID")

    with get_db() as connection:
        with connection.cursor() as cursor:
            mg22_require_schema(cursor)

            cursor.execute("""
                UPDATE mg22_releases
                SET status = 'archived', updated_at = NOW()
                WHERE id = %s
                RETURNING id, platform, version, status, updated_at
            """, (parsed_id,))

            result = mg22_row(cursor, cursor.fetchone())

            if result is None:
                raise HTTPException(status_code=404, detail="Release not found")

    return {"success": True, "release": result}


# ============================================================
# END OF SECTION 22
# ============================================================

# ============================================================
# MASIH GRAM GLOBAL — SECTION 23
# GLOBAL QUOTA & USAGE CONTROL
# ============================================================

import uuid as mg23_uuid
from datetime import datetime, timezone
from typing import Optional

from fastapi import Header, HTTPException, Query
from pydantic import BaseModel, Field


# -------------------- MODELS --------------------

class MG23QuotaCreate(BaseModel):
    user_id: str = Field(..., min_length=1, max_length=100)
    daily_requests: int = Field(default=1000, ge=0, le=10000000)
    monthly_requests: int = Field(default=30000, ge=0, le=300000000)
    storage_limit_bytes: int = Field(default=104857600, ge=0)
    upload_limit_bytes: int = Field(default=10485760, ge=0)


class MG23UsageReport(BaseModel):
    resource: str = Field(..., min_length=2, max_length=40)
    amount: int = Field(..., gt=0, le=1000000000000)


class MG23QuotaUpdate(BaseModel):
    daily_requests: Optional[int] = Field(default=None, ge=0, le=10000000)
    monthly_requests: Optional[int] = Field(default=None, ge=0, le=300000000)
    storage_limit_bytes: Optional[int] = Field(default=None, ge=0)
    upload_limit_bytes: Optional[int] = Field(default=None, ge=0)


# -------------------- CONSTANTS --------------------

MG23_RESOURCES = {
    "requests",
    "storage_bytes",
    "upload_bytes"
}


# -------------------- HELPERS --------------------

def mg23_require_admin(api_key):
    global_admin_check(api_key)


def mg23_parse_user_id(value):
    try:
        return int(value)
    except (ValueError, TypeError):
        raise HTTPException(status_code=422, detail="Invalid user ID")


def mg23_require_schema(cursor):
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS mg23_user_quotas (
            user_id BIGINT PRIMARY KEY,
            daily_requests BIGINT NOT NULL DEFAULT 1000
                CHECK (daily_requests >= 0),
            monthly_requests BIGINT NOT NULL DEFAULT 30000
                CHECK (monthly_requests >= 0),
            storage_limit_bytes BIGINT NOT NULL DEFAULT 104857600
                CHECK (storage_limit_bytes >= 0),
            upload_limit_bytes BIGINT NOT NULL DEFAULT 10485760
                CHECK (upload_limit_bytes >= 0),
            updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
        )
    """)

    cursor.execute("""
        CREATE TABLE IF NOT EXISTS mg23_usage_events (
            id UUID PRIMARY KEY,
            user_id BIGINT NOT NULL,
            resource VARCHAR(40) NOT NULL,
            amount BIGINT NOT NULL CHECK (amount > 0),
            created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
        )
    """)

    cursor.execute("""
        CREATE INDEX IF NOT EXISTS mg23_usage_user_resource_time_idx
        ON mg23_usage_events (user_id, resource, created_at DESC)
    """)


def mg23_row(cursor, row):
    if row is None:
        return None
    return dict(zip(
        [column.name for column in cursor.description],
        row
    ))


def mg23_usage_sum(cursor, user_id, resource, since):
    cursor.execute("""
        SELECT COALESCE(SUM(amount), 0)
        FROM mg23_usage_events
        WHERE user_id = %s
          AND resource = %s
          AND created_at >= %s
    """, (user_id, resource, since))
    return int(cursor.fetchone()[0])


def mg23_get_or_create_quota(cursor, user_id):
    cursor.execute("""
        INSERT INTO mg23_user_quotas (user_id)
        VALUES (%s)
        ON CONFLICT (user_id) DO NOTHING
    """, (user_id,))

    cursor.execute("""
        SELECT user_id, daily_requests, monthly_requests,
               storage_limit_bytes, upload_limit_bytes, updated_at
        FROM mg23_user_quotas
        WHERE user_id = %s
    """, (user_id,))

    return mg23_row(cursor, cursor.fetchone())


# -------------------- MIGRATION --------------------

@app.post("/api/v1/admin/migrations/quotas/apply")
def mg23_apply_migration(
    x_admin_api_key: Optional[str] = Header(default=None)
):
    mg23_require_admin(x_admin_api_key)

    with get_db() as connection:
        with connection.cursor() as cursor:
            mg23_require_schema(cursor)

    return {
        "success": True,
        "module": "global_quota_control",
        "version": "23.0"
    }


# -------------------- CREATE / RESET USER QUOTA --------------------

@app.post("/api/v1/admin/quotas")
def mg23_create_quota(
    data: MG23QuotaCreate,
    x_admin_api_key: Optional[str] = Header(default=None)
):
    mg23_require_admin(x_admin_api_key)
    user_id = mg23_parse_user_id(data.user_id)

    with get_db() as connection:
        with connection.cursor() as cursor:
            mg23_require_schema(cursor)

            cursor.execute("""
                INSERT INTO mg23_user_quotas (
                    user_id, daily_requests, monthly_requests,
                    storage_limit_bytes, upload_limit_bytes, updated_at
                )
                VALUES (%s, %s, %s, %s, %s, NOW())
                ON CONFLICT (user_id)
                DO UPDATE SET
                    daily_requests = EXCLUDED.daily_requests,
                    monthly_requests = EXCLUDED.monthly_requests,
                    storage_limit_bytes = EXCLUDED.storage_limit_bytes,
                    upload_limit_bytes = EXCLUDED.upload_limit_bytes,
                    updated_at = NOW()
                RETURNING user_id, daily_requests, monthly_requests,
                          storage_limit_bytes, upload_limit_bytes, updated_at
            """, (
                user_id,
                data.daily_requests,
                data.monthly_requests,
                data.storage_limit_bytes,
                data.upload_limit_bytes
            ))

            result = mg23_row(cursor, cursor.fetchone())

    return {"success": True, "quota": result}


# -------------------- UPDATE USER QUOTA --------------------

@app.patch("/api/v1/admin/quotas/{user_id}")
def mg23_update_quota(
    user_id: int,
    data: MG23QuotaUpdate,
    x_admin_api_key: Optional[str] = Header(default=None)
):
    mg23_require_admin(x_admin_api_key)

    changes = data.dict(exclude_unset=True)

    if not changes:
        raise HTTPException(status_code=422, detail="No update fields provided")

    allowed = {
        "daily_requests",
        "monthly_requests",
        "storage_limit_bytes",
        "upload_limit_bytes"
    }

    if any(key not in allowed for key in changes):
        raise HTTPException(status_code=422, detail="Invalid quota field")

    with get_db() as connection:
        with connection.cursor() as cursor:
            mg23_require_schema(cursor)

            mg23_get_or_create_quota(cursor, user_id)

            assignments = []
            values = []

            for key, value in changes.items():
                assignments.append(key + " = %s")
                values.append(value)

            assignments.append("updated_at = NOW()")
            values.append(user_id)

            cursor.execute(
                "UPDATE mg23_user_quotas SET "
                + ", ".join(assignments)
                + " WHERE user_id = %s "
                + "RETURNING user_id, daily_requests, monthly_requests, "
                + "storage_limit_bytes, upload_limit_bytes, updated_at",
                tuple(values)
            )

            result = mg23_row(cursor, cursor.fetchone())

    return {"success": True, "quota": result}


# -------------------- RECORD USAGE --------------------

@app.post("/api/v1/quotas/usage")
def mg23_record_usage(
    data: MG23UsageReport,
    x_admin_api_key: Optional[str] = Header(default=None)
):
    mg23_require_admin(x_admin_api_key)

    if data.resource not in MG23_RESOURCES:
        raise HTTPException(status_code=422, detail="Invalid resource")

    # This administrative endpoint is intentionally restricted.
    # User-facing usage recording must be called internally by trusted
    # server operations, never directly trusted from a client.

    raise HTTPException(
        status_code=501,
        detail="Usage recording is reserved for trusted server integration"
    )


# -------------------- INTERNAL USAGE RECORDER --------------------

def mg23_record_usage_internal(cursor, user_id, resource, amount):
    if resource not in MG23_RESOURCES:
        raise ValueError("Invalid quota resource")

    if not isinstance(amount, int) or isinstance(amount, bool) or amount <= 0:
        raise ValueError("Usage amount must be a positive integer")

    quota = mg23_get_or_create_quota(cursor, user_id)

    now = datetime.now(timezone.utc)

    if resource == "requests":
        daily = mg23_usage_sum(
            cursor, user_id, "requests",
            now.replace(hour=0, minute=0, second=0, microsecond=0)
        )

        month_start = now.replace(
            day=1, hour=0, minute=0, second=0, microsecond=0
        )

        monthly = mg23_usage_sum(
            cursor, user_id, "requests", month_start
        )

        if daily + amount > quota["daily_requests"]:
            raise HTTPException(status_code=429, detail="Daily request quota exceeded")

        if monthly + amount > quota["monthly_requests"]:
            raise HTTPException(status_code=429, detail="Monthly request quota exceeded")

    elif resource == "upload_bytes":
        if amount > quota["upload_limit_bytes"]:
            raise HTTPException(status_code=413, detail="Upload size limit exceeded")

    elif resource == "storage_bytes":
        current_storage = mg23_usage_sum(
            cursor, user_id, "storage_bytes",
            datetime(1970, 1, 1, tzinfo=timezone.utc)
        )

        if current_storage + amount > quota["storage_limit_bytes"]:
            raise HTTPException(status_code=413, detail="Storage quota exceeded")

    cursor.execute("""
        INSERT INTO mg23_usage_events (
            id, user_id, resource, amount
        )
        VALUES (%s, %s, %s, %s)
    """, (mg23_uuid.uuid4(), user_id, resource, amount))


# -------------------- USER QUOTA REPORT --------------------

@app.get("/api/v1/admin/quotas/{user_id}")
def mg23_get_quota(
    user_id: int,
    x_admin_api_key: Optional[str] = Header(default=None)
):
    mg23_require_admin(x_admin_api_key)

    with get_db() as connection:
        with connection.cursor() as cursor:
            mg23_require_schema(cursor)

            quota = mg23_get_or_create_quota(cursor, user_id)

            now = datetime.now(timezone.utc)
            day_start = now.replace(
                hour=0, minute=0, second=0, microsecond=0
            )
            month_start = now.replace(
                day=1, hour=0, minute=0, second=0, microsecond=0
            )
            all_time = datetime(1970, 1, 1, tzinfo=timezone.utc)

            daily_requests_used = mg23_usage_sum(
                cursor, user_id, "requests", day_start
            )

            monthly_requests_used = mg23_usage_sum(
                cursor, user_id, "requests", month_start
            )

            storage_used = mg23_usage_sum(
                cursor, user_id, "storage_bytes", all_time
            )

            result = {
                "user_id": user_id,
                "limits": quota,
                "usage": {
                    "daily_requests": daily_requests_used,
                    "monthly_requests": monthly_requests_used,
                    "storage_bytes": storage_used
                }
            }

    return {"success": True, "quota_report": result}


# -------------------- ADMIN USAGE HISTORY --------------------

@app.get("/api/v1/admin/quotas/{user_id}/history")
def mg23_usage_history(
    user_id: int,
    resource: Optional[str] = Query(default=None),
    limit: int = Query(default=100, ge=1, le=500),
    offset: int = Query(default=0, ge=0),
    x_admin_api_key: Optional[str] = Header(default=None)
):
    mg23_require_admin(x_admin_api_key)

    if resource is not None and resource not in MG23_RESOURCES:
        raise HTTPException(status_code=422, detail="Invalid resource")

    with get_db() as connection:
        with connection.cursor() as cursor:
            mg23_require_schema(cursor)

            if resource is None:
                cursor.execute("""
                    SELECT id, resource, amount, created_at
                    FROM mg23_usage_events
                    WHERE user_id = %s
                    ORDER BY created_at DESC
                    LIMIT %s OFFSET %s
                """, (user_id, limit, offset))
            else:
                cursor.execute("""
                    SELECT id, resource, amount, created_at
                    FROM mg23_usage_events
                    WHERE user_id = %s AND resource = %s
                    ORDER BY created_at DESC
                    LIMIT %s OFFSET %s
                """, (user_id, resource, limit, offset))

            rows = [
                mg23_row(cursor, row)
                for row in cursor.fetchall()
            ]

    return {
        "success": True,
        "count": len(rows),
        "items": rows
    }


# ============================================================
# END OF SECTION 23
# ============================================================

# ============================================================
# MASIH GRAM GLOBAL
# SECTIONS 24 + 25
# CONTENT CATEGORIES & KNOWLEDGE CENTER
# ============================================================

import uuid as mg2425_uuid
import re as mg2425_re
from typing import Optional

from fastapi import Header, HTTPException, Query
from pydantic import BaseModel, Field


MG2425_ARTICLE_STATUSES = {"draft", "published", "archived"}


# ============================================================
# SECTION 24 — CONTENT CATEGORY CENTER
# ============================================================

class MG24CategoryCreate(BaseModel):
    name: str = Field(..., min_length=2, max_length=100)
    slug: str = Field(..., min_length=2, max_length=100)
    description: str = Field(default="", max_length=1000)
    sort_order: int = Field(default=0, ge=0, le=100000)


def mg2425_require_admin(api_key):
    global_admin_check(api_key)


def mg2425_require_schema(cursor):
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS mg24_content_categories (
            id UUID PRIMARY KEY,
            name VARCHAR(100) NOT NULL,
            slug VARCHAR(100) NOT NULL UNIQUE,
            description VARCHAR(1000) NOT NULL DEFAULT '',
            sort_order INTEGER NOT NULL DEFAULT 0,
            is_active BOOLEAN NOT NULL DEFAULT TRUE,
            created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
            updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
        )
    """)

    cursor.execute("""
        CREATE TABLE IF NOT EXISTS mg25_knowledge_articles (
            id UUID PRIMARY KEY,
            category_id UUID NOT NULL
                REFERENCES mg24_content_categories(id)
                ON DELETE RESTRICT,
            title VARCHAR(200) NOT NULL,
            slug VARCHAR(200) NOT NULL UNIQUE,
            summary VARCHAR(1000) NOT NULL DEFAULT '',
            content TEXT NOT NULL,
            status VARCHAR(20) NOT NULL DEFAULT 'draft'
                CHECK (status IN ('draft', 'published', 'archived')),
            views_count BIGINT NOT NULL DEFAULT 0
                CHECK (views_count >= 0),
            created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
            updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
            published_at TIMESTAMPTZ NULL
        )
    """)

    cursor.execute("""
        CREATE INDEX IF NOT EXISTS mg24_categories_active_idx
        ON mg24_content_categories (is_active, sort_order, name)
    """)

    cursor.execute("""
        CREATE INDEX IF NOT EXISTS mg25_articles_category_idx
        ON mg25_knowledge_articles (category_id, status, published_at DESC)
    """)

    cursor.execute("""
        CREATE INDEX IF NOT EXISTS mg25_articles_created_idx
        ON mg25_knowledge_articles (created_at DESC)
    """)


def mg2425_row(cursor, row):
    if row is None:
        return None

    columns = [column.name for column in cursor.description]
    return dict(zip(columns, row))


def mg2425_validate_slug(value):
    if not isinstance(value, str):
        raise HTTPException(status_code=422, detail="Invalid slug")

    value = value.strip().lower()

    if not mg2425_re.fullmatch(r"[a-z0-9]+(?:-[a-z0-9]+)*", value):
        raise HTTPException(
            status_code=422,
            detail="Slug must contain lowercase English letters, numbers and hyphens"
        )

    return value


def mg2425_clean(value, field_name):
    if not isinstance(value, str):
        raise HTTPException(status_code=422, detail="Invalid " + field_name)

    value = value.strip()

    if not value:
        raise HTTPException(status_code=422, detail=field_name + " cannot be empty")

    return value


# -------------------- SECTION 24 MIGRATION --------------------

@app.post("/api/v1/admin/migrations/content-center/apply")
def mg2425_apply_migration(
    x_admin_api_key: Optional[str] = Header(default=None)
):
    mg2425_require_admin(x_admin_api_key)

    with get_db() as connection:
        with connection.cursor() as cursor:
            mg2425_require_schema(cursor)

    return {
        "success": True,
        "modules": [
            "content_categories",
            "knowledge_articles"
        ],
        "version": "24.25"
    }


# -------------------- CREATE CATEGORY --------------------

@app.post("/api/v1/admin/content/categories")
def mg24_create_category(
    data: MG24CategoryCreate,
    x_admin_api_key: Optional[str] = Header(default=None)
):
    mg2425_require_admin(x_admin_api_key)

    name = mg2425_clean(data.name, "name")
    slug = mg2425_validate_slug(data.slug)
    description = data.description.strip()

    category_id = mg2425_uuid.uuid4()

    with get_db() as connection:
        with connection.cursor() as cursor:
            mg2425_require_schema(cursor)

            cursor.execute("""
                SELECT 1
                FROM mg24_content_categories
                WHERE slug = %s
            """, (slug,))

            if cursor.fetchone():
                raise HTTPException(
                    status_code=409,
                    detail="Category slug already exists"
                )

            cursor.execute("""
                INSERT INTO mg24_content_categories (
                    id, name, slug, description, sort_order
                )
                VALUES (%s, %s, %s, %s, %s)
                RETURNING id, name, slug, description,
                          sort_order, is_active, created_at
            """, (
                category_id,
                name,
                slug,
                description,
                data.sort_order
            ))

            result = mg2425_row(cursor, cursor.fetchone())

    return {"success": True, "category": result}


# -------------------- ADMIN CATEGORY LIST --------------------

@app.get("/api/v1/admin/content/categories")
def mg24_admin_categories(
    limit: int = Query(default=100, ge=1, le=300),
    offset: int = Query(default=0, ge=0),
    x_admin_api_key: Optional[str] = Header(default=None)
):
    mg2425_require_admin(x_admin_api_key)

    with get_db() as connection:
        with connection.cursor() as cursor:
            mg2425_require_schema(cursor)

            cursor.execute("""
                SELECT id, name, slug, description,
                       sort_order, is_active, created_at, updated_at
                FROM mg24_content_categories
                ORDER BY sort_order ASC, created_at DESC
                LIMIT %s OFFSET %s
            """, (limit, offset))

            rows = [
                mg2425_row(cursor, row)
                for row in cursor.fetchall()
            ]

    return {
        "success": True,
        "count": len(rows),
        "items": rows
    }


# -------------------- CATEGORY ACTIVE SWITCH --------------------

@app.patch("/api/v1/admin/content/categories/{category_id}/active")
def mg24_set_category_active(
    category_id: str,
    active: bool = Query(...),
    x_admin_api_key: Optional[str] = Header(default=None)
):
    mg2425_require_admin(x_admin_api_key)

    try:
        parsed_id = mg2425_uuid.UUID(category_id)
    except (ValueError, TypeError, AttributeError):
        raise HTTPException(status_code=400, detail="Invalid category ID")

    with get_db() as connection:
        with connection.cursor() as cursor:
            mg2425_require_schema(cursor)

            cursor.execute("""
                UPDATE mg24_content_categories
                SET is_active = %s, updated_at = NOW()
                WHERE id = %s
                RETURNING id, name, slug, is_active, updated_at
            """, (active, parsed_id))

            result = mg2425_row(cursor, cursor.fetchone())

            if result is None:
                raise HTTPException(status_code=404, detail="Category not found")

    return {"success": True, "category": result}


# -------------------- PUBLIC CATEGORY LIST --------------------

@app.get("/api/v1/content/categories")
def mg24_public_categories():
    with get_db() as connection:
        with connection.cursor() as cursor:
            mg2425_require_schema(cursor)

            cursor.execute("""
                SELECT
                    c.id,
                    c.name,
                    c.slug,
                    c.description,
                    c.sort_order,
                    COUNT(a.id) AS published_articles
                FROM mg24_content_categories c
                LEFT JOIN mg25_knowledge_articles a
                    ON a.category_id = c.id
                    AND a.status = 'published'
                WHERE c.is_active = TRUE
                GROUP BY c.id
                ORDER BY c.sort_order ASC, c.name ASC
            """)

            rows = [
                mg2425_row(cursor, row)
                for row in cursor.fetchall()
            ]

    return {
        "success": True,
        "count": len(rows),
        "items": rows
    }


# ============================================================
# SECTION 25 — KNOWLEDGE ARTICLES CENTER
# ============================================================

class MG25ArticleCreate(BaseModel):
    category_id: str
    title: str = Field(..., min_length=2, max_length=200)
    slug: str = Field(..., min_length=2, max_length=200)
    summary: str = Field(default="", max_length=1000)
    content: str = Field(..., min_length=2, max_length=50000)


class MG25ArticleStatus(BaseModel):
    status: str


# -------------------- CREATE ARTICLE --------------------

@app.post("/api/v1/admin/content/articles")
def mg25_create_article(
    data: MG25ArticleCreate,
    x_admin_api_key: Optional[str] = Header(default=None)
):
    mg2425_require_admin(x_admin_api_key)

    try:
        category_id = mg2425_uuid.UUID(data.category_id)
    except (ValueError, TypeError, AttributeError):
        raise HTTPException(status_code=400, detail="Invalid category ID")

    title = mg2425_clean(data.title, "title")
    content = mg2425_clean(data.content, "content")
    slug = mg2425_validate_slug(data.slug)
    summary = data.summary.strip()

    article_id = mg2425_uuid.uuid4()

    with get_db() as connection:
        with connection.cursor() as cursor:
            mg2425_require_schema(cursor)

            cursor.execute("""
                SELECT id
                FROM mg24_content_categories
                WHERE id = %s AND is_active = TRUE
            """, (category_id,))

            if cursor.fetchone() is None:
                raise HTTPException(
                    status_code=404,
                    detail="Active category not found"
                )

            cursor.execute("""
                SELECT 1
                FROM mg25_knowledge_articles
                WHERE slug = %s
            """, (slug,))

            if cursor.fetchone():
                raise HTTPException(
                    status_code=409,
                    detail="Article slug already exists"
                )

            cursor.execute("""
                INSERT INTO mg25_knowledge_articles (
                    id, category_id, title, slug,
                    summary, content, status
                )
                VALUES (%s, %s, %s, %s, %s, %s, 'draft')
                RETURNING id, category_id, title, slug,
                          summary, status, views_count,
                          created_at, updated_at
            """, (
                article_id,
                category_id,
                title,
                slug,
                summary,
                content
            ))

            result = mg2425_row(cursor, cursor.fetchone())

    return {"success": True, "article": result}


# -------------------- ADMIN ARTICLE LIST --------------------

@app.get("/api/v1/admin/content/articles")
def mg25_admin_articles(
    status: Optional[str] = Query(default=None),
    category_id: Optional[str] = Query(default=None),
    limit: int = Query(default=50, ge=1, le=200),
    offset: int = Query(default=0, ge=0),
    x_admin_api_key: Optional[str] = Header(default=None)
):
    mg2425_require_admin(x_admin_api_key)

    if status is not None and status not in MG2425_ARTICLE_STATUSES:
        raise HTTPException(status_code=422, detail="Invalid article status")

    parsed_category = None

    if category_id is not None:
        try:
            parsed_category = mg2425_uuid.UUID(category_id)
        except (ValueError, TypeError, AttributeError):
            raise HTTPException(status_code=400, detail="Invalid category ID")

    conditions = []
    values = []

    if status is not None:
        conditions.append("a.status = %s")
        values.append(status)

    if parsed_category is not None:
        conditions.append("a.category_id = %s")
        values.append(parsed_category)

    where_clause = ""
    if conditions:
        where_clause = "WHERE " + " AND ".join(conditions)

    values.extend([limit, offset])

    with get_db() as connection:
        with connection.cursor() as cursor:
            mg2425_require_schema(cursor)

            cursor.execute("""
                SELECT a.id, a.category_id, c.name AS category_name,
                       a.title, a.slug, a.summary, a.status,
                       a.views_count, a.created_at,
                       a.updated_at, a.published_at
                FROM mg25_knowledge_articles a
                JOIN mg24_content_categories c
                    ON c.id = a.category_id
            """ + where_clause + """
                ORDER BY a.created_at DESC
                LIMIT %s OFFSET %s
            """, tuple(values))

            rows = [
                mg2425_row(cursor, row)
                for row in cursor.fetchall()
            ]

    return {
        "success": True,
        "count": len(rows),
        "items": rows
    }


# -------------------- PUBLISH / ARCHIVE ARTICLE --------------------

@app.patch("/api/v1/admin/content/articles/{article_id}/status")
def mg25_change_article_status(
    article_id: str,
    data: MG25ArticleStatus,
    x_admin_api_key: Optional[str] = Header(default=None)
):
    mg2425_require_admin(x_admin_api_key)

    if data.status not in MG2425_ARTICLE_STATUSES:
        raise HTTPException(status_code=422, detail="Invalid article status")

    try:
        parsed_id = mg2425_uuid.UUID(article_id)
    except (ValueError, TypeError, AttributeError):
        raise HTTPException(status_code=400, detail="Invalid article ID")

    with get_db() as connection:
        with connection.cursor() as cursor:
            mg2425_require_schema(cursor)

            cursor.execute("""
                UPDATE mg25_knowledge_articles
                SET status = %s,
                    published_at = CASE
                        WHEN %s = 'published'
                            THEN COALESCE(published_at, NOW())
                        ELSE published_at
                    END,
                    updated_at = NOW()
                WHERE id = %s
                  AND (
                      %s <> 'published'
                      OR EXISTS (
                          SELECT 1
                          FROM mg24_content_categories c
                          WHERE c.id = mg25_knowledge_articles.category_id
                            AND c.is_active = TRUE
                      )
                  )
                RETURNING id, title, slug, status,
                          published_at, updated_at
            """, (
                data.status,
                data.status,
                parsed_id,
                data.status
            ))

            result = mg2425_row(cursor, cursor.fetchone())

            if result is None:
                raise HTTPException(
                    status_code=404,
                    detail="Article or active category not found"
                )

    return {"success": True, "article": result}


# -------------------- PUBLIC ARTICLE SEARCH --------------------

@app.get("/api/v1/content/articles")
def mg25_public_articles(
    search: Optional[str] = Query(default=None, max_length=100),
    category: Optional[str] = Query(default=None, max_length=100),
    limit: int = Query(default=20, ge=1, le=100),
    offset: int = Query(default=0, ge=0)
):
    conditions = [
        "a.status = 'published'",
        "c.is_active = TRUE"
    ]
    values = []

    if search:
        search_text = search.strip()

        if search_text:
            conditions.append("""
                (
                    a.title ILIKE %s
                    OR a.summary ILIKE %s
                    OR a.content ILIKE %s
                )
            """)
            pattern = "%" + search_text + "%"
            values.extend([pattern, pattern, pattern])

    if category:
        conditions.append("c.slug = %s")
        values.append(category.strip().lower())

    values.extend([limit, offset])

    with get_db() as connection:
        with connection.cursor() as cursor:
            mg2425_require_schema(cursor)

            cursor.execute("""
                SELECT a.id, a.title, a.slug, a.summary,
                       a.category_id, c.name AS category_name,
                       c.slug AS category_slug,
                       a.views_count, a.published_at
                FROM mg25_knowledge_articles a
                JOIN mg24_content_categories c
                    ON c.id = a.category_id
                WHERE """ + " AND ".join(conditions) + """
                ORDER BY a.published_at DESC NULLS LAST,
                         a.created_at DESC
                LIMIT %s OFFSET %s
            """, tuple(values))

            rows = [
                mg2425_row(cursor, row)
                for row in cursor.fetchall()
            ]

    return {
        "success": True,
        "count": len(rows),
        "items": rows
    }


# -------------------- PUBLIC ARTICLE DETAIL --------------------

@app.get("/api/v1/content/articles/{slug}")
def mg25_public_article_detail(slug: str):
    if not mg2425_re.fullmatch(r"[a-z0-9]+(?:-[a-z0-9]+)*", slug):
        raise HTTPException(status_code=400, detail="Invalid article slug")

    with get_db() as connection:
        with connection.cursor() as cursor:
            mg2425_require_schema(cursor)

            cursor.execute("""
                UPDATE mg25_knowledge_articles a
                SET views_count = a.views_count + 1
                FROM mg24_content_categories c
                WHERE a.category_id = c.id
                  AND a.slug = %s
                  AND a.status = 'published'
                  AND c.is_active = TRUE
                RETURNING
                    a.id,
                    a.title,
                    a.slug,
                    a.summary,
                    a.content,
                    a.views_count,
                    a.published_at,
                    c.id AS category_id,
                    c.name AS category_name,
                    c.slug AS category_slug
            """, (slug,))

            result = mg2425_row(cursor, cursor.fetchone())

            if result is None:
                raise HTTPException(status_code=404, detail="Article not found")

    return {"success": True, "article": result}


# ============================================================
# END OF SECTIONS 24 + 25
# ============================================================
