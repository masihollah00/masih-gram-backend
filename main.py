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
