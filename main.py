
import os
import re
import json
import hmac
import uuid
import time
import base64
import hashlib
import secrets

from datetime import datetime, timedelta, timezone
from typing import Optional

import httpx
import psycopg

from fastapi import FastAPI, HTTPException, Header, Request
from fastapi.responses import JSONResponse
from pydantic import BaseModel, Field


APP_VERSION = "2.0.0"
MIGRATION_VERSION = "001_initial_core"
AUTH_MIGRATION_VERSION = "002_auth_engine"

TEXTBEE_URL = "https://api.textbee.dev/api/v1/gateway/send-sms"

OTP_LIFETIME_SECONDS = 300
OTP_RESEND_SECONDS = 60
OTP_MAX_ATTEMPTS = 5
OTP_HOURLY_LIMIT = 3

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

def env_required(name):
    value = os.getenv(name)
    if not value:
        raise HTTPException(
            status_code=503,
            detail=f"Server configuration missing: {name}"
        )
    return value


def get_database_url():
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


def auth_secret():
    return env_required("AUTH_SECRET").encode("utf-8")


def otp_pepper():
    return env_required("OTP_PEPPER").encode("utf-8")


# ---------------------------------------------------------
# REQUEST MODELS
# ---------------------------------------------------------

class OTPRequest(BaseModel):
    phone: str = Field(min_length=8, max_length=30)
    purpose: str = Field(pattern="^(signup|login)$")


class OTPVerify(BaseModel):
    phone: str
    purpose: str = Field(pattern="^(signup|login)$")
    code: str = Field(pattern="^[0-9]{6}$")

    username: Optional[str] = Field(
        default=None,
        min_length=3,
        max_length=32
    )

    display_name: Optional[str] = Field(
        default=None,
        min_length=1,
        max_length=100
    )

    device_name: Optional[str] = Field(
        default=None,
        max_length=120
    )

    platform: Optional[str] = Field(
        default="Android",
        max_length=50
    )

    app_version: Optional[str] = Field(
        default=None,
        max_length=40
    )


class RefreshRequest(BaseModel):
    refresh_token: str = Field(min_length=30, max_length=200)


# ---------------------------------------------------------
# PHONE AND HASH UTILITIES
# ---------------------------------------------------------

def normalize_phone(phone):
    value = re.sub(r"[\s\-().]", "", phone.strip())

    if not re.fullmatch(r"\+[1-9][0-9]{7,14}", value):
        raise HTTPException(
            status_code=422,
            detail="Phone must use international format, e.g. +989121234567"
        )

    return value


def hash_otp(phone, purpose, code):
    message = f"{phone}:{purpose}:{code}".encode("utf-8")
    return hmac.new(
        otp_pepper(),
        message,
        hashlib.sha256
    ).hexdigest()


def hash_refresh_token(token):
    return hashlib.sha256(
        token.encode("utf-8")
    ).hexdigest()


def get_client_ip(request):
    if request.client:
        return request.client.host
    return None


# ---------------------------------------------------------
# JWT IMPLEMENTATION
# ---------------------------------------------------------

def b64url(data):
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def create_access_token(user_id, session_id):
    now = int(time.time())

    header = {
        "alg": "HS256",
        "typ": "JWT"
    }

    payload = {
        "sub": str(user_id),
        "sid": str(session_id),
        "iat": now,
        "exp": now + ACCESS_TOKEN_SECONDS,
        "iss": "masih-gram"
    }

    first = b64url(json.dumps(
        header,
        separators=(",", ":")
    ).encode())

    second = b64url(json.dumps(
        payload,
        separators=(",", ":")
    ).encode())

    signing_input = f"{first}.{second}".encode()

    signature = hmac.new(
        auth_secret(),
        signing_input,
        hashlib.sha256
    ).digest()

    return f"{first}.{second}.{b64url(signature)}"


def decode_access_token(token):
    try:
        parts = token.split(".")

        if len(parts) != 3:
            raise ValueError()

        first, second, signature = parts

        signing_input = f"{first}.{second}".encode()

        expected = hmac.new(
            auth_secret(),
            signing_input,
            hashlib.sha256
        ).digest()

        supplied = base64.urlsafe_b64decode(
            signature + "=" * (-len(signature) % 4)
        )

        if not hmac.compare_digest(expected, supplied):
            raise ValueError()

        payload = json.loads(
            base64.urlsafe_b64decode(
                second + "=" * (-len(second) % 4)
            )
        )

        if payload.get("iss") != "masih-gram":
            raise ValueError()

        if int(payload.get("exp", 0)) <= int(time.time()):
            raise ValueError()

        uuid.UUID(payload["sub"])
        uuid.UUID(payload["sid"])

        return payload

    except Exception:
        raise HTTPException(
            status_code=401,
            detail="Invalid or expired access token"
        )


def get_authenticated_user(
    authorization: Optional[str] = Header(default=None)
):
    if not authorization or not authorization.startswith("Bearer "):
        raise HTTPException(
            status_code=401,
            detail="Bearer token required"
        )

    token = authorization[7:].strip()
    payload = decode_access_token(token)

    with get_connection() as connection:
        with connection.cursor() as cursor:
            cursor.execute("""
                SELECT
                    u.id,
                    u.username,
                    u.display_name,
                    u.phone,
                    u.account_status,
                    s.id
                FROM public.mg_users u
                JOIN public.mg_user_sessions s
                    ON s.user_id = u.id
                WHERE u.id = %s
                  AND s.id = %s
                  AND s.revoked_at IS NULL
                  AND s.expires_at > NOW()
                  AND u.account_status = 'active'
                  AND u.deleted_at IS NULL
            """, (
                payload["sub"],
                payload["sid"]
            ))

            row = cursor.fetchone()

    if not row:
        raise HTTPException(
            status_code=401,
            detail="Session is invalid or revoked"
        )

    return {
        "id": str(row[0]),
        "username": row[1],
        "display_name": row[2],
        "phone": row[3],
        "account_status": row[4],
        "session_id": str(row[5])
    }


# ---------------------------------------------------------
# DATABASE READINESS
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


# ---------------------------------------------------------
# TEXTBEE SMS
# ---------------------------------------------------------

def send_textbee_sms(phone, message):
    api_key = os.getenv("TEXTBEE_API_KEY")

    if not api_key:
        raise HTTPException(
            status_code=503,
            detail="SMS provider is not configured"
        )

    try:
        response = httpx.post(
            TEXTBEE_URL,
            headers={
                "x-api-key": api_key,
                "Content-Type": "application/json"
            },
            json={
                "recipients": [phone],
                "message": message
            },
            timeout=20
        )

        if response.status_code != 200:
            raise HTTPException(
                status_code=502,
                detail="SMS provider rejected the request"
            )

        result = response.json()

        data = result.get("data", {})
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
# REQUEST OTP
# ---------------------------------------------------------

@app.post("/api/v1/auth/otp/request")
def request_otp(
    data: OTPRequest,
    request: Request
):
    phone = normalize_phone(data.phone)
    ip = get_client_ip(request)

    with get_connection() as connection:
        with connection.cursor() as cursor:
            require_auth_schema(cursor)

            cursor.execute("""
                SELECT id, account_status
                FROM public.mg_users
                WHERE phone = %s
                  AND deleted_at IS NULL
            """, (phone,))

            existing_user = cursor.fetchone()

            if data.purpose == "signup" and existing_user:
                raise HTTPException(
                    status_code=409,
                    detail="An account already exists for this phone"
                )

            if data.purpose == "login" and not existing_user:
                raise HTTPException(
                    status_code=404,
                    detail="No account exists for this phone"
                )

            if existing_user and existing_user[1] != "active":
                raise HTTPException(
                    status_code=403,
                    detail="This account is not active"
                )

            cursor.execute("""
                SELECT created_at
                FROM public.mg_auth_otp_challenges
                WHERE phone = %s
                  AND purpose = %s
                  AND created_at > NOW() - INTERVAL '60 seconds'
                ORDER BY created_at DESC
                LIMIT 1
            """, (phone, data.purpose))

            recent = cursor.fetchone()

            if recent:
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

            cursor.execute("""
                SELECT COUNT(*)
                FROM public.mg_auth_otp_challenges
                WHERE request_ip = %s::inet
                  AND created_at > NOW() - INTERVAL '1 hour'
            """, (ip,))

            if cursor.fetchone()[0] >= 10:
                raise HTTPException(
                    status_code=429,
                    detail="Too many requests from this network"
                )

    code = f"{secrets.randbelow(1000000):06d}"
    code_hash = hash_otp(phone, data.purpose, code)

    message = (
        f"MASIH GRAM | مسیح، شاه مجازی\n"
        f"Your verification code: {code}\n"
        f"Valid for 5 minutes. Do not share this code."
    )

    batch_id = send_textbee_sms(phone, message)

    with get_connection() as connection:
        with connection.cursor() as cursor:
            require_auth_schema(cursor)

            cursor.execute("""
                UPDATE public.mg_auth_otp_challenges
                SET consumed_at = NOW()
                WHERE phone = %s
                  AND purpose = %s
                  AND consumed_at IS NULL
            """, (phone, data.purpose))

            cursor.execute("""
                INSERT INTO public.mg_auth_otp_challenges (
                    phone,
                    purpose,
                    code_hash,
                    attempts,
                    max_attempts,
                    expires_at,
                    request_ip,
                    provider,
                    provider_batch_id
                )
                VALUES (
                    %s, %s, %s, 0, %s,
                    NOW() + INTERVAL '5 minutes',
                    %s::inet, 'textbee', %s
                )
            """, (
                phone,
                data.purpose,
                code_hash,
                OTP_MAX_ATTEMPTS,
                ip,
                batch_id
            ))

    return {
        "success": True,
        "message": "Verification SMS accepted by provider",
        "expires_in": OTP_LIFETIME_SECONDS,
        "resend_after": OTP_RESEND_SECONDS
    }


# ---------------------------------------------------------
# VERIFY OTP AND CREATE LOGIN SESSION
# ---------------------------------------------------------

@app.post("/api/v1/auth/otp/verify")
def verify_otp(
    data: OTPVerify,
    request: Request
):
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

    code_hash = hash_otp(
        phone,
        data.purpose,
        data.code
    )

    with get_connection() as connection:
        with connection.cursor() as cursor:
            require_auth_schema(cursor)

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

            challenge_id = challenge[0]
            stored_hash = challenge[1]
            attempts = challenge[2]
            max_attempts = challenge[3]

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

                raise HTTPException(
                    status_code=400,
                    detail="Verification code is incorrect"
                )

            cursor.execute("""
                UPDATE public.mg_auth_otp_challenges
                SET consumed_at = NOW()
                WHERE id = %s
            """, (challenge_id,))

            cursor.execute("""
                SELECT id, username, display_name, account_status
                FROM public.mg_users
                WHERE phone = %s
                  AND deleted_at IS NULL
                FOR UPDATE
            """, (phone,))

            user = cursor.fetchone()

            if data.purpose == "signup":
                if user:
                    raise HTTPException(
                        status_code=409,
                        detail="An account already exists"
                    )

                cursor.execute("""
                    INSERT INTO public.mg_users (
                        username,
                        display_name,
                        phone,
                        password_hash,
                        account_status,
                        is_verified,
                        phone_verified_at,
                        registration_completed_at
                    )
                    VALUES (
                        %s, %s, %s, NULL,
                        'active', TRUE, NOW(), NOW()
                    )
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
                    id,
                    user_id,
                    device_name,
                    device_type,
                    platform,
                    app_version,
                    last_active_at,
                    is_active
                )
                VALUES (
                    %s, %s, %s, 'mobile',
                    %s, %s, NOW(), TRUE
                )
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
            expires_at = utcnow() + timedelta(
                days=REFRESH_TOKEN_DAYS
            )

            cursor.execute("""
                INSERT INTO public.mg_user_sessions (
                    id,
                    user_id,
                    device_id,
                    refresh_token_hash,
                    ip_address,
                    user_agent,
                    expires_at
                )
                VALUES (
                    %s, %s, %s, %s,
                    %s::inet, %s, %s
                )
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
                SET last_seen_at = NOW(),
                    updated_at = NOW()
                WHERE id = %s
            """, (user_id,))

    access_token = create_access_token(
        user_id,
        session_id
    )

    return {
        "success": True,
        "message": "Authentication successful",
        "user": {
            "id": str(user_id),
            "username": user[1],
            "display_name": user[2],
            "phone": phone,
            "account_status": user[3]
        },
        "tokens": {
            "token_type": "Bearer",
            "access_token": access_token,
            "expires_in": ACCESS_TOKEN_SECONDS,
            "refresh_token": refresh_token,
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
            require_auth_schema(cursor)

            cursor.execute("""
                SELECT
                    s.id,
                    s.user_id,
                    u.account_status
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

            session_id, user_id, _ = row

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
            "access_token": create_access_token(
                user_id,
                session_id
            ),
            "expires_in": ACCESS_TOKEN_SECONDS,
            "refresh_token": new_refresh_token,
            "refresh_expires_in": REFRESH_TOKEN_DAYS * 86400
        }
    }


# ---------------------------------------------------------
# LOGOUT
# ---------------------------------------------------------

@app.post("/api/v1/auth/logout")
def logout(
    authorization: Optional[str] = Header(default=None)
):
    if not authorization or not authorization.startswith("Bearer "):
        raise HTTPException(
            status_code=401,
            detail="Bearer token required"
        )

    payload = decode_access_token(
        authorization[7:].strip()
    )

    with get_connection() as connection:
        with connection.cursor() as cursor:
            cursor.execute("""
                UPDATE public.mg_user_sessions
                SET revoked_at = NOW()
                WHERE id = %s
                  AND user_id = %s
                  AND revoked_at IS NULL
            """, (
                payload["sid"],
                payload["sub"]
            ))

    return {
        "success": True,
        "message": "Session revoked"
    }


# ---------------------------------------------------------
# CURRENT USER
# ---------------------------------------------------------

@app.get("/api/v1/auth/me")
def current_user(
    authorization: Optional[str] = Header(default=None)
):
    user = get_authenticated_user(authorization)

    with get_connection() as connection:
        with connection.cursor() as cursor:
            cursor.execute("""
                SELECT
                    bio,
                    avatar_url,
                    cover_url,
                    language,
                    timezone,
                    profile_visibility
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
def list_sessions(
    authorization: Optional[str] = Header(default=None)
):
    user = get_authenticated_user(authorization)

    with get_connection() as connection:
        with connection.cursor() as cursor:
            cursor.execute("""
                SELECT
                    s.id,
                    s.device_id,
                    s.created_at,
                    s.expires_at,
                    s.ip_address::text,
                    s.user_agent,
                    d.device_name,
                    d.platform,
                    d.app_version
                FROM public.mg_user_sessions s
                LEFT JOIN public.mg_user_devices d
                    ON d.id = s.device_id
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
            """, (
                session_id,
                user["id"]
            ))

            changed = cursor.rowcount

    if not changed:
        raise HTTPException(
            status_code=404,
            detail="Session not found or already revoked"
        )

    return {
        "success": True,
        "message": "Session revoked"
    }


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
def database_tables(
    x_admin_key: str = Header(default=None)
):
    verify_admin_key(x_admin_key)

    with get_connection() as connection:
        with connection.cursor() as cursor:
            cursor.execute("""
                SELECT table_schema, table_name
                FROM information_schema.tables
                WHERE table_schema NOT IN (
                    'pg_catalog',
                    'information_schema'
                )
                AND table_type = 'BASE TABLE'
                ORDER BY table_schema, table_name
            """)

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


@app.get("/api/v1/system/info")
def system_info():
    return {
        "application": "MASIH GRAM",
        "brand": "مسیح، شاه مجازی",
        "edition": "GLOBAL ULTIMATE",
        "api_version": "v1",
        "backend_version": APP_VERSION,
        "modules": {
            "authentication": "implemented",
            "otp": "implemented",
            "sessions": "implemented",
            "devices": "implemented",
            "messaging": "database_ready",
            "groups": "database_ready",
            "channels": "database_ready",
            "media": "database_ready",
            "social": "planned",
            "ai": "planned",
            "cloud": "planned",
            "live": "planned"
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
