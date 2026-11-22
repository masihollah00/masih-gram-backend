
BEGIN;

-- Phone-based authentication support
ALTER TABLE public.mg_users
    ALTER COLUMN password_hash DROP NOT NULL;

ALTER TABLE public.mg_users
    ADD COLUMN IF NOT EXISTS phone_verified_at TIMESTAMPTZ;

ALTER TABLE public.mg_users
    ADD COLUMN IF NOT EXISTS registration_completed_at TIMESTAMPTZ;

-- OTP challenges
CREATE TABLE IF NOT EXISTS public.mg_auth_otp_challenges (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),

    phone VARCHAR(30) NOT NULL,
    purpose VARCHAR(20) NOT NULL
        CHECK (purpose IN ('signup', 'login')),

    code_hash TEXT NOT NULL,

    attempts SMALLINT NOT NULL DEFAULT 0
        CHECK (attempts >= 0),

    max_attempts SMALLINT NOT NULL DEFAULT 5
        CHECK (max_attempts BETWEEN 1 AND 10),

    expires_at TIMESTAMPTZ NOT NULL,
    consumed_at TIMESTAMPTZ,

    request_ip INET,
    provider VARCHAR(30) NOT NULL DEFAULT 'textbee',
    provider_batch_id TEXT,

    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),

    CHECK (expires_at > created_at)
);

CREATE INDEX IF NOT EXISTS mg_otp_phone_created_idx
ON public.mg_auth_otp_challenges(phone, created_at DESC);

CREATE INDEX IF NOT EXISTS mg_otp_expiry_idx
ON public.mg_auth_otp_challenges(expires_at);

CREATE INDEX IF NOT EXISTS mg_otp_active_phone_idx
ON public.mg_auth_otp_challenges(phone, purpose)
WHERE consumed_at IS NULL;

-- Security and authentication audit indexes
CREATE INDEX IF NOT EXISTS mg_sessions_active_user_idx
ON public.mg_user_sessions(user_id, expires_at)
WHERE revoked_at IS NULL;

CREATE INDEX IF NOT EXISTS mg_devices_active_user_idx
ON public.mg_user_devices(user_id, last_active_at DESC)
WHERE is_active = TRUE;

INSERT INTO public.mg_schema_migrations(version, description)
VALUES (
    '002_auth_engine',
    'MASIH GRAM phone authentication and OTP foundation'
)
ON CONFLICT (version) DO NOTHING;

COMMIT;
