
-- =========================================================
-- MASIH GRAM GLOBAL
-- GLOBAL ULTIMATE EDITION
-- CORE DATABASE MIGRATION 001
-- PostgreSQL 18+
-- =========================================================

BEGIN;

-- ---------------------------------------------------------
-- 1. MIGRATION HISTORY
-- ---------------------------------------------------------

CREATE TABLE IF NOT EXISTS public.mg_schema_migrations (
    version VARCHAR(100) PRIMARY KEY,
    description TEXT NOT NULL,
    applied_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- ---------------------------------------------------------
-- 2. USERS
-- ---------------------------------------------------------

CREATE TABLE IF NOT EXISTS public.mg_users (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),

    username VARCHAR(32) NOT NULL,
    display_name VARCHAR(100) NOT NULL,

    email VARCHAR(255),
    phone VARCHAR(30),

    password_hash TEXT NOT NULL,

    account_status VARCHAR(20) NOT NULL DEFAULT 'active'
        CHECK (account_status IN (
            'active', 'suspended', 'disabled', 'pending'
        )),

    is_verified BOOLEAN NOT NULL DEFAULT FALSE,
    is_premium BOOLEAN NOT NULL DEFAULT FALSE,

    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    last_seen_at TIMESTAMPTZ,

    deleted_at TIMESTAMPTZ
);

CREATE UNIQUE INDEX IF NOT EXISTS mg_users_username_unique
ON public.mg_users (LOWER(username));

CREATE UNIQUE INDEX IF NOT EXISTS mg_users_email_unique
ON public.mg_users (LOWER(email))
WHERE email IS NOT NULL;

CREATE UNIQUE INDEX IF NOT EXISTS mg_users_phone_unique
ON public.mg_users (phone)
WHERE phone IS NOT NULL;

-- ---------------------------------------------------------
-- 3. USER PROFILES
-- ---------------------------------------------------------

CREATE TABLE IF NOT EXISTS public.mg_user_profiles (
    user_id UUID PRIMARY KEY
        REFERENCES public.mg_users(id) ON DELETE CASCADE,

    bio TEXT,
    avatar_url TEXT,
    cover_url TEXT,

    country_code VARCHAR(5),
    language VARCHAR(12) NOT NULL DEFAULT 'fa',
    timezone VARCHAR(80),

    birth_date DATE,
    website_url TEXT,

    profile_visibility VARCHAR(20) NOT NULL DEFAULT 'public'
        CHECK (profile_visibility IN (
            'public', 'contacts', 'private'
        )),

    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- ---------------------------------------------------------
-- 4. USER DEVICES
-- ---------------------------------------------------------

CREATE TABLE IF NOT EXISTS public.mg_user_devices (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),

    user_id UUID NOT NULL
        REFERENCES public.mg_users(id) ON DELETE CASCADE,

    device_name VARCHAR(120),
    device_type VARCHAR(30),
    platform VARCHAR(50),
    app_version VARCHAR(40),

    device_fingerprint_hash TEXT,

    push_token TEXT,

    last_active_at TIMESTAMPTZ DEFAULT NOW(),
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),

    is_trusted BOOLEAN NOT NULL DEFAULT FALSE,
    is_active BOOLEAN NOT NULL DEFAULT TRUE
);

CREATE INDEX IF NOT EXISTS mg_devices_user_idx
ON public.mg_user_devices(user_id);

-- ---------------------------------------------------------
-- 5. AUTHENTICATION SESSIONS
-- ---------------------------------------------------------

CREATE TABLE IF NOT EXISTS public.mg_user_sessions (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),

    user_id UUID NOT NULL
        REFERENCES public.mg_users(id) ON DELETE CASCADE,

    device_id UUID
        REFERENCES public.mg_user_devices(id) ON DELETE SET NULL,

    refresh_token_hash TEXT NOT NULL UNIQUE,

    ip_address INET,
    user_agent TEXT,

    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    expires_at TIMESTAMPTZ NOT NULL,
    revoked_at TIMESTAMPTZ,

    CHECK (expires_at > created_at)
);

CREATE INDEX IF NOT EXISTS mg_sessions_user_idx
ON public.mg_user_sessions(user_id);

CREATE INDEX IF NOT EXISTS mg_sessions_expiry_idx
ON public.mg_user_sessions(expires_at);

-- ---------------------------------------------------------
-- 6. CONVERSATIONS
-- ---------------------------------------------------------

CREATE TABLE IF NOT EXISTS public.mg_conversations (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),

    conversation_type VARCHAR(20) NOT NULL
        CHECK (conversation_type IN (
            'direct', 'group', 'channel'
        )),

    title VARCHAR(150),
    description TEXT,
    photo_url TEXT,

    created_by UUID
        REFERENCES public.mg_users(id) ON DELETE SET NULL,

    is_public BOOLEAN NOT NULL DEFAULT FALSE,
    invite_code_hash TEXT,

    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),

    last_message_at TIMESTAMPTZ
);

CREATE INDEX IF NOT EXISTS mg_conversations_updated_idx
ON public.mg_conversations(updated_at DESC);

-- ---------------------------------------------------------
-- 7. CONVERSATION MEMBERS
-- ---------------------------------------------------------

CREATE TABLE IF NOT EXISTS public.mg_conversation_members (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),

    conversation_id UUID NOT NULL
        REFERENCES public.mg_conversations(id) ON DELETE CASCADE,

    user_id UUID NOT NULL
        REFERENCES public.mg_users(id) ON DELETE CASCADE,

    member_role VARCHAR(20) NOT NULL DEFAULT 'member'
        CHECK (member_role IN (
            'owner', 'admin', 'moderator', 'member'
        )),

    joined_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    left_at TIMESTAMPTZ,

    is_muted BOOLEAN NOT NULL DEFAULT FALSE,
    is_pinned BOOLEAN NOT NULL DEFAULT FALSE,
    is_archived BOOLEAN NOT NULL DEFAULT FALSE,

    last_read_at TIMESTAMPTZ,

    UNIQUE(conversation_id, user_id)
);

CREATE INDEX IF NOT EXISTS mg_members_user_idx
ON public.mg_conversation_members(user_id);

CREATE INDEX IF NOT EXISTS mg_members_conversation_idx
ON public.mg_conversation_members(conversation_id);

-- ---------------------------------------------------------
-- 8. MESSAGES
-- ---------------------------------------------------------

CREATE TABLE IF NOT EXISTS public.mg_messages (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),

    conversation_id UUID NOT NULL
        REFERENCES public.mg_conversations(id) ON DELETE CASCADE,

    sender_id UUID
        REFERENCES public.mg_users(id) ON DELETE SET NULL,

    reply_to_id UUID
        REFERENCES public.mg_messages(id) ON DELETE SET NULL,

    message_type VARCHAR(30) NOT NULL DEFAULT 'text'
        CHECK (message_type IN (
            'text', 'image', 'video', 'audio',
            'voice', 'file', 'location',
            'contact', 'sticker', 'system'
        )),

    body TEXT,
    metadata JSONB NOT NULL DEFAULT '{}'::JSONB,

    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    edited_at TIMESTAMPTZ,
    deleted_at TIMESTAMPTZ,

    is_forwarded BOOLEAN NOT NULL DEFAULT FALSE,
    is_pinned BOOLEAN NOT NULL DEFAULT FALSE
);

CREATE INDEX IF NOT EXISTS mg_messages_conversation_time_idx
ON public.mg_messages(conversation_id, created_at DESC);

CREATE INDEX IF NOT EXISTS mg_messages_sender_idx
ON public.mg_messages(sender_id);

CREATE INDEX IF NOT EXISTS mg_messages_reply_idx
ON public.mg_messages(reply_to_id);

-- ---------------------------------------------------------
-- 9. MESSAGE RECEIPTS
-- ---------------------------------------------------------

CREATE TABLE IF NOT EXISTS public.mg_message_receipts (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),

    message_id UUID NOT NULL
        REFERENCES public.mg_messages(id) ON DELETE CASCADE,

    user_id UUID NOT NULL
        REFERENCES public.mg_users(id) ON DELETE CASCADE,

    delivery_status VARCHAR(20) NOT NULL DEFAULT 'sent'
        CHECK (delivery_status IN (
            'sent', 'delivered', 'read'
        )),

    delivered_at TIMESTAMPTZ,
    read_at TIMESTAMPTZ,

    UNIQUE(message_id, user_id)
);

CREATE INDEX IF NOT EXISTS mg_receipts_user_idx
ON public.mg_message_receipts(user_id);

-- ---------------------------------------------------------
-- 10. ATTACHMENTS
-- ---------------------------------------------------------

CREATE TABLE IF NOT EXISTS public.mg_attachments (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),

    uploaded_by UUID
        REFERENCES public.mg_users(id) ON DELETE SET NULL,

    original_name TEXT NOT NULL,
    storage_key TEXT NOT NULL UNIQUE,

    mime_type VARCHAR(150),
    file_size BIGINT NOT NULL CHECK (file_size >= 0),

    checksum_sha256 VARCHAR(64),

    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    deleted_at TIMESTAMPTZ
);

CREATE TABLE IF NOT EXISTS public.mg_message_attachments (
    message_id UUID NOT NULL
        REFERENCES public.mg_messages(id) ON DELETE CASCADE,

    attachment_id UUID NOT NULL
        REFERENCES public.mg_attachments(id) ON DELETE CASCADE,

    position INTEGER NOT NULL DEFAULT 0,

    PRIMARY KEY(message_id, attachment_id)
);

CREATE INDEX IF NOT EXISTS mg_attachments_owner_idx
ON public.mg_attachments(uploaded_by);

-- ---------------------------------------------------------
-- 11. MESSAGE REACTIONS
-- ---------------------------------------------------------

CREATE TABLE IF NOT EXISTS public.mg_message_reactions (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),

    message_id UUID NOT NULL
        REFERENCES public.mg_messages(id) ON DELETE CASCADE,

    user_id UUID NOT NULL
        REFERENCES public.mg_users(id) ON DELETE CASCADE,

    reaction VARCHAR(32) NOT NULL,

    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),

    UNIQUE(message_id, user_id, reaction)
);

CREATE INDEX IF NOT EXISTS mg_reactions_message_idx
ON public.mg_message_reactions(message_id);

-- ---------------------------------------------------------
-- 12. USER BLOCKS
-- ---------------------------------------------------------

CREATE TABLE IF NOT EXISTS public.mg_user_blocks (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),

    blocker_id UUID NOT NULL
        REFERENCES public.mg_users(id) ON DELETE CASCADE,

    blocked_id UUID NOT NULL
        REFERENCES public.mg_users(id) ON DELETE CASCADE,

    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),

    CHECK (blocker_id <> blocked_id),
    UNIQUE(blocker_id, blocked_id)
);

-- ---------------------------------------------------------
-- 13. USER SETTINGS
-- ---------------------------------------------------------

CREATE TABLE IF NOT EXISTS public.mg_user_settings (
    user_id UUID PRIMARY KEY
        REFERENCES public.mg_users(id) ON DELETE CASCADE,

    settings JSONB NOT NULL DEFAULT '{}'::JSONB,

    notification_settings JSONB NOT NULL DEFAULT '{}'::JSONB,

    privacy_settings JSONB NOT NULL DEFAULT '{}'::JSONB,

    appearance_settings JSONB NOT NULL DEFAULT '{}'::JSONB,

    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- ---------------------------------------------------------
-- 14. USER CONTACTS
-- ---------------------------------------------------------

CREATE TABLE IF NOT EXISTS public.mg_user_contacts (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),

    owner_id UUID NOT NULL
        REFERENCES public.mg_users(id) ON DELETE CASCADE,

    contact_user_id UUID NOT NULL
        REFERENCES public.mg_users(id) ON DELETE CASCADE,

    custom_name VARCHAR(100),

    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),

    CHECK (owner_id <> contact_user_id),
    UNIQUE(owner_id, contact_user_id)
);

CREATE INDEX IF NOT EXISTS mg_contacts_owner_idx
ON public.mg_user_contacts(owner_id);

-- ---------------------------------------------------------
-- 15. USER REPORTS
-- ---------------------------------------------------------

CREATE TABLE IF NOT EXISTS public.mg_user_reports (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),

    reporter_id UUID
        REFERENCES public.mg_users(id) ON DELETE SET NULL,

    reported_user_id UUID
        REFERENCES public.mg_users(id) ON DELETE SET NULL,

    message_id UUID
        REFERENCES public.mg_messages(id) ON DELETE SET NULL,

    reason VARCHAR(80) NOT NULL,
    details TEXT,

    report_status VARCHAR(20) NOT NULL DEFAULT 'pending'
        CHECK (report_status IN (
            'pending', 'reviewing', 'resolved', 'rejected'
        )),

    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    reviewed_at TIMESTAMPTZ
);

CREATE INDEX IF NOT EXISTS mg_reports_status_idx
ON public.mg_user_reports(report_status, created_at);

-- ---------------------------------------------------------
-- 16. AUDIT EVENTS
-- ---------------------------------------------------------

CREATE TABLE IF NOT EXISTS public.mg_audit_events (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),

    actor_user_id UUID
        REFERENCES public.mg_users(id) ON DELETE SET NULL,

    event_type VARCHAR(100) NOT NULL,
    target_type VARCHAR(80),
    target_id UUID,

    details JSONB NOT NULL DEFAULT '{}'::JSONB,

    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS mg_audit_actor_idx
ON public.mg_audit_events(actor_user_id, created_at DESC);

-- ---------------------------------------------------------
-- 17. FINALIZE MIGRATION
-- ---------------------------------------------------------

INSERT INTO public.mg_schema_migrations (
    version,
    description
)
VALUES (
    '001_initial_core',
    'MASIH GRAM GLOBAL core database foundation'
)
ON CONFLICT (version) DO NOTHING;

COMMIT;

-- =========================================================
-- END OF MIGRATION 001
-- =========================================================
