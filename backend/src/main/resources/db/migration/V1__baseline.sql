-- ---------------------------------------------------------------------------
-- IAM platform baseline schema.
-- PostgreSQL is the source of truth for identity; Redis only holds derived or
-- short-lived state and is never authoritative for anything in this file.
-- ---------------------------------------------------------------------------

CREATE EXTENSION IF NOT EXISTS pgcrypto;

-- --------------------------------------------------------------- identities --

CREATE TABLE users (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    email VARCHAR(320) NOT NULL,
    password_hash VARCHAR(255) NOT NULL,
    status VARCHAR(32) NOT NULL,
    email_verified BOOLEAN NOT NULL DEFAULT FALSE,
    -- Bumped whenever authorities change; tokens carrying an older value are
    -- rejected, which closes the stale-permission window (doc section 20.2).
    permission_version INTEGER NOT NULL DEFAULT 1,
    locked_until TIMESTAMPTZ,
    lockout_strikes INTEGER NOT NULL DEFAULT 0,
    last_login_at TIMESTAMPTZ,
    password_changed_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    deleted_at TIMESTAMPTZ,
    version BIGINT NOT NULL DEFAULT 0,
    CONSTRAINT ck_users_status CHECK (status IN ('PENDING_VERIFICATION', 'ACTIVE', 'DISABLED',
        'DELETED'))
);

-- Email is stored already normalised (trimmed + lower-cased) by the application,
-- so "A@x.com" and "a@x.com" can never both be registered.
CREATE UNIQUE INDEX ux_users_email ON users (email);

-- ------------------------------------------------------------- applications --

CREATE TABLE client_applications (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    client_id VARCHAR(64) NOT NULL,
    client_secret_hash VARCHAR(255),
    name VARCHAR(160) NOT NULL,
    client_type VARCHAR(16) NOT NULL,
    status VARCHAR(16) NOT NULL,
    require_consent BOOLEAN NOT NULL DEFAULT TRUE,
    require_pkce BOOLEAN NOT NULL DEFAULT TRUE,
    access_token_ttl_seconds INTEGER,
    refresh_token_ttl_seconds INTEGER,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    version BIGINT NOT NULL DEFAULT 0,
    CONSTRAINT ck_clients_type CHECK (client_type IN ('PUBLIC', 'CONFIDENTIAL')),
    CONSTRAINT ck_clients_status CHECK (status IN ('ACTIVE', 'DISABLED')),
    -- A confidential client with no secret would authenticate as nobody.
    CONSTRAINT ck_clients_secret CHECK (NOT (client_type = 'CONFIDENTIAL' AND client_secret_hash IS NULL))
);

CREATE UNIQUE INDEX ux_client_applications_client_id ON client_applications (client_id);

CREATE TABLE client_redirect_uris (
    client_application_id UUID NOT NULL REFERENCES client_applications (id) ON DELETE CASCADE,
    redirect_uri VARCHAR(2000) NOT NULL,
    PRIMARY KEY (client_application_id, redirect_uri)
);

CREATE TABLE client_scopes (
    client_application_id UUID NOT NULL REFERENCES client_applications (id) ON DELETE CASCADE,
    scope VARCHAR(64) NOT NULL,
    PRIMARY KEY (client_application_id, scope)
);

-- --------------------------------------------------------------------- rbac --

CREATE TABLE permissions (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    name VARCHAR(96) NOT NULL,
    description VARCHAR(255),
    created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE UNIQUE INDEX ux_permissions_name ON permissions (name);

CREATE TABLE roles (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    name VARCHAR(64) NOT NULL,
    description VARCHAR(255),
    -- NULL = platform-wide role. Otherwise the role applies only to that client,
    -- which is what stops roles leaking across applications.
    client_application_id UUID REFERENCES client_applications (id) ON DELETE CASCADE,
    system_role BOOLEAN NOT NULL DEFAULT FALSE,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    version BIGINT NOT NULL DEFAULT 0
);

-- COALESCE keeps uniqueness meaningful for platform roles, where a NULL scope
-- would otherwise never collide with itself.
CREATE UNIQUE INDEX ux_roles_name_scope
ON roles (name, COALESCE(client_application_id, '00000000-0000-0000-0000-000000000000'::uuid));

CREATE TABLE role_permissions (
    role_id UUID NOT NULL REFERENCES roles (id) ON DELETE CASCADE,
    permission_id UUID NOT NULL REFERENCES permissions (id) ON DELETE CASCADE,
    PRIMARY KEY (role_id, permission_id)
);

CREATE TABLE user_roles (
    user_id UUID NOT NULL REFERENCES users (id) ON DELETE CASCADE,
    role_id UUID NOT NULL REFERENCES roles (id) ON DELETE CASCADE,
    assigned_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    PRIMARY KEY (user_id, role_id)
);

CREATE INDEX ix_user_roles_role ON user_roles (role_id);

-- ----------------------------------------------------------------- sessions --

CREATE TABLE sessions (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id UUID NOT NULL REFERENCES users (id) ON DELETE CASCADE,
    client_application_id UUID REFERENCES client_applications (id) ON DELETE SET NULL,
    -- SHA-256 of the SSO cookie secret; the raw value never reaches the database.
    sso_token_hash VARCHAR(64),
    device_info VARCHAR(512),
    ip_address VARCHAR(64),
    -- Scopes granted when this session was established. Rotation reissues tokens
    -- from the session, so the grant cannot silently widen on refresh.
    scopes VARCHAR(512),
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    last_seen_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    expires_at TIMESTAMPTZ NOT NULL,
    revoked_at TIMESTAMPTZ,
    revoked_reason VARCHAR(64),
    version BIGINT NOT NULL DEFAULT 0
);

CREATE INDEX ix_sessions_user_active ON sessions (user_id) WHERE revoked_at IS NULL;
CREATE UNIQUE INDEX ux_sessions_sso_token ON sessions (sso_token_hash) WHERE sso_token_hash IS NOT NULL;

-- ------------------------------------------------------------------- tokens --

CREATE TABLE refresh_tokens (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    -- Every token descended from one login shares a family id; detecting reuse
    -- of any member revokes the whole family.
    family_id UUID NOT NULL,
    user_id UUID NOT NULL REFERENCES users (id) ON DELETE CASCADE,
    session_id UUID NOT NULL REFERENCES sessions (id) ON DELETE CASCADE,
    client_application_id UUID REFERENCES client_applications (id) ON DELETE CASCADE,
    token_hash VARCHAR(64) NOT NULL,
    issued_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    expires_at TIMESTAMPTZ NOT NULL,
    revoked_at TIMESTAMPTZ,
    revoked_reason VARCHAR(64),
    replaced_by_id UUID REFERENCES refresh_tokens (id) ON DELETE SET NULL
);

CREATE UNIQUE INDEX ux_refresh_tokens_hash ON refresh_tokens (token_hash);
CREATE INDEX ix_refresh_tokens_family ON refresh_tokens (family_id);
CREATE INDEX ix_refresh_tokens_session ON refresh_tokens (session_id);
CREATE INDEX ix_refresh_tokens_expiry ON refresh_tokens (expires_at);

CREATE TABLE email_verification_tokens (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id UUID NOT NULL REFERENCES users (id) ON DELETE CASCADE,
    token_hash VARCHAR(64) NOT NULL,
    expires_at TIMESTAMPTZ NOT NULL,
    used_at TIMESTAMPTZ,
    invalidated_at TIMESTAMPTZ,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE UNIQUE INDEX ux_email_verification_hash ON email_verification_tokens (token_hash);
CREATE INDEX ix_email_verification_user ON email_verification_tokens (user_id);

CREATE TABLE password_reset_tokens (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id UUID NOT NULL REFERENCES users (id) ON DELETE CASCADE,
    token_hash VARCHAR(64) NOT NULL,
    expires_at TIMESTAMPTZ NOT NULL,
    used_at TIMESTAMPTZ,
    invalidated_at TIMESTAMPTZ,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE UNIQUE INDEX ux_password_reset_hash ON password_reset_tokens (token_hash);
CREATE INDEX ix_password_reset_user ON password_reset_tokens (user_id);

-- ------------------------------------------------------------------ consent --

CREATE TABLE user_consents (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id UUID NOT NULL REFERENCES users (id) ON DELETE CASCADE,
    client_application_id UUID NOT NULL REFERENCES client_applications (id) ON DELETE CASCADE,
    scopes VARCHAR(512) NOT NULL,
    granted_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    revoked_at TIMESTAMPTZ,
    version BIGINT NOT NULL DEFAULT 0
);

CREATE UNIQUE INDEX ux_user_consents ON user_consents (user_id, client_application_id);

-- --------------------------------------------------------- security records --

CREATE TABLE login_attempts (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    email VARCHAR(320) NOT NULL,
    user_id UUID REFERENCES users (id) ON DELETE SET NULL,
    successful BOOLEAN NOT NULL,
    failure_reason VARCHAR(64),
    ip_address VARCHAR(64),
    user_agent VARCHAR(512),
    created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX ix_login_attempts_email_time ON login_attempts (email, created_at DESC);

CREATE TABLE audit_events (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    event_type VARCHAR(64) NOT NULL,
    actor_user_id UUID,
    target_id VARCHAR(128),
    client_id VARCHAR(64),
    ip_address VARCHAR(64),
    correlation_id VARCHAR(64),
    outcome VARCHAR(16) NOT NULL,
    detail VARCHAR(1024),
    created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX ix_audit_events_time ON audit_events (created_at DESC);
CREATE INDEX ix_audit_events_actor ON audit_events (actor_user_id, created_at DESC);

-- -------------------------------------------------------------- mail outbox --

-- Transactional outbox: the mail row commits with the business change and a
-- background dispatcher delivers it, so a dead SMTP server cannot fail a
-- registration or a password reset.
CREATE TABLE email_outbox (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    recipient VARCHAR(320) NOT NULL,
    subject VARCHAR(255) NOT NULL,
    body TEXT NOT NULL,
    status VARCHAR(16) NOT NULL,
    attempts INTEGER NOT NULL DEFAULT 0,
    next_attempt_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    last_error VARCHAR(512),
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    sent_at TIMESTAMPTZ,
    version BIGINT NOT NULL DEFAULT 0,
    CONSTRAINT ck_outbox_status CHECK (status IN ('PENDING', 'SENT', 'FAILED'))
);

CREATE INDEX ix_email_outbox_pending ON email_outbox (next_attempt_at) WHERE status = 'PENDING';