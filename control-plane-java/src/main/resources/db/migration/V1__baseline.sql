-- AgentShield control plane baseline schema.
--
-- Two rules shape this file:
--
-- 1. Every tenant-scoped table carries workspace_id directly, even where it could be derived
--    through a join. Isolation must be enforceable in a single predicate; a filter that
--    depends on a three-table join is a filter someone will forget.
-- 2. Nothing here stores a secret in plaintext. Target credentials are AES-GCM ciphertext,
--    and the column is named so that is obvious at a glance.

CREATE TABLE workspace (
    id          UUID PRIMARY KEY,
    name        TEXT        NOT NULL,
    slug        TEXT        NOT NULL UNIQUE,
    created_at  TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at  TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE app_user (
    id                 UUID PRIMARY KEY,
    email              TEXT        NOT NULL UNIQUE,
    display_name       TEXT        NOT NULL,
    password_hash      TEXT,
    external_identity  TEXT,
    created_at         TIMESTAMPTZ NOT NULL DEFAULT now(),
    -- Either a local password or a federated identity, never neither.
    CONSTRAINT app_user_has_credential
        CHECK (password_hash IS NOT NULL OR external_identity IS NOT NULL)
);

CREATE TABLE workspace_member (
    workspace_id UUID        NOT NULL REFERENCES workspace (id) ON DELETE CASCADE,
    user_id      UUID        NOT NULL REFERENCES app_user (id) ON DELETE CASCADE,
    role         TEXT        NOT NULL CHECK (role IN ('OWNER', 'ENGINEER', 'VIEWER')),
    created_at   TIMESTAMPTZ NOT NULL DEFAULT now(),
    PRIMARY KEY (workspace_id, user_id)
);

CREATE INDEX idx_workspace_member_user ON workspace_member (user_id);

CREATE TABLE project (
    id           UUID PRIMARY KEY,
    workspace_id UUID        NOT NULL REFERENCES workspace (id) ON DELETE CASCADE,
    name         TEXT        NOT NULL,
    description  TEXT        NOT NULL DEFAULT '',
    created_at   TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at   TIMESTAMPTZ NOT NULL DEFAULT now(),
    UNIQUE (workspace_id, name)
);

CREATE TABLE target (
    id                       UUID PRIMARY KEY,
    workspace_id             UUID        NOT NULL REFERENCES workspace (id) ON DELETE CASCADE,
    project_id               UUID        NOT NULL REFERENCES project (id) ON DELETE CASCADE,
    name                     TEXT        NOT NULL,
    type                     TEXT        NOT NULL
        CHECK (type IN ('REST_AGENT', 'MCP_SERVER', 'ASYNC_AGENT', 'DEMO_TARGET')),
    adapter_type             TEXT        NOT NULL,
    base_url                 TEXT        NOT NULL,
    authentication_type      TEXT        NOT NULL DEFAULT 'NONE',
    -- AES-GCM ciphertext. Never selected into a DTO, never logged, never traced.
    configuration_encrypted  BYTEA,
    -- Hash of the non-secret configuration, recorded on every scan for reproducibility.
    configuration_hash       TEXT        NOT NULL DEFAULT '',
    enabled                  BOOLEAN     NOT NULL DEFAULT TRUE,
    created_at               TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at               TIMESTAMPTZ NOT NULL DEFAULT now(),
    UNIQUE (project_id, name)
);

CREATE INDEX idx_target_workspace ON target (workspace_id);

CREATE TABLE security_policy (
    id           UUID PRIMARY KEY,
    workspace_id UUID        NOT NULL REFERENCES workspace (id) ON DELETE CASCADE,
    project_id   UUID        NOT NULL REFERENCES project (id) ON DELETE CASCADE,
    name         TEXT        NOT NULL,
    version      INTEGER     NOT NULL DEFAULT 1,
    content      TEXT        NOT NULL,
    -- Findings pin themselves to this hash; two scans under different hashes are not
    -- comparable and the CI baseline diff must refuse to compare them.
    content_hash TEXT        NOT NULL,
    created_at   TIMESTAMPTZ NOT NULL DEFAULT now(),
    UNIQUE (project_id, name, version)
);

CREATE TABLE scan (
    id              UUID PRIMARY KEY,
    workspace_id    UUID        NOT NULL REFERENCES workspace (id) ON DELETE CASCADE,
    project_id      UUID        NOT NULL REFERENCES project (id) ON DELETE CASCADE,
    target_id       UUID        NOT NULL REFERENCES target (id),
    policy_id       UUID        NOT NULL REFERENCES security_policy (id),
    status          TEXT        NOT NULL
        CHECK (status IN ('CREATED', 'QUEUED', 'DISCOVERING', 'RUNNING',
                          'EVALUATING', 'COMPLETED', 'FAILED', 'CANCELLED')),
    -- Retrying POST /scans with the same key returns the original scan instead of starting
    -- a second one. Scoped to the workspace so keys cannot collide across tenants.
    idempotency_key TEXT        NOT NULL,
    requested_by    UUID        NOT NULL REFERENCES app_user (id),
    suites          TEXT        NOT NULL DEFAULT '',
    max_scenarios   INTEGER     NOT NULL DEFAULT 50,
    seed            INTEGER     NOT NULL DEFAULT 0,
    correlation_id  TEXT        NOT NULL,
    error_code      TEXT,
    error_message   TEXT,
    attack_count    INTEGER     NOT NULL DEFAULT 0,
    finding_count   INTEGER     NOT NULL DEFAULT 0,
    critical_count  INTEGER     NOT NULL DEFAULT 0,
    high_count      INTEGER     NOT NULL DEFAULT 0,
    medium_count    INTEGER     NOT NULL DEFAULT 0,
    low_count       INTEGER     NOT NULL DEFAULT 0,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
    started_at      TIMESTAMPTZ,
    completed_at    TIMESTAMPTZ,
    -- Optimistic lock. Several engine workers report progress for one scan concurrently;
    -- without it the second write silently discards the first.
    lock_version    BIGINT      NOT NULL DEFAULT 0,
    UNIQUE (workspace_id, idempotency_key)
);

CREATE INDEX idx_scan_project_created ON scan (project_id, created_at DESC);
CREATE INDEX idx_scan_status ON scan (status) WHERE status NOT IN ('COMPLETED', 'FAILED', 'CANCELLED');

CREATE TABLE attack_scenario (
    id              UUID PRIMARY KEY,
    workspace_id    UUID        NOT NULL REFERENCES workspace (id) ON DELETE CASCADE,
    scan_id         UUID        NOT NULL REFERENCES scan (id) ON DELETE CASCADE,
    scenario_key    TEXT        NOT NULL,
    category        TEXT        NOT NULL,
    name            TEXT        NOT NULL,
    template_id     TEXT        NOT NULL DEFAULT '',
    payload         TEXT        NOT NULL,
    expected_policy TEXT        NOT NULL DEFAULT '',
    seed            INTEGER     NOT NULL DEFAULT 0,
    status          TEXT        NOT NULL DEFAULT 'PENDING',
    created_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
    UNIQUE (scan_id, scenario_key)
);

CREATE TABLE attack_run (
    id                 UUID PRIMARY KEY,
    workspace_id       UUID        NOT NULL REFERENCES workspace (id) ON DELETE CASCADE,
    scenario_id        UUID        NOT NULL REFERENCES attack_scenario (id) ON DELETE CASCADE,
    attempt            INTEGER     NOT NULL DEFAULT 1,
    status             TEXT        NOT NULL,
    target_session_id  TEXT,
    input_tokens       INTEGER     NOT NULL DEFAULT 0,
    output_tokens      INTEGER     NOT NULL DEFAULT 0,
    estimated_cost_usd NUMERIC(12, 6) NOT NULL DEFAULT 0,
    started_at         TIMESTAMPTZ,
    completed_at       TIMESTAMPTZ,
    UNIQUE (scenario_id, attempt)
);

CREATE TABLE trajectory_step (
    id              UUID PRIMARY KEY,
    workspace_id    UUID        NOT NULL REFERENCES workspace (id) ON DELETE CASCADE,
    attack_run_id   UUID        NOT NULL REFERENCES attack_run (id) ON DELETE CASCADE,
    sequence_number INTEGER     NOT NULL,
    step_type       TEXT        NOT NULL
        CHECK (step_type IN ('USER_INPUT', 'MODEL_OUTPUT', 'RETRIEVAL', 'TOOL_CALL',
                             'TOOL_RESULT', 'APPROVAL_REQUEST', 'APPROVAL_RESULT',
                             'FINAL_OUTPUT', 'ERROR')),
    tool_name       TEXT,
    -- Redacted by the engine before it ever reaches the wire. The column names say so, so
    -- nobody adds an unredacted sibling by accident.
    input_redacted  TEXT        NOT NULL DEFAULT '',
    output_redacted TEXT        NOT NULL DEFAULT '',
    duration_ms     INTEGER,
    trace_id        TEXT,
    occurred_at     TIMESTAMPTZ NOT NULL DEFAULT now(),
    UNIQUE (attack_run_id, sequence_number)
);

CREATE INDEX idx_trajectory_step_run ON trajectory_step (attack_run_id, sequence_number);

CREATE TABLE finding (
    id             UUID PRIMARY KEY,
    workspace_id   UUID        NOT NULL REFERENCES workspace (id) ON DELETE CASCADE,
    scan_id        UUID        NOT NULL REFERENCES scan (id) ON DELETE CASCADE,
    scenario_id    UUID        REFERENCES attack_scenario (id) ON DELETE SET NULL,
    code           TEXT        NOT NULL,
    category       TEXT        NOT NULL,
    severity       TEXT        NOT NULL CHECK (severity IN ('CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'INFO')),
    title          TEXT        NOT NULL,
    description    TEXT        NOT NULL DEFAULT '',
    evidence       TEXT        NOT NULL DEFAULT '{}',
    reproduction   TEXT        NOT NULL DEFAULT '{}',
    remediation    TEXT        NOT NULL DEFAULT '{}',
    status         TEXT        NOT NULL DEFAULT 'OPEN'
        CHECK (status IN ('OPEN', 'RESOLVED', 'ACCEPTED_RISK', 'FALSE_POSITIVE')),
    -- Identity of the defect across scans. The CI gate diffs on this, so it is indexed.
    fingerprint    TEXT        NOT NULL,
    detected_by    TEXT        NOT NULL DEFAULT '',
    occurrences    INTEGER     NOT NULL DEFAULT 1,
    first_seen_at  TIMESTAMPTZ NOT NULL DEFAULT now(),
    last_seen_at   TIMESTAMPTZ NOT NULL DEFAULT now(),
    -- One row per defect per scan; a duplicate delivery updates instead of inserts.
    UNIQUE (scan_id, fingerprint)
);

CREATE INDEX idx_finding_fingerprint ON finding (workspace_id, fingerprint);
CREATE INDEX idx_finding_scan_severity ON finding (scan_id, severity);

CREATE TABLE regression_baseline (
    id           UUID PRIMARY KEY,
    workspace_id UUID        NOT NULL REFERENCES workspace (id) ON DELETE CASCADE,
    project_id   UUID        NOT NULL REFERENCES project (id) ON DELETE CASCADE,
    scan_id      UUID        NOT NULL REFERENCES scan (id),
    name         TEXT        NOT NULL,
    policy_hash  TEXT        NOT NULL DEFAULT '',
    fingerprints TEXT        NOT NULL DEFAULT '',
    created_at   TIMESTAMPTZ NOT NULL DEFAULT now(),
    UNIQUE (project_id, name)
);

CREATE TABLE ci_token (
    id           UUID PRIMARY KEY,
    workspace_id UUID        NOT NULL REFERENCES workspace (id) ON DELETE CASCADE,
    project_id   UUID        REFERENCES project (id) ON DELETE CASCADE,
    name         TEXT        NOT NULL,
    -- Only the hash is stored; the token itself is shown once, at creation.
    token_hash   TEXT        NOT NULL UNIQUE,
    created_by   UUID        NOT NULL REFERENCES app_user (id),
    expires_at   TIMESTAMPTZ,
    revoked_at   TIMESTAMPTZ,
    created_at   TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE audit_log (
    id           BIGSERIAL PRIMARY KEY,
    workspace_id UUID        NOT NULL,
    actor_id     UUID,
    action       TEXT        NOT NULL,
    resource     TEXT        NOT NULL,
    resource_id  TEXT,
    detail       TEXT        NOT NULL DEFAULT '{}',
    occurred_at  TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX idx_audit_workspace_time ON audit_log (workspace_id, occurred_at DESC);
