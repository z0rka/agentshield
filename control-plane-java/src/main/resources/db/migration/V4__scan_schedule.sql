-- Recurring scans.
--
-- A security scan that only runs when somebody remembers to run it is a security scan that
-- stops running. The schedule is the difference between "we tested this once" and "this is
-- tested", and it is the only part of the platform that produces work with no human in the
-- request path.
CREATE TABLE scan_schedule (
    id                  UUID PRIMARY KEY,
    workspace_id        UUID        NOT NULL,
    project_id          UUID        NOT NULL,
    target_id           UUID        NOT NULL,
    policy_id           UUID        NOT NULL,
    name                TEXT        NOT NULL,
    -- Interval rather than cron. Cron needs a timezone to mean anything, and a scan that
    -- silently moves by an hour twice a year is a scan whose baseline comparison drifts.
    interval_minutes    INTEGER     NOT NULL CHECK (interval_minutes >= 5),
    suites              TEXT        NOT NULL DEFAULT '',
    max_scenarios       INTEGER     NOT NULL DEFAULT 50,
    enabled             BOOLEAN     NOT NULL DEFAULT TRUE,
    created_by          UUID,
    -- When the scheduler should next consider it. Kept as a column rather than computed from
    -- `last_run_at` so a paused-then-resumed schedule does not immediately fire a backlog.
    next_run_at         TIMESTAMPTZ NOT NULL DEFAULT now(),
    last_run_at         TIMESTAMPTZ,
    last_scan_id        UUID,
    created_at          TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at          TIMESTAMPTZ NOT NULL DEFAULT now()
);

-- The scheduler's only query: due, enabled, oldest first. Partial so the index holds just the
-- rows it will ever read.
CREATE INDEX idx_schedule_due ON scan_schedule (next_run_at) WHERE enabled;

CREATE INDEX idx_schedule_workspace ON scan_schedule (workspace_id);
