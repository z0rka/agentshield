-- Transactional outbox and consumer idempotency.
--
-- The problem being solved: "write to the database, then publish to Kafka" is two operations
-- that can half-succeed. A scan row with no event stalls forever; an event with no row makes
-- the engine work on something that does not exist. The outbox makes the write and the intent
-- to publish one atomic commit, and a relay does the publishing afterwards.
--
-- This yields at-least-once delivery, never exactly-once. Duplicates are therefore the normal
-- case, not the exception - which is what processed_event is for.

CREATE TABLE outbox_entry (
    id             UUID PRIMARY KEY,
    aggregate_type TEXT        NOT NULL,
    aggregate_id   TEXT        NOT NULL,
    workspace_id   UUID        NOT NULL,
    event_type     TEXT        NOT NULL,
    event_version  INTEGER     NOT NULL DEFAULT 1,
    topic          TEXT        NOT NULL,
    payload        TEXT        NOT NULL,
    correlation_id TEXT        NOT NULL,
    created_at     TIMESTAMPTZ NOT NULL DEFAULT now(),
    published_at   TIMESTAMPTZ,
    attempts       INTEGER     NOT NULL DEFAULT 0,
    next_attempt_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    last_error     TEXT
);

-- The relay's hot query: unpublished entries whose backoff has elapsed, oldest first.
-- Partial index so the table can grow without slowing the poll.
CREATE INDEX idx_outbox_pending
    ON outbox_entry (next_attempt_at, created_at)
    WHERE published_at IS NULL;

CREATE INDEX idx_outbox_aggregate ON outbox_entry (aggregate_type, aggregate_id);

CREATE TABLE processed_event (
    -- The event id from the envelope. A duplicate delivery collides on the primary key and
    -- the handler skips it: idempotency enforced by the database rather than by a check the
    -- next consumer author might forget.
    event_id     UUID PRIMARY KEY,
    event_type   TEXT        NOT NULL,
    consumer     TEXT        NOT NULL,
    workspace_id UUID,
    processed_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX idx_processed_event_time ON processed_event (processed_at);

-- Failures that survived the retry topics. Kept in the database as well as the DLQ topic so
-- an operator can see them without a Kafka client.
CREATE TABLE dead_letter (
    id           UUID PRIMARY KEY,
    event_id     UUID,
    event_type   TEXT        NOT NULL,
    topic        TEXT        NOT NULL,
    workspace_id UUID,
    payload      TEXT        NOT NULL,
    error        TEXT        NOT NULL,
    attempts     INTEGER     NOT NULL DEFAULT 0,
    created_at   TIMESTAMPTZ NOT NULL DEFAULT now()
);
