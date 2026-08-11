-- BaseEntity supplies created_at for every persisted UUID entity.  These stage-1 tables were
-- missing it, which Hibernate validation would otherwise catch only on the first real startup.
ALTER TABLE attack_run ADD COLUMN created_at TIMESTAMPTZ NOT NULL DEFAULT now();
ALTER TABLE trajectory_step ADD COLUMN created_at TIMESTAMPTZ NOT NULL DEFAULT now();
ALTER TABLE finding ADD COLUMN created_at TIMESTAMPTZ NOT NULL DEFAULT now();
