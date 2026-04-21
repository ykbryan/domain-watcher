CREATE EXTENSION IF NOT EXISTS pgcrypto;

CREATE TABLE scan_jobs (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    target_domain   TEXT NOT NULL,
    status          TEXT NOT NULL CHECK (status IN ('queued','running','completed','failed')),
    triggered_by    TEXT NOT NULL CHECK (triggered_by IN ('api','monitor','cli')),
    created_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
    completed_at    TIMESTAMPTZ,
    error           TEXT
);

CREATE INDEX scan_jobs_target_domain_idx ON scan_jobs(target_domain);
CREATE INDEX scan_jobs_created_at_idx ON scan_jobs(created_at DESC);

CREATE TABLE permutations (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    scan_job_id     UUID NOT NULL REFERENCES scan_jobs(id) ON DELETE CASCADE,
    domain          TEXT NOT NULL,
    dns_a           TEXT[] NOT NULL DEFAULT '{}',
    dns_mx          TEXT[] NOT NULL DEFAULT '{}',
    dns_ns          TEXT[] NOT NULL DEFAULT '{}',
    is_live         BOOLEAN NOT NULL DEFAULT FALSE,
    risk_score      INTEGER,
    risk_band       TEXT,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX permutations_scan_job_id_idx ON permutations(scan_job_id);
CREATE INDEX permutations_live_idx ON permutations(scan_job_id) WHERE is_live = TRUE;
