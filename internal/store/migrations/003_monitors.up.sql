CREATE TABLE monitored_domains (
    id                     UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    domain                 TEXT NOT NULL,
    owner_email            TEXT,
    alert_channels         JSONB NOT NULL DEFAULT '{}'::jsonb,
    check_interval_minutes INTEGER NOT NULL DEFAULT 1440,
    last_checked_at        TIMESTAMPTZ,
    last_scan_id           UUID REFERENCES scan_jobs(id) ON DELETE SET NULL,
    current_scan_id        UUID REFERENCES scan_jobs(id) ON DELETE SET NULL,
    created_at             TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX monitored_domains_last_checked_idx ON monitored_domains(last_checked_at);
CREATE INDEX monitored_domains_domain_idx ON monitored_domains(domain);

CREATE TABLE alerts (
    id                    UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    monitored_domain_id   UUID NOT NULL REFERENCES monitored_domains(id) ON DELETE CASCADE,
    permutation_domain    TEXT NOT NULL,
    risk_score            INTEGER NOT NULL,
    risk_band             TEXT NOT NULL,
    findings_summary      JSONB NOT NULL DEFAULT '{}'::jsonb,
    alert_created_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
    alert_sent_at         TIMESTAMPTZ
);

CREATE INDEX alerts_monitored_domain_id_idx ON alerts(monitored_domain_id, alert_created_at DESC);
