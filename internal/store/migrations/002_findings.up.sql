CREATE TABLE findings (
    id             UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    permutation_id UUID NOT NULL REFERENCES permutations(id) ON DELETE CASCADE,
    source_name    TEXT NOT NULL,
    risk_signals   JSONB NOT NULL DEFAULT '[]'::jsonb,
    raw_data       JSONB,
    fetched_at     TIMESTAMPTZ NOT NULL,
    error          TEXT,
    created_at     TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX findings_permutation_id_idx ON findings(permutation_id);
CREATE INDEX findings_source_name_idx ON findings(source_name);
