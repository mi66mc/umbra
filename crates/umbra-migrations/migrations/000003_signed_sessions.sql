ALTER TABLE sessions
    ADD COLUMN auth_scheme text NOT NULL DEFAULT 'bearer'
        CHECK (auth_scheme IN ('bearer', 'signed'));

CREATE TABLE session_nonces (
    session_id uuid NOT NULL REFERENCES sessions(id) ON DELETE CASCADE,
    nonce text NOT NULL,
    created_at timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (session_id, nonce)
);

CREATE INDEX session_nonces_created_at_idx ON session_nonces(created_at);
