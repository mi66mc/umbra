ALTER TABLE devices
    ADD COLUMN state text;

UPDATE devices
SET state = CASE
    WHEN revoked_at IS NOT NULL THEN 'revoked'
    WHEN trusted IS TRUE THEN 'trusted'
    ELSE 'pending'
END;

ALTER TABLE devices
    ALTER COLUMN state SET NOT NULL,
    ALTER COLUMN state SET DEFAULT 'pending',
    ADD CONSTRAINT devices_state_check CHECK (state IN ('pending', 'trusted', 'revoked')),
    ADD COLUMN approval_code_hash text,
    ADD COLUMN approval_expires_at timestamptz,
    ADD COLUMN bootstrap_public_key text,
    ADD COLUMN bootstrap_bundle jsonb,
    ADD COLUMN trusted_at timestamptz;

UPDATE devices
SET trusted_at = created_at
WHERE state = 'trusted' AND trusted_at IS NULL;

CREATE INDEX devices_user_state_idx ON devices(user_id, state);
CREATE INDEX devices_approval_code_hash_idx ON devices(approval_code_hash)
    WHERE approval_code_hash IS NOT NULL;

CREATE TABLE device_recovery_challenges (
    id uuid PRIMARY KEY,
    user_id uuid NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    device_id uuid NOT NULL REFERENCES devices(id) ON DELETE CASCADE,
    challenge_hash text NOT NULL,
    expires_at timestamptz NOT NULL,
    consumed_at timestamptz,
    created_at timestamptz NOT NULL DEFAULT now()
);

CREATE INDEX device_recovery_challenges_device_idx
    ON device_recovery_challenges(device_id, expires_at)
    WHERE consumed_at IS NULL;
