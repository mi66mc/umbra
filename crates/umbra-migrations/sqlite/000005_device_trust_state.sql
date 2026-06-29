ALTER TABLE devices
    ADD COLUMN state text;

UPDATE devices
SET state = CASE
    WHEN revoked_at IS NOT NULL THEN 'revoked'
    WHEN trusted = 1 THEN 'trusted'
    ELSE 'pending'
END;

ALTER TABLE devices
    ADD COLUMN approval_code_hash text;

ALTER TABLE devices
    ADD COLUMN approval_expires_at text;

ALTER TABLE devices
    ADD COLUMN bootstrap_public_key text;

ALTER TABLE devices
    ADD COLUMN bootstrap_bundle text;

ALTER TABLE devices
    ADD COLUMN trusted_at text;

UPDATE devices
SET trusted_at = created_at
WHERE state = 'trusted' AND trusted_at IS NULL;

CREATE INDEX devices_user_state_idx ON devices(user_id, state);
CREATE INDEX devices_approval_code_hash_idx ON devices(approval_code_hash)
    WHERE approval_code_hash IS NOT NULL;

CREATE TABLE device_recovery_challenges (
    id text PRIMARY KEY,
    user_id text NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    device_id text NOT NULL REFERENCES devices(id) ON DELETE CASCADE,
    challenge_hash text NOT NULL,
    expires_at text NOT NULL,
    consumed_at text,
    created_at text NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX device_recovery_challenges_device_idx
    ON device_recovery_challenges(device_id, expires_at)
    WHERE consumed_at IS NULL;
