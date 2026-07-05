ALTER TABLE invites
ADD COLUMN vault_key_wrapping jsonb;

ALTER TABLE invites
ADD COLUMN accepted_user_id uuid REFERENCES users(id) ON DELETE SET NULL;

UPDATE invites
SET state = 'expired',
    expires_at = COALESCE(expires_at, now())
WHERE state = 'pending'
  AND vault_key_wrapping IS NULL;

ALTER TABLE invites
ADD CONSTRAINT invites_vault_key_wrapping_required_for_pending
CHECK (state <> 'pending' OR vault_key_wrapping IS NOT NULL);

CREATE UNIQUE INDEX invites_pending_vault_email_idx
ON invites(vault_id, lower(email))
WHERE state = 'pending';
