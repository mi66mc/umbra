ALTER TABLE invites
ADD COLUMN vault_key_wrapping text;

ALTER TABLE invites
ADD COLUMN accepted_user_id text REFERENCES users(id) ON DELETE SET NULL;

UPDATE invites
SET state = 'expired',
    expires_at = COALESCE(expires_at, strftime('%Y-%m-%dT%H:%M:%fZ', 'now'))
WHERE state = 'pending'
  AND vault_key_wrapping IS NULL;

CREATE UNIQUE INDEX invites_pending_vault_email_idx
ON invites(vault_id, lower(email))
WHERE state = 'pending';
