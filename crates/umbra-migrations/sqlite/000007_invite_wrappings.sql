ALTER TABLE invites
ADD COLUMN vault_key_wrapping text;

ALTER TABLE invites
ADD COLUMN accepted_user_id text REFERENCES users(id) ON DELETE SET NULL;

CREATE UNIQUE INDEX invites_pending_vault_email_idx
ON invites(vault_id, lower(email))
WHERE state = 'pending';
