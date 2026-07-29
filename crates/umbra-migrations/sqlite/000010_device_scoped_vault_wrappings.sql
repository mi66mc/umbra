ALTER TABLE devices ADD COLUMN encryption_public_key text;
CREATE INDEX vault_key_wrappings_device_generation_idx ON vault_key_wrappings(vault_id, user_id, device_id, key_generation) WHERE revoked_at IS NULL;
