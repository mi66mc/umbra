ALTER TABLE vaults
    ADD COLUMN current_key_generation integer NOT NULL DEFAULT 1 CHECK (current_key_generation > 0);

ALTER TABLE vaults
    ADD COLUMN needs_key_rotation integer NOT NULL DEFAULT 0;

ALTER TABLE vault_key_wrappings
    ADD COLUMN key_generation integer NOT NULL DEFAULT 1 CHECK (key_generation > 0);

ALTER TABLE item_revisions
    ADD COLUMN key_generation integer NOT NULL DEFAULT 1 CHECK (key_generation > 0);

CREATE INDEX vault_key_wrappings_generation_idx
    ON vault_key_wrappings(vault_id, key_generation)
    WHERE revoked_at IS NULL;
