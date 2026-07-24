CREATE TABLE sync_checkpoints (
    checkpoint_hash text PRIMARY KEY,
    vault_id text NOT NULL REFERENCES vaults(id) ON DELETE CASCADE,
    vault_revision integer NOT NULL,
    state_commitment text NOT NULL,
    previous_checkpoint_hash text,
    author_device_id text NOT NULL REFERENCES devices(id) ON DELETE RESTRICT,
    signature text NOT NULL,
    created_at text NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now')),
    UNIQUE (vault_id, vault_revision, checkpoint_hash),
    UNIQUE (vault_id, vault_revision)
);

CREATE INDEX sync_checkpoints_vault_revision_idx
ON sync_checkpoints(vault_id, vault_revision ASC);
