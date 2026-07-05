ALTER TABLE items
ADD COLUMN deleted_vault_revision INTEGER;

CREATE INDEX items_deleted_vault_revision_idx
ON items(vault_id, deleted_vault_revision)
WHERE deleted_vault_revision IS NOT NULL;
