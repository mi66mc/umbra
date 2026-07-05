ALTER TABLE items
ADD COLUMN deleted_vault_revision bigint;

ALTER TABLE items
ADD CONSTRAINT items_deleted_vault_revision_positive
CHECK (deleted_vault_revision IS NULL OR deleted_vault_revision > 0);

CREATE INDEX items_deleted_vault_revision_idx
ON items(vault_id, deleted_vault_revision)
WHERE deleted_vault_revision IS NOT NULL;
