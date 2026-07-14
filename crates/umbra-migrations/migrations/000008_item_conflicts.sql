CREATE TABLE item_conflicts (
    id uuid PRIMARY KEY,
    vault_id uuid NOT NULL REFERENCES vaults(id) ON DELETE CASCADE,
    item_id uuid NOT NULL REFERENCES items(id) ON DELETE CASCADE,
    base_revision bigint NOT NULL,
    current_revision bigint NOT NULL,
    candidate_kind text NOT NULL CHECK (candidate_kind IN ('update', 'delete')),
    candidate_envelope jsonb,
    author_user_id uuid REFERENCES users(id) ON DELETE SET NULL,
    state text NOT NULL DEFAULT 'open' CHECK (state IN ('open', 'resolved', 'discarded')),
    resolved_revision bigint,
    created_at timestamptz NOT NULL DEFAULT now(),
    resolved_at timestamptz
);

CREATE INDEX item_conflicts_open_vault_item_idx
ON item_conflicts(vault_id, item_id)
WHERE state = 'open';
