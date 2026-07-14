CREATE TABLE item_conflicts (
    id text PRIMARY KEY,
    vault_id text NOT NULL REFERENCES vaults(id) ON DELETE CASCADE,
    item_id text NOT NULL REFERENCES items(id) ON DELETE CASCADE,
    base_revision integer NOT NULL,
    current_revision integer NOT NULL,
    candidate_kind text NOT NULL CHECK (candidate_kind IN ('update', 'delete')),
    candidate_envelope text,
    author_user_id text REFERENCES users(id) ON DELETE SET NULL,
    state text NOT NULL DEFAULT 'open' CHECK (state IN ('open', 'resolved', 'discarded')),
    resolved_revision integer,
    created_at text NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now')),
    resolved_at text
);

CREATE INDEX item_conflicts_open_vault_item_idx
ON item_conflicts(vault_id, item_id)
WHERE state = 'open';
