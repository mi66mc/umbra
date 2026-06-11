CREATE TABLE users (
    id uuid PRIMARY KEY,
    email text UNIQUE NOT NULL,
    display_name text,
    public_key text NOT NULL,
    encrypted_private_key jsonb NOT NULL,
    created_at timestamptz NOT NULL DEFAULT now(),
    updated_at timestamptz NOT NULL DEFAULT now(),
    disabled_at timestamptz
);

CREATE TABLE user_auth (
    user_id uuid PRIMARY KEY REFERENCES users(id) ON DELETE CASCADE,
    auth_method text NOT NULL,
    auth_data jsonb NOT NULL,
    created_at timestamptz NOT NULL DEFAULT now(),
    updated_at timestamptz NOT NULL DEFAULT now()
);

CREATE TABLE devices (
    id uuid PRIMARY KEY,
    user_id uuid NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    name text NOT NULL,
    public_key text,
    fingerprint text NOT NULL,
    trusted boolean NOT NULL DEFAULT false,
    created_at timestamptz NOT NULL DEFAULT now(),
    last_seen_at timestamptz,
    revoked_at timestamptz
);

CREATE INDEX devices_user_id_idx ON devices(user_id);
CREATE UNIQUE INDEX devices_user_fingerprint_active_idx
    ON devices(user_id, fingerprint)
    WHERE revoked_at IS NULL;

CREATE TABLE orgs (
    id uuid PRIMARY KEY,
    name text NOT NULL,
    created_by uuid REFERENCES users(id) ON DELETE SET NULL,
    created_at timestamptz NOT NULL DEFAULT now(),
    updated_at timestamptz NOT NULL DEFAULT now(),
    deleted_at timestamptz
);

CREATE TABLE org_members (
    org_id uuid NOT NULL REFERENCES orgs(id) ON DELETE CASCADE,
    user_id uuid NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    role text NOT NULL CHECK (role IN ('owner', 'admin', 'member')),
    state text NOT NULL CHECK (state IN ('active', 'invited', 'removed')),
    created_at timestamptz NOT NULL DEFAULT now(),
    updated_at timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (org_id, user_id)
);

CREATE TABLE vaults (
    id uuid PRIMARY KEY,
    org_id uuid REFERENCES orgs(id) ON DELETE SET NULL,
    name text NOT NULL,
    kind text NOT NULL CHECK (kind IN ('personal', 'shared', 'project', 'org')),
    vault_revision bigint NOT NULL DEFAULT 0 CHECK (vault_revision >= 0),
    created_by uuid REFERENCES users(id) ON DELETE SET NULL,
    created_at timestamptz NOT NULL DEFAULT now(),
    updated_at timestamptz NOT NULL DEFAULT now(),
    deleted_at timestamptz,
    crypto_policy jsonb NOT NULL DEFAULT '{}'::jsonb
);

CREATE INDEX vaults_org_id_idx ON vaults(org_id);
CREATE INDEX vaults_created_by_idx ON vaults(created_by);

CREATE TABLE vault_members (
    vault_id uuid NOT NULL REFERENCES vaults(id) ON DELETE CASCADE,
    user_id uuid NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    role text NOT NULL CHECK (role IN ('owner', 'admin', 'editor', 'viewer')),
    state text NOT NULL CHECK (state IN ('active', 'invited', 'removed')),
    created_at timestamptz NOT NULL DEFAULT now(),
    updated_at timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (vault_id, user_id)
);

CREATE INDEX vault_members_user_id_idx ON vault_members(user_id);

CREATE TABLE vault_key_wrappings (
    id uuid PRIMARY KEY,
    vault_id uuid NOT NULL REFERENCES vaults(id) ON DELETE CASCADE,
    user_id uuid NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    device_id uuid REFERENCES devices(id) ON DELETE SET NULL,
    wrapping_type text NOT NULL CHECK (wrapping_type IN ('user_public_key', 'password_kek', 'device_public_key', 'recovery_key', 'organization_key', 'future_hpke')),
    envelope jsonb NOT NULL,
    created_at timestamptz NOT NULL DEFAULT now(),
    rotated_at timestamptz,
    revoked_at timestamptz
);

CREATE INDEX vault_key_wrappings_vault_user_idx ON vault_key_wrappings(vault_id, user_id);
CREATE INDEX vault_key_wrappings_device_id_idx ON vault_key_wrappings(device_id);

CREATE TABLE items (
    id uuid PRIMARY KEY,
    vault_id uuid NOT NULL REFERENCES vaults(id) ON DELETE CASCADE,
    kind text NOT NULL CHECK (kind IN ('login', 'secure_note', 'ssh_key', 'api_key', 'token', 'env_var', 'env_bundle', 'credit_card', 'custom')),
    current_revision bigint NOT NULL CHECK (current_revision >= 0),
    created_by uuid REFERENCES users(id) ON DELETE SET NULL,
    created_at timestamptz NOT NULL DEFAULT now(),
    updated_at timestamptz NOT NULL DEFAULT now(),
    deleted_at timestamptz
);

CREATE INDEX items_vault_id_idx ON items(vault_id);

CREATE TABLE item_revisions (
    id uuid PRIMARY KEY,
    item_id uuid NOT NULL REFERENCES items(id) ON DELETE CASCADE,
    vault_id uuid NOT NULL REFERENCES vaults(id) ON DELETE CASCADE,
    revision bigint NOT NULL CHECK (revision > 0),
    vault_revision bigint NOT NULL CHECK (vault_revision > 0),
    author_user_id uuid REFERENCES users(id) ON DELETE SET NULL,
    envelope jsonb NOT NULL,
    created_at timestamptz NOT NULL DEFAULT now(),
    UNIQUE (item_id, revision)
);

CREATE INDEX item_revisions_vault_revision_idx ON item_revisions(vault_id, vault_revision);

CREATE TABLE audit_logs (
    id uuid PRIMARY KEY,
    actor_user_id uuid REFERENCES users(id) ON DELETE SET NULL,
    vault_id uuid REFERENCES vaults(id) ON DELETE SET NULL,
    action text NOT NULL,
    target_type text,
    target_id uuid,
    metadata jsonb NOT NULL DEFAULT '{}'::jsonb,
    created_at timestamptz NOT NULL DEFAULT now()
);

CREATE INDEX audit_logs_vault_id_created_at_idx ON audit_logs(vault_id, created_at);

CREATE TABLE invites (
    id uuid PRIMARY KEY,
    vault_id uuid REFERENCES vaults(id) ON DELETE CASCADE,
    org_id uuid REFERENCES orgs(id) ON DELETE CASCADE,
    email text NOT NULL,
    role text NOT NULL,
    state text NOT NULL CHECK (state IN ('pending', 'accepted', 'rejected', 'revoked', 'expired')),
    invited_by uuid REFERENCES users(id) ON DELETE SET NULL,
    created_at timestamptz NOT NULL DEFAULT now(),
    accepted_at timestamptz,
    expires_at timestamptz
);

CREATE INDEX invites_email_idx ON invites(email);
CREATE INDEX invites_vault_id_idx ON invites(vault_id);

CREATE TABLE sessions (
    id uuid PRIMARY KEY,
    user_id uuid NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    device_id uuid REFERENCES devices(id) ON DELETE SET NULL,
    token_hash text NOT NULL UNIQUE,
    created_at timestamptz NOT NULL DEFAULT now(),
    expires_at timestamptz NOT NULL,
    revoked_at timestamptz
);

CREATE INDEX sessions_user_id_idx ON sessions(user_id);
