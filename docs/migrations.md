# Umbra Migrations

Umbra separates migration types by trust boundary.

## Database Migrations

Database migrations run on the server and change database schema. PostgreSQL remains the production default; SQLite is supported for local development and small self-host installs that do not want a Postgres container.

- users
- user_auth
- devices
- vaults
- vault_members
- vault_key_wrappings
- items
- item_revisions
- audit_logs
- orgs
- org_members
- invites
- sessions

PostgreSQL migration path:

```txt
crates/umbra-migrations/migrations/000001_initial_schema.sql
```

SQLite migration path:

```txt
crates/umbra-migrations/sqlite/000001_initial_schema.sql
```

The schema stores encrypted envelopes and metadata only. It must not add columns for plaintext passwords, API keys, SSH keys, notes, card numbers, vault keys, or item plaintext.

The initial sync model uses:

```txt
vaults.vault_revision
items.current_revision
item_revisions.revision
item_revisions.vault_revision
```

`vault_revision` is incremented when an encrypted item revision is written. This supports "changes since vault revision N" sync without requiring a global server revision in the MVP.

PostgreSQL encrypted JSON is stored as `jsonb`:

```txt
users.encrypted_private_key
vaults.crypto_policy
vault_key_wrappings.envelope
item_revisions.envelope
audit_logs.metadata
```

SQLite stores UUIDs, timestamps, and JSON envelopes as text. The server chooses the correct migration runner from `database.backend`.

Production default:

```txt
auto_migrate = false
```

Self-host/dev may opt in:

```txt
auto_migrate = true
```

SQLite dev example:

```txt
UMBRA__DATABASE__BACKEND=sqlite
UMBRA__DATABASE__URL=sqlite://./umbra-dev.db?mode=rwc
UMBRA__MIGRATIONS__AUTO_MIGRATE=true
```

## Test Database

PostgreSQL integration tests use a separate database:

```txt
UMBRA_TEST_DATABASE_URL=postgres://umbra:umbra@localhost:5432/umbra_test
```

`docker compose up -d postgres` creates both `umbra` and `umbra_test` on a fresh volume. If the Postgres volume already existed before this setup, create `umbra_test` manually or recreate the volume.

## Crypto Migrations

Crypto migrations are client-side because they require plaintext keys or items:

- envelope v1 to v2
- KDF profile changes
- vault key rotation
- encryption suite changes
- AAD changes

## Encrypted Data Migrations

Plaintext item schema migrations are client-side:

```txt
download envelope
decrypt locally
migrate plaintext schema
encrypt new revision
upload new encrypted revision
```

## Protocol Migrations

Protocol migrations are handled with explicit `protocol_version` fields and versioned API routes.
