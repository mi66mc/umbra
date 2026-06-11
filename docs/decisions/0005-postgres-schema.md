# 0005: Initial PostgreSQL Schema

## Decision

Use PostgreSQL as the only server database for the MVP and manage schema through SQLx migrations embedded in `umbra-migrations`.

The initial schema includes users, auth metadata, devices, org placeholders, vaults, memberships, vault key wrappings, encrypted item revisions, audit logs, invites, and sessions.

## Consequences

- Server storage is ready for multi-user, multi-device, multi-vault, shared vaults, and encrypted sync.
- Envelopes and policies are stored as `jsonb`; plaintext secrets are not modeled in database columns.
- Sync starts with `vault_revision` rather than a global server revision.
- SQLite/local vault remains outside the MVP server storage path.
