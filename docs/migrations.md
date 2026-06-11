# Umbra Migrations

Umbra separates migration types by trust boundary.

## Database Migrations

Database migrations run on the server and change PostgreSQL schema:

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

Production default:

```txt
auto_migrate = false
```

Self-host/dev may opt in:

```txt
auto_migrate = true
```

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
