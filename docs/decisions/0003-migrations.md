# 0003: Migration Boundaries

## Decision

Use a separate `umbra-migrations` crate for database migrations and keep crypto/data migrations client-side.

## Consequences

- Server owns PostgreSQL schema migrations.
- Client owns anything requiring decrypted keys or plaintext items.
- Production defaults to no automatic migrations unless explicitly enabled.
