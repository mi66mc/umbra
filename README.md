# Umbra

Umbra is a zero-knowledge, self-hosted, developer-first vault for passwords, SSH keys, API keys, project secrets, personal vaults, and shared team vaults.

The server stores users, devices, vault metadata, memberships, encrypted envelopes, wrapped vault keys, revisions, and audit events. It must never receive plaintext secrets, plaintext vault keys, master passwords, user secret keys, or decrypted items.

## Initial Direction

- Cargo workspace with separate CLI and server packages.
- `umbra-cli` publishes the `umbra` binary.
- `umbra-server` publishes the `umbra-server` binary.
- Vault keys are random per vault and wrapped for authorized users/devices.
- User passwords unlock encrypted user private keys, not vaults directly.
- Client-side crypto and client-side encrypted data migrations.
- Server-side PostgreSQL schema migrations.

## Development

```bash
docker compose up -d postgres
$env:UMBRA_TEST_DATABASE_URL="postgres://umbra:umbra@localhost:5432/umbra_test"
cargo test
cargo build
cargo run -p umbra-cli
cargo run -p umbra-server
```

Generate a persistent OPAQUE server setup secret before running a non-dev server:

```bash
cargo run -p umbra-server -- opaque setup generate
```

Set it as:

```txt
UMBRA__AUTH__OPAQUE__SERVER_SETUP=<generated-secret>
```

## Current CLI Happy Path

This stage supports a developer remote flow with OPAQUE login, signed HTTP sessions, client-side vault key wrapping, encrypted item upload, sync, and cached decrypt:

```bash
umbra register \
  --server http://127.0.0.1:8080 \
  --email miguel@example.com \
  --profile personal

umbra login --profile personal

umbra profile list
umbra profile use personal

umbra vault list

umbra vault create Personal

umbra secret set pulzar/dev DATABASE_URL "postgres://user:pass@localhost:5432/app" --vault Personal

umbra secret get pulzar/dev DATABASE_URL --vault Personal

umbra item create \
  --vault Personal \
  --kind login \
  --title GitHub \
  --field username=miguel \
  --field password=secret

umbra item list --vault Personal
umbra item get --vault Personal --item-id "$ITEM_ID"
```

The CLI encrypts item plaintext locally before upload. The server receives only JSON envelopes and key wrappings. The local SQLite cache stores encrypted envelopes and wrapped vault keys, not plaintext fields.

`vault create` stores the first created vault as the profile default. `--vault Personal` resolves a vault name from the local cache populated by `umbra vault list` or `umbra vault create`. If a name is ambiguous, pass `--vault-id`.

The CLI uses signed HTTP sessions by default after `umbra login`. Normal CLI requests do not send a reusable bearer token. The server still stores only encrypted envelopes. The `--envelope-json` item escape hatch remains available for low-level protocol testing.

Legacy bearer-token setup is still available for debugging:

```bash
umbra auth token set \
  --server-url http://127.0.0.1:8080 \
  --token "$UMBRA_SESSION_TOKEN"
```

## Local CLI Cache

The CLI stores a per-profile SQLite cache under the local Umbra data directory.

The cache contains encrypted envelopes, key wrappings, sync cursors, and metadata. It does not contain plaintext secrets or plaintext vault keys.

Useful commands:

```bash
umbra sync run --vault "$VAULT_ID"
umbra cache status
umbra item list --vault Personal
umbra item get --vault Personal --item-id "$ITEM_ID"
umbra item list --vault Personal --offline
umbra item get --vault Personal --item-id "$ITEM_ID" --offline
```

Online read commands call sync status first and only run full sync when item or access revisions changed. `--offline` reads only from the local encrypted-envelope cache and may be stale. `--cached` remains an alias for `--offline` on item reads for compatibility.

`sync run` uses the cached vault revision cursor by default. Use `--force-full` to request from revision `0`.
