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

## Remote CLI MVP

This stage supports a developer remote flow with a pre-existing session token:

```bash
umbra auth token set \
  --server-url http://127.0.0.1:8080 \
  --token "$UMBRA_SESSION_TOKEN"

umbra vault list

umbra vault create Personal \
  --wrapping-json '{"version":1,"type":"vault_key_wrapping","ciphertext":"example"}'

umbra item create \
  --vault-id "$VAULT_ID" \
  --kind api_key \
  --envelope-json '{"version":1,"suite":"UMBRA_XCHACHA20POLY1305_HKDFSHA256_V1","ciphertext":"example"}'

umbra sync run \
  --vault-id "$VAULT_ID" \
  --since-vault-revision 0
```

The server still stores only encrypted envelopes. Human-friendly `umbra auth login`, local unlock, vault key cache, and client-side item encryption are the next CLI layer.
