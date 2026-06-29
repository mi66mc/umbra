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

umbra vault create Personal
umbra vault list

umbra unlock --vault Personal --ttl-minutes 30

umbra secret set pulzar/dev DATABASE_URL "postgres://user:pass@localhost:5432/app" --vault Personal
umbra secret list pulzar/dev --vault Personal
umbra secret get pulzar/dev DATABASE_URL --vault Personal
umbra secret get pulzar/dev --vault Personal

umbra item create \
  --vault Personal \
  --kind login \
  --title GitHub \
  --field username=miguel \
  --field password=secret

umbra item list --vault Personal
umbra item get --vault Personal --title GitHub
umbra item get --vault Personal

umbra sync run --vault Personal
umbra status
umbra lock
```

Commands print human-readable output by default. Pass `--json` for scriptable output:

```bash
umbra --json vault list
umbra --json item get --vault Personal --title GitHub
```

Interactive selection only runs in human output mode. Omit `--vault` when you want the CLI to prompt from cached vaults, omit `--title`/`--item-id` from `item get` to choose an item, and omit the key from `secret get` or `secret rm` to choose a field. Commands run with `--json` require explicit selectors and never open prompts.

The CLI encrypts item plaintext locally before upload. The server receives only JSON envelopes and key wrappings. The local SQLite cache stores encrypted envelopes and wrapped vault keys, not plaintext fields.

`vault create` stores the first created vault as the profile default. `--vault Personal` resolves a vault name from the local cache populated by `umbra vault list` or `umbra vault create`. If a name is ambiguous, pass `--vault-id`.

`umbra unlock` decrypts the account private key once, unwraps selected vault keys from the local encrypted-envelope cache, and writes an encrypted local unlock state. The random key for that unlock state is stored in the OS keychain. `umbra lock` removes both the keychain entry and the encrypted unlock state file.

The CLI uses signed HTTP sessions by default after `umbra login`. Normal CLI requests do not send a reusable bearer token. The server still stores only encrypted envelopes. The `--envelope-json` item escape hatch remains available for low-level protocol testing.

## Multi-Device Flow

The first device created by `umbra register` is trusted. A later device can prove the account password with OPAQUE, but it starts as pending until an existing trusted device approves it.

On the new device:

```bash
umbra login --profile laptop-2 --new-device --device-name "Laptop 2"
```

The CLI prints an approval code. On an existing trusted device:

```bash
umbra device pending
umbra device approve UMBRA-ABCD-1234
```

Then, back on the new device:

```bash
umbra device bootstrap
umbra login --profile laptop-2
```

`device approve` encrypts a bootstrap bundle locally for the pending device. The server stores that encrypted bundle but cannot decrypt the user secret key, account private key, vault keys, or item data.

Useful device commands:

```bash
umbra device list
umbra device pending
umbra device revoke <device-id>
umbra device recover
```

`device recover` uses the protocol recovery challenge, but the current CLI expects the profile to already have enough local account crypto material to decrypt the challenge. A clean-machine emergency-kit import command is planned separately.

Revoking a device stops future server access and active sessions for that device. It does not erase secrets already viewed or cached on that machine; rotate affected vault keys and real third-party secrets after device loss or compromise.

Legacy bearer-token setup is still available for debugging:

```bash
umbra auth token set \
  --server-url http://127.0.0.1:8080 \
  --token "$UMBRA_SESSION_TOKEN"
```

## Local CLI Cache

The CLI stores a per-profile SQLite cache under the local Umbra data directory.

The cache contains encrypted envelopes, key wrappings, sync cursors, and metadata. It does not contain plaintext secrets or plaintext vault keys.

Normal online read/write commands first try the local unlock state. If the selected vault key is not unlocked, the CLI falls back to the master-password prompt and unwraps the vault key from the cached wrapping.

Useful commands:

```bash
umbra sync run --vault Personal
umbra cache status
umbra item list --vault Personal
umbra item get --vault Personal --title GitHub
umbra item get --vault Personal
umbra item list --vault Personal --offline
umbra item get --vault Personal --title GitHub --offline
umbra secret get pulzar/dev --vault Personal
```

Online read commands call sync status first and only run full sync when item or access revisions changed. `--offline` reads only from the local encrypted-envelope cache and may be stale. `--cached` remains an alias for `--offline` on item reads for compatibility.

`sync run` uses the cached vault revision cursor by default. Use `--force-full` to request from revision `0`.
