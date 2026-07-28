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
- Server-side schema migrations for PostgreSQL and SQLite.

## Development

Fast local server without Postgres:

```bash
$env:UMBRA__DATABASE__BACKEND="sqlite"
$env:UMBRA__DATABASE__URL="sqlite://./umbra-dev.db?mode=rwc"
$env:UMBRA__MIGRATIONS__AUTO_MIGRATE="true"
$env:UMBRA__AUTH__OPAQUE__ALLOW_EPHEMERAL_SETUP="true"
cargo run -p umbra-server -- serve
```

PostgreSQL development and integration tests:

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

## Production Operations

Run the production gate before deployment or after restoring a backup:

```bash
umbra-server doctor --strict
umbra-server migrate status
```

`doctor --json` is suitable for deployment automation. Strict mode rejects ephemeral or missing OPAQUE setup, automatic migrations, stale-migration bypasses, missing/insecure public URLs, and public binds without an HTTPS public URL. For a reverse proxy, configure only proxy networks you operate with `server.trusted_proxy_cidrs`; forwarded client IP headers are ignored for all other peers.

Rate limits are local to each server instance: registration is limited per client IP per hour, OPAQUE authentication per client IP per minute, and authenticated traffic per device per minute. A restart resets these counters; multi-instance deployments need a shared limiter in front of Umbra.

Back up PostgreSQL with `pg_dump` and validate restores into a separate database with `pg_restore`. For SQLite, stop Umbra before copying the database or use SQLite's consistent backup facility. Backups contain encrypted envelopes and operational metadata, never decrypted vault items or vault keys. After a restore, run migration status, `doctor --strict`, and `/health` plus `/ready`.

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
umbra env get pulzar/dev --vault Personal
umbra env inject pulzar/dev --vault Personal --output .env --yes
umbra run pulzar/dev --vault Personal -- cargo run

umbra item create \
  --vault Personal \
  --kind login \
  --title GitHub \
  --field username=miguel \
  --field password=secret

umbra item list --vault Personal
umbra item get --vault Personal --title GitHub
umbra item get --vault Personal
umbra item delete --vault Personal --title GitHub
umbra item delete --vault-id <vault-id> --item-id <item-id> --yes

umbra sync run --vault Personal
umbra status
umbra lock
```

Commands print human-readable output by default. Pass `--json` for scriptable output:

```bash
umbra --json vault list
umbra --json item get --vault Personal --title GitHub
```

Interactive selection only runs in human output mode. Omit `--vault` when you want the CLI to prompt from cached vaults, omit `--title`/`--item-id` from `item get` or `item delete` to choose an item, and omit the key from `secret get` or `secret rm` to choose a field. Commands run with `--json` require explicit selectors and never open prompts.

The CLI encrypts item plaintext locally before upload. The server receives only JSON envelopes and key wrappings. The local SQLite cache stores encrypted envelopes and wrapped vault keys, not plaintext fields.

`env get` prints a deterministic dotenv view of an encrypted `secret` bundle. `env inject` writes that dotenv output to a file and refuses to overwrite an existing file unless `--yes` is passed; on Unix, new and replacement files are created with owner-only permissions. `umbra run <project/env> -- <command>` decrypts the bundle locally and passes the variables only to the direct child process environment; it does not invoke a shell or write plaintext to the local cache.

Deleting an item is a metadata operation on the server. The server marks the encrypted item as deleted, increments the vault revision, and future sync responses include the deleted item id so clients remove it from local encrypted cache.

### Conflicts de sincronização

Uma edição offline nunca substitui silenciosamente uma revisão mais nova. Quando uma atualização ou exclusão usa uma revisão-base divergente, o servidor preserva a tentativa como uma candidata de conflito e responde `409`. Candidatas e sincronização contêm somente envelopes cifrados e metadata de revisão; a comparação e qualquer merge acontecem no cliente com a vault desbloqueada.

Enquanto houver conflito aberto, resolva-o explicitamente. Não há last-write-wins nem merge automático:

```powershell
umbra conflict list --vault Personal
umbra conflict show <conflict-id> --vault Personal
umbra conflict resolve <conflict-id> --use remote --vault Personal
umbra conflict resolve <conflict-id> --use local --vault Personal
umbra conflict resolve <conflict-id> --merge-from remote --field username=alice --notes "revisado" --vault Personal
```

`show` desbloqueia a vault e apresenta as versões remota e candidata; `list` não mostra plaintext. Para conflitos de exclusão, as únicas escolhas são manter a versão remota ou confirmar a exclusão local. A resolução fecha todas as candidatas abertas daquele item.

`vault create` stores the first created vault as the profile default. `--vault Personal` resolves a vault name from the local cache populated by `umbra vault list` or `umbra vault create`. If a name is ambiguous, pass `--vault-id`.

`umbra unlock` decrypts the account private key once, unwraps selected vault keys from the local encrypted-envelope cache with the profile's device encryption private key, and writes an encrypted local unlock state. The random key for that unlock state is stored in the OS keychain. `umbra lock` removes both the keychain entry and the encrypted unlock state file.

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

### Device-scoped vault envelopes (protocol v3)

Protocol v3 introduces a distinct X25519 encryption keypair for each device. The private half is generated and retained only in that device profile; the server stores the public half as non-secret device metadata. A newly created vault stores its initial `device_public_key` wrapping for the authenticated device, and protocol-v3 sync returns only wrappings addressed to the authenticated trusted device. The wrapping AAD binds the vault ID, recipient device ID, and key generation, so an envelope copied between devices or generations cannot be used to unlock a vault.

This migration is deliberately fail-closed for unlock and cache selection: a client must find a `device_public_key` wrapping for its own device and generation. It does not fall back to the account private key or to a legacy user-scoped wrapping. A legacy vault therefore requires distribution of a device-scoped envelope by a trusted device before a newly enrolled device can unlock it.

The server remains zero-knowledge: it authorizes device state and membership and persists opaque JSON envelopes, but never decrypts, rewraps, logs, or audits vault keys, device private keys, or raw envelope bodies. The server-side filtering cannot erase material a revoked device already downloaded or decrypted. Revoke a lost/compromised device immediately, then rotate every affected vault key and the real secrets that device may have seen.

The v3 rollout is incomplete for multi-recipient operations: approval distribution, invite acceptance/member grants, and rotation must all create one envelope for every intended active device. Until those routes are migrated and verified, do not treat a newly approved device, an invited member, or a rotated shared vault as covered by the v3 device-envelope guarantee. See [operations guidance](docs/operations.md) and [the verification matrix](docs/device-scoped-vault-wrapping-tests.md).

Useful device commands:

```bash
umbra device list
umbra device pending
umbra device revoke <device-id>
umbra emergency-kit export --output umbra-emergency-kit.json
umbra device recover --emergency-kit umbra-emergency-kit.json
```

`emergency-kit export` must be run from an already trusted profile. The kit contains the account public key, KDF params, and user secret key. It does not contain the master password, plaintext user private key, vault keys, item plaintext, or session tokens.

Clean-machine recovery when no trusted device is available:

```bash
umbra login --profile recovered --email miguel@example.com --new-device --device-name "Recovered laptop"
umbra device recover --emergency-kit umbra-emergency-kit.json
umbra login --profile recovered
```

The first login creates a pending device and stores the encrypted user private key envelope returned by the server. `device recover` combines that envelope with the emergency kit and master password locally, answers the server recovery challenge, clears the pending bearer/session, and requires a normal login after trust succeeds. Anyone with both the emergency kit and master password can recover the account, so store the kit offline.

Revoking a device stops future server access and active sessions for that device. It does not erase secrets already viewed or cached on that machine; rotate affected vault keys and real third-party secrets after device loss or compromise.

## Organizations And Shared Vaults

Personal vaults do not need an organization. Use an organization when a team needs shared ownership and org-scoped vaults.

```bash
umbra org create BlackWire
umbra org list
umbra org add-member <org-id> --email ana@example.com --role admin
umbra org members <org-id>

umbra vault create Platform --org-id <org-id>
umbra vault invite --vault Platform --email ana@example.com --role editor
umbra vault members --vault Platform

umbra invite list
umbra invite accept <invite-id>
```

Current invite and direct-member flows use account-public-key wrappings. They remain legacy paths during the device-envelope migration and must not be relied on to provision a new device under protocol v3. The completed migration will have the inviting client create one opaque wrapping for each trusted device of the recipient; the server will authorize and store the records without receiving a vault key in plaintext.

Removing a vault member stops future sync for that user and revokes their active wrapping, but it does not erase secrets already seen. Rotate the vault key and real third-party secrets after sensitive removals.

## Vault Key Rotation

Removing a vault member blocks future sync and marks the vault as needing key rotation. Rotation is a client-side crypto operation:

```bash
umbra crypto rotation-status --vault Platform
umbra crypto rotate-vault-key --vault Platform --dry-run
umbra crypto rotate-vault-key --vault Platform --yes
```

The CLI downloads the latest encrypted item revisions, unlocks the current vault key locally, generates a fresh vault key, reencrypts each latest item revision, and uploads only encrypted envelopes to the server. Legacy rotation wraps to active member account public keys. The device-scoped rollout must replace this with exactly one wrapping per active recipient device; until then, rotate after revocation/removal as a defense-in-depth response but do not claim that rotation has excluded every previously provisioned device under v3.

After removing a member, also rotate any real external credential the removed member may have seen, such as GitHub tokens, API keys, SSH keys, or database passwords. Vault key rotation prevents future Umbra sync access; it cannot erase knowledge already copied.

Legacy bearer-token setup is still available for debugging:

```bash
umbra auth token set \
  --server-url http://127.0.0.1:8080 \
  --token "$UMBRA_SESSION_TOKEN"
```

## Local CLI Cache

The CLI keeps a per-profile SQLite cache in memory and persists it under the local Umbra data directory as an authenticated encrypted `cache.enc` snapshot.

The cache contains encrypted envelopes, key wrappings, sync cursors, and metadata. It does not contain plaintext secrets, plaintext vault keys, or readable operational metadata at rest. Its random cache key is stored only in the OS keychain for that profile.

If the OS keychain entry is unavailable, the encrypted file is corrupt, or authentication fails, Umbra refuses to open the cache and keeps it for recovery; it never silently replaces it with an empty cache. A pre-encryption `cache.db` is likewise preserved and refused: back it up offline, remove it intentionally, then sync again. The server remains authoritative, so this recovery discards only the local acceleration/offline copy. Use `umbra cache clear` to intentionally remove `cache.enc` and its keychain key before re-syncing.

Snapshot updates use an interprocess lock and reject a command that opened an older snapshot while another command committed first. Re-run the rejected command; Umbra never lets that stale process overwrite newer local integrity state.

Normal online read/write commands first try the local unlock state. If the selected vault key is not unlocked, the CLI falls back to the master-password prompt and unwraps the vault key from the cached wrapping.

Useful commands:

```bash
umbra sync run --vault Personal
umbra cache status
umbra item list --vault Personal
umbra item get --vault Personal --title GitHub
umbra item get --vault Personal
umbra item delete --vault Personal --title GitHub
umbra item list --vault Personal --offline
umbra item get --vault Personal --title GitHub --offline
umbra secret get pulzar/dev --vault Personal
```

Online read commands call sync status first and only run full sync when item or access revisions changed. `--offline` reads only from the local encrypted-envelope cache and may be stale. `--cached` remains an alias for `--offline` on item reads for compatibility.

`sync run` uses the cached vault revision cursor by default. Use `--force-full` to request from revision `0`.

## Sync integrity checkpoints (protocol v2)

Protocol v2 adds signed, append-only sync checkpoints. A checkpoint binds a vault revision to a deterministic SHA-256 commitment of the encrypted item/conflict state and to the prior checkpoint hash. It contains identifiers, revisions, deletion/conflict state, key-generation metadata, ciphertext-envelope hashes, the author device ID, and an Ed25519 signature. It never contains plaintext, vault keys, passwords, private keys, raw envelopes, or key wrappings.

Version 1 remains compatible: v1 requests and responses neither request nor contain checkpoints. A client must explicitly negotiate `protocol_version: 2` before it creates, receives, or validates them.

The server is an opaque relay and store for checkpoint metadata. Only an authenticated, trusted device with vault write permission may author a checkpoint; the request signature binds its device ID. The server does not hold checkpoint signing keys and is not a trust authority for checkpoint signatures.

Each client persists its own trusted checkpoint-device public keys and its last verified checkpoint. Never treat a device key returned by the server as a new trust anchor. Transfer trust anchors through an authenticated local/device-to-device procedure when bootstrapping a new client; a valid signature from an unknown device is not sufficient.

If the client observes rollback, a missing or broken predecessor, non-monotonic revision, invalid signature, untrusted/revoked signer, commitment mismatch, or two different checkpoint hashes for one vault revision, it records the evidence and quarantines that vault. Normal sync and status then refuse to accept more state, including with `--force-full`. Umbra does not silently reset the cursor, discard evidence, or auto-recover this condition.

Inspect a quarantined vault without exposing vault contents:

```powershell
umbra sync integrity status --vault Personal
umbra sync integrity export --vault Personal --output integrity-evidence.json
```

The export contains only signed checkpoint metadata and integrity findings (IDs, revisions, hashes, device IDs/public-key fingerprints, signatures, and error codes). It deliberately excludes plaintext, ciphertext or raw envelopes, wrappings, vault keys, passwords, tokens, and private keys. Preserve this file and compare it with another trusted device or incident-response record before deciding on recovery.
