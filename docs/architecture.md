# Umbra Architecture

Umbra is a zero-knowledge, self-hosted vault. The server is an authorization, metadata, and synchronization service for encrypted envelopes. It must not receive plaintext secrets, plaintext vault keys, master passwords, user secret keys, or decrypted items.

## Product Shape

The first implementation targets:

- Remote mode only.
- CLI first.
- PostgreSQL-backed server by default, with SQLite available for local development and lightweight self-host testing.
- Separate Rust packages for CLI and server.
- JSON crypto envelopes initially.
- Shared vaults through per-recipient vault key wrappings.
- Organizations for team grouping, with vault access still granted per vault.
- OPAQUE-based password authentication DTOs and initial server flow.

Local offline vaults, web UI, browser extension, desktop, mobile, WebAuthn, and HPKE are future work.

## Workspace

```txt
crates/
  umbra-core/        pure domain types and rules
  umbra-crypto/      client-side crypto primitives and envelopes
  umbra-protocol/    API and sync DTOs
  umbra-storage/     database access
  umbra-migrations/  SQL migrations and migration runner
  umbra-server/      HTTP server and admin commands
  umbra-cli/         user CLI, binary name `umbra`
```

## Server Database Backends

The server selects its database with:

```txt
database.backend = "postgres" | "sqlite"
database.url = "..."
```

PostgreSQL is the production default. SQLite uses the same storage trait and separate SQL migrations so developers can run `umbra-server` without starting a container:

```txt
UMBRA__DATABASE__BACKEND=sqlite
UMBRA__DATABASE__URL=sqlite://./umbra-dev.db?mode=rwc
```

The trust model is unchanged across backends: both store encrypted envelopes, key wrappings, metadata, sessions, and revisions only.

## Trust Boundary

Client-side:

- Derives keys from password and secret key.
- Decrypts the user private key.
- Decrypts vault keys.
- Encrypts and decrypts vault items.
- Runs crypto migrations.
- Runs encrypted plaintext data migrations.

Server-side:

- Stores users, devices, vault metadata, memberships, invites, sessions, encrypted key wrappings, encrypted item revisions, audit logs, and migration state.
- Enforces auth, roles, membership, sync visibility, rate limits, and admin policy.
- Never calls item decryption APIs.

## Key Hierarchy

```txt
master password + user secret key
        |
        v
account_kek
        |
        v
encrypted user private key
        |
        v
user private key
        |
        v
encrypted vault key wrapping
        |
        v
vault key
        |
        v
encrypted item envelopes
```

Vault keys are random 32-byte keys generated per vault. They are not derived from the user's password.

Each authorized user/device receives a wrapped copy of the vault key:

```txt
vault_key_for_miguel = encrypt(public_key_miguel, vault_key)
vault_key_for_ana    = encrypt(public_key_ana, vault_key)
```

Miguel opens his copy with his private key. Ana opens her copy with her private key. Their private keys are encrypted locally/server-side as envelopes that require `account_kek`, derived from password plus secret key.

## Secret Key UX

The user secret key is not a daily password. It is a high-entropy account secret generated on registration.

- Existing trusted device: user enters password; CLI reads the secret key from local secure storage/cache.
- New device with another trusted device available: user enters password, the device starts as pending, and a trusted device encrypts a bootstrap bundle for it.
- New device with no trusted device available: user enters password and uses an emergency-kit recovery flow. The clean-device import UX is future work; the protocol already supports challenge recovery when account crypto material is locally available.
- After registration or bootstrap: the device may store the secret key locally, protected by OS keychain or encrypted local cache.

## Device Trust

OPAQUE proves account-password knowledge. It does not make an unknown device trusted by itself.

Device states:

```txt
pending  -> authenticated with password, limited to bootstrap/recovery
trusted  -> allowed to receive signed sessions and use normal APIs
revoked  -> denied future server access
```

First registration creates a trusted device. Later devices use this flow:

```txt
1. new device runs OPAQUE login with --new-device
2. server creates devices.state = pending and returns an approval code
3. trusted device looks up the approval code
4. trusted device encrypts account bootstrap material to the pending device bootstrap public key
5. server marks the pending device trusted and stores the encrypted bootstrap bundle
6. pending device downloads and decrypts the bundle locally
```

The bootstrap bundle is zero-knowledge from the server perspective. It is encrypted client-side to the pending device's bootstrap public key and includes the account material needed for local decrypt operations.

Revoking a device stops future sync/API access and revokes that device's active sessions. It does not erase local cache or secrets already viewed on that device. Vault key rotation and real secret rotation are still required after suspected compromise.

## Sharing Flow

```txt
1. Admin/owner has the vault unlocked locally.
2. Admin invites another user.
3. Server creates or records a pending invite.
4. Client obtains the recipient public key.
5. Admin client encrypts the vault key for the recipient public key.
6. Server stores the recipient vault_key_wrapping.
7. Recipient downloads the wrapping and opens it with their private key.
```

An accepted invite without a key wrapping is not enough to decrypt a vault. Access becomes cryptographically usable only after a wrapping exists.

## Item Model

Vault items must support simple and complex secrets. The encrypted plaintext schema is client-owned and versioned. Initial item kinds include:

- login
- secure note
- SSH key
- API key
- token
- environment variable
- environment bundle
- credit card
- custom

The server stores the item kind and encrypted envelope, but not plaintext fields.

## Organizations And Vault Access

Organizations are explicit team/workspace containers. A user does not need an organization for personal use.

```txt
solo user vault:
  vault.org_id = null

team vault:
  vault.org_id = org_id
```

Organization membership controls who can manage the organization and create organization vaults. It does not decrypt vaults and does not automatically grant access to every vault in the organization.

Vault access requires all of:

- active `vault_members` row;
- role that permits the requested server action;
- usable `vault_key_wrapping` for the user/device key generation.

This split matters because the server can authorize sync, but only the client can unwrap the vault key.

## Removing Members And Rotation

Removing a vault member is a server-side authorization change first:

```txt
1. mark vault_members.state = removed
2. revoke active vault_key_wrappings for that user
3. set vaults.needs_key_rotation = true
```

That stops future sync and future key unwraps, but it cannot erase secrets the removed user already saw. Strong cryptographic removal requires an owner/admin client to rotate the vault key:

```txt
1. owner/admin unlocks the old vault key locally
2. client generates a new random vault key
3. client re-encrypts current item revisions
4. client creates new wrappings for remaining active members
5. server stores the new generation and clears needs_key_rotation
```

## Sync

The MVP uses revision tracking per vault:

```txt
vault_revision
item_revision
```

A global `server_revision` can be added later if multi-vault sync needs it. The model must allow conflict records later, even if early behavior is conservative.
