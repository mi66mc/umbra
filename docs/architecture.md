# Umbra Architecture

Umbra is a zero-knowledge, self-hosted vault. The server is an authorization, metadata, and synchronization service for encrypted envelopes. It must not receive plaintext secrets, plaintext vault keys, master passwords, user secret keys, or decrypted items.

## Product Shape

The first implementation targets:

- Remote mode only.
- CLI first.
- PostgreSQL-backed server.
- Separate Rust packages for CLI and server.
- JSON crypto envelopes initially.
- Shared vaults through per-recipient vault key wrappings.
- Organizations reserved in the model through nullable `org_id`, but not fully implemented in the MVP.

Local offline vaults, web UI, browser extension, desktop, mobile, SQLite, OPAQUE, WebAuthn, and HPKE are future work.

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
- New device: user enters password and imports/types the secret key once.
- After registration: the device may store the secret key locally, protected by OS keychain or encrypted local cache.

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

## Sync

The MVP uses revision tracking per vault:

```txt
vault_revision
item_revision
```

A global `server_revision` can be added later if multi-vault sync needs it. The model must allow conflict records later, even if early behavior is conservative.
