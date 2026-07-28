# Umbra Threat Model

## Protects Against

- Database leak.
- Stolen backups.
- Curious server administrator.
- Server attempting to read secrets.
- SQL dump with encrypted envelopes.
- Ciphertext tampering.
- Basic replay of stale item revisions.
- Lost device when the local vault is locked.

## Does Not Fully Protect Against

- Compromised client device.
- Keyloggers.
- Malware reading process memory.
- Malicious web frontend served by a compromised server.
- User copying a secret elsewhere.
- Removed member who already saw a secret.
- Supply chain compromise.

## Mitigations

- CLI-first sensitive operations.
- Device fingerprints.
- User keypairs.
- Secret key required for new devices.
- Local encrypted cache.
- Audit log without secrets.
- Vault key rotation after member removal.
- KDF policy and calibration.
- OPAQUE server setup secret kept outside PostgreSQL.
- OPAQUE for password authentication.
- Future WebAuthn/passkeys.
- Future signed builds.

## Sync rollback and equivocation

Protocol v2 signed checkpoints help a client detect a server that returns an older vault revision, omits a required checkpoint, alters encrypted-state metadata, or shows different checkpoint histories at the same revision. The server remains zero-knowledge: it stores and transports signed public metadata and hashes, not signing keys, plaintext, vault keys, or raw encrypted envelopes.

Detection is client-local. Each client keeps trusted checkpoint-device public keys and a verified checkpoint head. A server response cannot add or replace those trust anchors. Therefore a new client needs an authenticated local/device-to-device trust-anchor transfer; a valid signature by an unknown device does not establish trust.

On a failed signature, untrusted/revoked signer, broken predecessor, revision rollback, commitment mismatch, or observed equivocation, the client preserves the signed evidence and quarantines the vault. It will not automatically reset its cursor, discard evidence, accept `--force-full`, or silently downgrade to v1. Forensic export is deliberately redacted to checkpoint metadata and findings, excluding ciphertext/envelopes, key wrappings, plaintext, keys, passwords, tokens, and private keys.

This does not guarantee detection for every bootstrap or availability scenario. A client with no independently trusted anchor cannot distinguish a malicious first history from a genuine one. A server can deny service or withhold all updates, and a fully compromised trusted writer can sign harmful but internally consistent checkpoint state. Compare forensic evidence with another trusted device and protect client devices and trust-anchor transfer paths.

## Plain HTTP With Signed Requests

Signed requests avoid sending reusable bearer tokens over plain HTTP and prevent basic replay.

They do not hide:

- host/path;
- IP addresses;
- timing;
- request and response sizes;
- vault ids, item ids, and other metadata present outside encrypted envelopes;
- ciphertexts.

They also do not solve first-contact active MITM by themselves. Production deployments should still prefer HTTPS. Plain HTTP with signed requests is mainly useful for local networks, development, and self-hosted environments where the operator accepts metadata exposure but does not want bearer tokens to leak.

## Local SQLite Cache

The CLI operates SQLite only in memory and persists the complete database as a versioned XChaCha20-Poly1305 authenticated `cache.enc` snapshot. The separate random cache key is held only by the OS keychain. A stolen cache artifact therefore does not reveal vault IDs, item IDs, revision counts, timestamps, names, envelopes, plaintext secrets, plaintext vault keys, or master passwords without the local keychain credential.

Missing keys, malformed snapshots, unsupported versions, and authentication failures fail closed without erasing the encrypted artifact. Atomic replacement preserves the prior snapshot if a write cannot be promoted. A per-profile interprocess lock plus encrypted-artifact hash comparison rejects a stale writer before promotion, so a concurrent command cannot replace a newly persisted quarantine or checkpoint trust anchor with an older snapshot. Legacy plaintext caches are intentionally not auto-deleted because the user may need to recover them; operators must treat them as sensitive, back them up offline, remove them deliberately, and sync again.

This does not protect against malware in the same OS account, a compromised OS keychain, a process-memory dump while Umbra runs, or backups/filesystem remnants created before migration. The server still never receives cache keys, cache plaintext, or SQLite bytes.

## Local Unlock State

The CLI can store a short-lived local unlock state after `umbra unlock`.

The unlock state file contains the user private key and selected vault keys, but it is encrypted with a random local unlock key. That random key is stored in the operating system keychain, scoped to the local Umbra profile.

This protects against a simple copy of the SQLite cache or unlock state file. It does not fully protect against malware running as the same OS user, a compromised OS keychain, a process memory dump while Umbra is unlocked, or an attacker with interactive access to the unlocked account.

`umbra lock` removes the keychain entry and encrypted unlock state file. Expired unlock states are removed on the next status/load attempt.
