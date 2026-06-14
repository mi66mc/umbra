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
