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
- Future OPAQUE/WebAuthn/passkeys.
- Future signed builds.
