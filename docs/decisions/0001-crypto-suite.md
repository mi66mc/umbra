# 0001: Initial Crypto Suite

## Decision

Start with:

```txt
Argon2id
HKDF-SHA256
XChaCha20-Poly1305
JSON envelopes v1
```

Vault keys are random per vault. User passwords derive an account KEK that opens the encrypted user private key. User private keys open per-recipient vault key wrappings.

## Consequences

- Password changes do not require re-encrypting every vault item.
- Shared vaults use the same mechanism as personal vaults.
- JSON envelopes are easy to inspect and test during early development.
