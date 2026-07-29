# Device-Scoped Vault-Wrapping Security Verification Matrix

This matrix is the acceptance checklist for completing the device-scoped wrapping rollout. It intentionally distinguishes implemented coverage from required automated coverage; it is not evidence that an unchecked flow is secure.

| Scenario | Required assertion | Current state |
| --- | --- | --- |
| Device registration | A unique X25519 keypair is generated locally; only the public key is registered; private key is redacted | Implemented; retain regression coverage |
| Initial vault creation | The first wrapping is `device_public_key`, targets the authenticated device, and authenticates vault/device/generation AAD | Implemented; retain regression coverage |
| Two-device sync | Each trusted device receives only its own envelope and can unlock its own copy | Sync filtering/cache lookup implemented; end-to-end approval fixture required |
| Pending device | Cannot receive, list, sync, or unwrap a new envelope | Required automated route and CLI tests |
| Revoked device | Cannot authenticate/sync new envelope; later rotation excludes it | Required end-to-end tests |
| Approval/bootstrap | Trusted device distributes one envelope per vault to exactly the approved device | Required implementation and tests |
| Invite/member grant | Client produces one envelope for every active target-member device; server rejects foreign/inactive/duplicate targets | Required implementation and tests |
| Member removal | Removal requires rotation and later generation excludes all removed-member devices | Required end-to-end tests |
| Rotation | New generation contains exactly active recipient devices; no user-scoped fallback | Required implementation and tests |
| Emergency recovery | Recovered device remains pending and receives no vault material before trusted distribution | Required integration test |
| Legacy data | Null-device/user-scoped wrapping cannot unlock as a device wrapping | Implemented locally; add server/sync regression test |
| Checkpoint integrity | Recipient device ID, generation, wrapping type, and envelope hash are committed and tampering quarantines state | Required implementation and tamper tests |
| Leakage | Storage/sync/log/audit/cache fixtures contain no plaintext vault key, device private key, raw envelope, or test secret | Required scans for PostgreSQL and SQLite |

Run the full matrix against PostgreSQL and SQLite. Tampering tests must alter target device ID, key generation, wrapping type, wrapping hash, checkpoint commitment, and sync ordering, then assert atomic rejection and unchanged cache/integrity head. Do not weaken the `RUSTSEC-2023-0071` release gate while adding these tests.
