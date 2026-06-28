# Multi-Device Trust Design

## Goal

Umbra must support multiple devices per account without weakening the zero-knowledge boundary. A new device should be able to join an existing account through either:

- approval from an already trusted device; or
- recovery with master password plus emergency kit / `user_secret_key`.

The first implementation should make multi-device use practical without introducing per-device vault key wrapping yet. Device-specific vault wrappings remain a future evolution.

## Current Context

The project already has the main building blocks:

- OPAQUE registration/login for password authentication.
- Device records in PostgreSQL.
- Device signing keys for signed HTTP sessions.
- `device_id` on sessions and vault key wrappings.
- User private key encrypted by an account KEK derived from `master_password + user_secret_key + Argon2id`.
- Vault key wrappings encrypted for the user public key.
- Local CLI profiles and encrypted local unlock state.

The missing product flow is device trust: a second notebook or phone can prove the account password with OPAQUE, but it still needs a safe way to become trusted and receive local cryptographic account material.

## Model

`User` owns account-level cryptographic material:

- email;
- OPAQUE password registration;
- account public key;
- encrypted user private key.

`Device` represents a local installation:

- `id`;
- `user_id`;
- `name`;
- signing public key;
- fingerprint;
- `state`;
- approval/bootstrap metadata.

Device states are explicit:

```txt
pending
trusted
revoked
```

`trusted boolean` should stop being the source of truth. Migrate the code to use `devices.state`.

Existing rows map as:

```txt
revoked_at IS NOT NULL => revoked
trusted = true        => trusted
trusted = false       => pending
```

Pending devices cannot access vaults, sync, items, secrets, orgs, or membership APIs. They can only poll their own bootstrap state and complete device setup.

## Trust Boundaries

OPAQUE answers:

```txt
Does this client know the account password?
```

OPAQUE does not answer:

```txt
Is this device trusted?
Can this device sync vaults?
Does this device have user_secret_key?
Can this device decrypt vault key wrappings?
```

Those are separate layers:

```txt
OPAQUE login:
  proves password to the server without sending the password

Device trust:
  decides whether a device can operate the account

Local unlock:
  uses master_password + user_secret_key to decrypt user_private_key

Vault access:
  uses user_private_key to unwrap vault keys
```

The server must never receive master password, `user_secret_key`, account KEK, user private key plaintext, vault key plaintext, or item plaintext.

## Primary Flow: New Device Approval

1. New device runs:

   ```bash
   umbra login --profile work-laptop
   ```

2. CLI performs OPAQUE login with email and password.

3. Server validates the password through OPAQUE.

4. Because the device is not trusted, server creates or updates a pending device:

   ```txt
   device_id
   user_id
   name
   signing public key
   fingerprint
   bootstrap_public_key
   approval_code_hash
   approval_expires_at
   state = pending
   ```

5. New device shows:

   ```txt
   Pending approval
   Code: UMBRA-7K4Q-2M9D
   Fingerprint: ...
   ```

6. On an already trusted device:

   ```bash
   umbra device pending
   umbra device approve UMBRA-7K4Q-2M9D
   ```

7. Trusted device verifies code/fingerprint and creates an encrypted bootstrap bundle for the new device.

8. Server stores the encrypted bundle and marks the pending device trusted.

9. New device runs polling or:

   ```bash
   umbra device finish
   ```

10. New device downloads and decrypts the bootstrap bundle locally, saves its profile, and starts using signed sessions.

## Bootstrap Bundle

The bootstrap bundle is encrypted to the new device bootstrap public key. It contains:

```txt
user_secret_key
kdf_params
encrypted_user_private_key
account public key
default_vault_id, if known
```

It does not contain:

```txt
master password
vault key plaintext
item plaintext
reusable bearer token
```

The server stores and transports the bundle as opaque encrypted JSON.

## Recovery Flow

If the user loses all trusted devices, recovery uses password plus emergency kit:

1. User installs Umbra on a new device.

2. Runs:

   ```bash
   umbra login --profile recovered
   ```

3. CLI performs OPAQUE login.

4. Server confirms password and creates a pending device.

5. User runs:

   ```bash
   umbra device recover
   ```

6. CLI asks for:

   ```txt
   master password
   emergency kit / user_secret_key
   ```

7. CLI downloads account crypto metadata:

   ```txt
   encrypted_user_private_key
   kdf_params
   account public key
   ```

8. CLI derives and verifies locally:

   ```txt
   account_kek = Argon2id(master_password + user_secret_key)
   user_private_key = decrypt(encrypted_user_private_key, account_kek)
   ```

9. If decrypt succeeds, the CLI completes an account-key challenge:

   ```txt
   server creates random recovery challenge
   server encrypts challenge to account public key
   client decrypts challenge with recovered user_private_key
   client returns challenge response plus current device signing public key
   server marks current device trusted
   ```

   The existing MVP user keypair is X25519 encryption material, not a signing key. The recovery proof should therefore be based on decrypting an encrypted challenge, not signing with the account key.

10. If the challenge succeeds, the current device becomes trusted automatically.

This is acceptable because the emergency kit is the strong recovery factor. Requiring another trusted device would defeat the purpose of recovery.

## Device Revoke

Expected CLI:

```bash
umbra device list
umbra device revoke <device-id>
```

MVP behavior:

```txt
mark device state = revoked
set revoked_at
revoke active sessions for that device
reject future signed login for that device
reject sync/vault/item access for that device
write audit log
```

Revoke does not promise to:

```txt
delete local cache from the lost device
erase a vault key already saved locally
erase secrets already viewed or copied
```

After revoking a lost or stolen device, CLI should recommend vault key rotation:

```bash
umbra crypto rotate-vault-key <vault>
```

Do not implement `--rotate-accessible-vaults` in this first cut. That requires re-encrypting many vaults, handling conflicts, and creating new wrappings safely.

## Storage Changes

Add a migration for `devices`:

```txt
state text NOT NULL DEFAULT 'trusted'
approval_code_hash text nullable
approval_expires_at timestamptz nullable
bootstrap_public_key text nullable
bootstrap_bundle jsonb nullable
trusted_at timestamptz nullable
```

`state` has a check constraint:

```txt
pending | trusted | revoked
```

Code should use `state` as the authority. `trusted boolean` may remain physically present during the migration, but new logic should not depend on it.

Approval codes must be stored hashed, not plaintext.

## API Changes

Add or complete device APIs:

```http
GET  /api/v1/devices
GET  /api/v1/devices/pending
POST /api/v1/devices/pending
POST /api/v1/devices/:device_id/approve
POST /api/v1/devices/:device_id/recover-trust
POST /api/v1/devices/:device_id/revoke
GET  /api/v1/devices/:device_id/bootstrap
```

Authorization rules:

```txt
pending session:
  can poll/finish only its own bootstrap
  cannot list vaults
  cannot sync
  cannot read/write items or secrets
  cannot approve another device

trusted signed session:
  can list devices for its user
  can list pending devices for its user
  can approve pending devices
  can revoke devices

revoked device:
  cannot create signed sessions
  cannot access protected APIs
```

`recover-trust` must not send `user_secret_key` to the server. It must also not trust a device from OPAQUE password success alone.

Recovery trust requires two facts:

```txt
1. OPAQUE session proves the user knows the account password.
2. Account-key challenge proves the client recovered user_private_key using the emergency kit.
```

The server should create a random challenge, encrypt it to the account public key, and accept trust only when the client decrypts and returns the expected response from the pending device session. The response should be bound to the pending `device_id` and current device signing public key so it cannot be replayed to trust another device.

## CLI Commands

Add:

```bash
umbra device list
umbra device pending
umbra device approve <code>
umbra device finish
umbra device recover
umbra device revoke <device-id>
```

Human mode should guide the user:

```txt
Approve this device from another trusted device.
Code: UMBRA-7K4Q-2M9D
Run: umbra device approve UMBRA-7K4Q-2M9D
```

JSON mode must remain deterministic and non-interactive.

## Error Handling

Required errors:

```txt
pending device expired
approval code invalid
approval code ambiguous
device already trusted
device revoked
bootstrap bundle not ready
bootstrap bundle already consumed
pending session cannot access vaults
trusted device required
recovery failed: invalid password or emergency kit
recovery challenge invalid
recovery challenge expired
```

Approval code lookup should handle ambiguity even if generated codes are expected to be unique. Expired pending devices should not be approvable.

## Testing

Server/storage tests:

```txt
creates pending device
lists pending devices only for the same user
trusted device approves pending device
pending device cannot access vault/sync/item endpoints
pending device can download bootstrap after approval
bootstrap bundle is opaque in storage and audit logs
revoke device invalidates sessions
revoked device cannot create signed session
recovery trust requires account-key challenge before marking current device trusted
```

CLI tests:

```txt
login from unknown device saves pending profile
device pending renders pending devices
device approve creates encrypted bootstrap bundle
device finish consumes bootstrap and saves local config
device recover with emergency kit marks current device trusted
device recover fails when account-key challenge cannot be decrypted
device revoke warns about vault key rotation
--json requires explicit inputs and never opens prompts
```

Crypto tests:

```txt
bootstrap bundle encrypt/decrypt roundtrip
bootstrap bundle decrypt fails with wrong device key
bootstrap bundle decrypt fails with changed AAD
approval code and fingerprint contain no secret material
Debug output redacts user_secret_key and emergency kit material
```

## Success Criteria

The implementation is correct when this scenario works:

```txt
1. User registers account on device A.
2. Device A creates a vault and a secret.
3. User logs in on device B.
4. Device B becomes pending and shows an approval code.
5. Device A approves device B.
6. Device B finishes bootstrap.
7. Device B syncs and reads the secret.
8. Device A revokes device B.
9. Device B cannot sync online anymore.
10. User recovers on device C with password + emergency kit.
11. Device C becomes trusted and can sync.
```

## Non-Goals

This design does not implement:

```txt
per-device vault key wrappings
automatic rotation of all accessible vaults on revoke
QR/deep-link approval UX
mobile push approval
remote wipe of local cache
perfect erasure of secrets already viewed by a revoked device
```

These are compatible future additions.
