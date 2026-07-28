# Device-Scoped Vault-Wrapping Operations

## Scope and current rollout state

Umbra's target model is one opaque vault-key envelope per active, approved recipient device. The envelope is created, decrypted, and re-encrypted only on clients. The server stores and authorizes opaque envelopes plus non-secret identifiers, device state, roles, and generations.

The currently implemented v3 boundary covers device encryption-key registration, initial vault creation, sync delivery, cache selection, and local unlock. It does **not** yet cover approved-device envelope distribution, invite acceptance/direct member grants, or multi-device rotation. Operators must not represent those incomplete workflows as fully protected by the device-scoped guarantee.

Migration 10 is required on both PostgreSQL and SQLite. Verify it before enabling a v3-capable client:

```powershell
umbra-server migrate status
umbra-server doctor --strict
```

PostgreSQL remains the production default and is not optional for this rollout. SQLite has the same migration for development and lightweight self-hosting.

## Enrollment and approval

1. Enroll a new machine with `umbra login --new-device`; it is pending.
2. Confirm the approval code and device fingerprint out of band on an existing trusted device.
3. Approve the device only after that comparison.
4. Do not assume approval alone grants a device a current vault key during this rollout. A trusted client must distribute a device-addressed envelope for every vault before the new device can unlock it; that distribution workflow is not complete yet.
5. A pending device must not receive vault envelopes through sync, bootstrap, member grants, or invites. Treat any contrary observation as a security incident and preserve redacted request/audit metadata.

Emergency-kit recovery creates or uses a pending device. The kit must remain offline and does not make the recovering device entitled to vault envelopes until the device is trusted and a trusted client has distributed device-targeted material. Never add a device encryption private key to an emergency kit.

## Lost, revoked, or compromised device

1. Revoke the device immediately with `umbra device revoke <device-id>` from a trusted profile.
2. End or invalidate any associated session through the normal revoke flow.
3. Identify every vault and external credential the device could have accessed.
4. Rotate each affected vault from a remaining trusted device, then rotate the external credentials stored inside it.
5. Preserve redacted audit/integrity evidence: device IDs, vault IDs, generations, timestamps, checkpoint hashes, and error codes only.

Revocation blocks future server access and delivery. It cannot erase vault keys, item plaintext, cache artifacts, screenshots, or exported secrets already obtained by the device. Do not claim remote wipe or retroactive cryptographic revocation.

## Member removal and shared vaults

Removing a member sets the vault rotation requirement. Until device-scoped member distribution is complete, treat current invite/direct-member and rotation wrapping as legacy user-scoped behavior. Complete the membership change, rotate the vault and external secrets, and record the residual risk that devices previously controlled by the removed member may retain old material.

The completed workflow must enumerate active member devices client-side, create one envelope per device with vault/device/generation AAD, and send only opaque records. The server must reject pending/revoked targets, targets outside the member, duplicate targets, and rotations missing an active target.

## Incident and logging hygiene

Never paste an envelope body, vault key, device encryption private key, account private key, password, session token, or decrypted item into tickets, audit notes, logs, or integrity evidence. Diagnostics may include IDs, states, roles, generations, counts, and SHA-256 hashes of opaque bytes. Cache exports and forensic reports must remain redacted.

The existing release block for `RUSTSEC-2023-0071` remains in force. Do not add an advisory ignore or exception while operating or releasing this branch.
