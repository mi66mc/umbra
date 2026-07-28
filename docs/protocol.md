# Umbra Protocol

All API requests use explicit protocol versioning.

```json
{
  "protocol_version": 1
}
```

An HTTP header such as `Umbra-Protocol-Version: 1` may also be supported later, but body-level versioning is the initial contract.

## Protocol v3: device-scoped vault-key wrapping

Version 3 is supported alongside versions 1 and 2. It introduces a non-secret `encryption_public_key` on a device and uses `device_public_key` wrappings addressed to `device_id`. The matching X25519 private key is client-only. Initial v3 vault creation stores a wrapping for the authenticated trusted device; a v3 sync response filters wrapping records to the authenticated trusted device and the requested vault.

The opaque wrapping record includes only routing metadata plus the encrypted envelope:

```json
{
  "vault_id": "<uuid>",
  "user_id": "<uuid>",
  "device_id": "<uuid>",
  "wrapping_type": "device_public_key",
  "key_generation": 1,
  "envelope": { "version": 1, "wrapping": { "method": "device_public_key" } }
}
```

The server treats `envelope` as opaque JSON. It authorizes the caller and recipient device state but must not decrypt, normalize, log, audit, or include raw envelope bytes in checkpoint/integrity evidence. Clients bind encryption/decryption to domain-separated AAD containing the vault ID, recipient device ID, and key generation. They must reject an absent, wrong-device, wrong-generation, or non-`device_public_key` wrapping rather than using an account-key fallback.

Version 3 is not yet a complete multi-recipient format. The approved-device bootstrap request, invite/member requests, and rotation request still expose legacy envelope shapes (including optional or absent recipient device routing). They require a coordinated protocol change before those operations can claim device-scoped distribution. Do not infer that protocol version 3 alone makes an invite, approval, or rotation safe for all devices. A future v3 checkpoint extension must commit sorted recipient-device metadata and hashes of opaque wrapping bytes; existing version-2 checkpoints do not do so.

## Initial Endpoints

```txt
GET  /health
GET  /ready

POST /api/v1/auth/register/start
POST /api/v1/auth/register/finish
POST /api/v1/auth/login/start
POST /api/v1/auth/login/finish

GET  /api/v1/devices
GET  /api/v1/devices/pending
POST /api/v1/devices/approval-lookup
POST /api/v1/devices/:device_id/approve
POST /api/v1/devices/:device_id/revoke
GET  /api/v1/devices/:device_id/bootstrap
POST /api/v1/devices/:device_id/recovery-challenge
POST /api/v1/devices/:device_id/recover-trust

POST /api/v1/users/lookup

GET  /api/v1/orgs
POST /api/v1/orgs
GET  /api/v1/orgs/:org_id
GET  /api/v1/orgs/:org_id/members
POST /api/v1/orgs/:org_id/members
POST /api/v1/orgs/:org_id/vaults

GET    /api/v1/vaults
POST   /api/v1/vaults
GET    /api/v1/vaults/:vault_id
PATCH  /api/v1/vaults/:vault_id
DELETE /api/v1/vaults/:vault_id

GET    /api/v1/vaults/:vault_id/members
POST   /api/v1/vaults/:vault_id/invites
GET    /api/v1/invites
POST   /api/v1/vaults/:vault_id/members
POST   /api/v1/invites/:invite_id/accept
POST   /api/v1/invites/:invite_id/reject
DELETE /api/v1/vaults/:vault_id/members/:user_id
GET    /api/v1/vaults/:vault_id/rotation-status
POST   /api/v1/vaults/:vault_id/rotate-key

GET    /api/v1/vaults/:vault_id/items
POST   /api/v1/vaults/:vault_id/items
GET    /api/v1/vaults/:vault_id/items/:item_id
PUT    /api/v1/vaults/:vault_id/items/:item_id
DELETE /api/v1/vaults/:vault_id/items/:item_id

POST /api/v1/sync
POST /api/v1/sync/status
```

The server currently implements the OPAQUE register/login flow, organization creation/listing/member management, personal vault creation, organization vault creation, invite-based vault sharing, direct vault member grants, member removal, rotation status, rotation completion, encrypted item creation/update, sync status, and revision sync.

### User Lookup

```http
POST /api/v1/users/lookup
```

This trusted endpoint returns `user_id`, email, and account public key for an existing user. It exists so a client can encrypt a vault-key wrapping to that user's public key without exposing the vault key to the server.

### Vault Members

```http
GET /api/v1/vaults/:vault_id/members
POST /api/v1/vaults/:vault_id/members
DELETE /api/v1/vaults/:vault_id/members/:user_id
```

`POST` requires `vault_key_wrapping`. The wrapping is produced client-side with the target account public key. The server stores the wrapping and enforces membership/role checks, but cannot decrypt it.

### Vault Invites

```http
POST /api/v1/vaults/:vault_id/invites
GET /api/v1/invites
POST /api/v1/invites/:invite_id/accept
POST /api/v1/invites/:invite_id/reject
```

`POST /vaults/:vault_id/invites` is the normal CLI sharing path. The owner/admin client looks up the target account public key, unwraps the vault key locally, creates a `user_public_key` vault-key wrapping for the target user, and sends that encrypted wrapping with `InviteMemberRequest`.

`GET /invites` returns pending invites for the authenticated user's email. `accept` validates the trusted device id, activates the membership, stores the pending encrypted vault-key wrapping, and increments access revision so sync sees the new access material. `reject` marks the invite rejected without creating membership.

### Vault Key Rotation

```http
GET /api/v1/vaults/:vault_id/rotation-status
POST /api/v1/vaults/:vault_id/rotate-key
```

`rotation-status` returns the current key generation and whether the vault needs rotation. `rotate-key` accepts `RotateVaultKeyRequest` with `from_generation`, `to_generation`, new encrypted vault-key wrappings, and reencrypted item revisions. The server never receives the new vault key or plaintext item contents.

## Auth Flow

OPAQUE is a two-step registration and login flow.

Registration:

```txt
1. client sends OPAQUE registration request to /register/start
2. server returns OPAQUE registration response
3. client sends registration upload, public key, encrypted private key, and initial device to /register/finish
4. server stores only the OPAQUE password file and encrypted account material
```

Login:

```txt
1. client sends OPAQUE credential request to /login/start
2. server stores pending login state bound to user_id
3. client sends credential finalization to /login/finish
4. server creates either:
   - a signed session when device_id is provided
   - a limited pending-device bearer session when pending_device is provided
   - a legacy bearer session when device_id is omitted
```

Known trusted devices receive signed sessions. Unknown devices can complete OPAQUE login with the account password, but they start as `pending` and cannot access vault, item, sync, organization, or device-management APIs.

Pending device approval:

```txt
1. new device sends device signing public key, fingerprint, and bootstrap public key during login finish
2. server stores devices.state = pending and returns an approval code
3. trusted device looks up the approval code
4. trusted device encrypts a device bootstrap bundle to the pending device bootstrap public key
5. server stores the bootstrap bundle and marks the pending device trusted
6. pending device downloads and decrypts the bootstrap bundle locally
```

The bootstrap bundle contains account crypto material already encrypted for client use: user secret key, KDF params, encrypted user private key, account public key, and optional default vault id. The server stores the encrypted bootstrap envelope as opaque JSON and cannot decrypt it.

Recovery without another trusted device is challenge based:

```txt
1. pending device starts a recovery challenge
2. server encrypts a random challenge to the account public key
3. client reconstructs the account private key locally from the pending encrypted private key, emergency kit, and master password
4. client returns the challenge response
5. server consumes the challenge once and marks the current pending device trusted
```

The CLI clean-device recovery path gets account public key, KDF params, and user secret key from the emergency kit, while the encrypted user private key comes from the OPAQUE login response. The challenge is decrypted locally and the plaintext challenge response is sent to `recover-trust`. After recovery succeeds, the CLI clears the pending bearer/session so the device performs a normal trusted login.

The OPAQUE server setup must be persistent outside PostgreSQL. Generate it with:

```bash
umbra-server opaque setup generate
```

Then inject it as `UMBRA__AUTH__OPAQUE__SERVER_SETUP` or `auth.opaque.server_setup` in config. Development may opt into ephemeral setup with `UMBRA__AUTH__OPAQUE__ALLOW_EPHEMERAL_SETUP=true`, but production should fail closed when the persistent setup is missing.

## Signed HTTP Sessions

For CLI sessions, Umbra can authenticate protected requests without sending a reusable bearer token.

Each protected request includes:

```http
Umbra-Session-Id: <uuid>
Umbra-Device-Id: <uuid>
Umbra-Timestamp: <unix timestamp>
Umbra-Nonce: <random nonce>
Umbra-Body-Sha256: <base64url sha256 body>
Umbra-Signature: <base64url ed25519 signature>
```

The signature covers:

```txt
UMBRA-SIGNED-REQUEST-V1
METHOD
PATH_AND_QUERY
BODY_SHA256
TIMESTAMP_UNIX
NONCE
SESSION_ID
DEVICE_ID
```

The server verifies the stored trusted device public key, rejects stale timestamps, and rejects repeated `(session_id, nonce)` pairs.

## Vault Grants

Inviting or directly adding a user to a vault requires a client-generated vault key wrapping:

```json
{
  "protocol_version": 1,
  "vault_id": "...",
  "email": "ana@example.com",
  "role": "viewer",
  "vault_key_wrapping": {
    "version": 1,
    "type": "vault_key_wrapping",
    "wrapping": {
      "method": "user_public_key",
      "recipient_public_key": "base64url...",
      "ephemeral_public_key": "base64url..."
    },
    "encryption": {}
  }
}
```

The server stores this as an opaque JSON envelope. It does not validate or decrypt the vault key. The invite recipient can only decrypt the wrapping after accepting and syncing it locally with their account private key.

## Item And Sync API

Items are stored as encrypted revision envelopes. The server validates vault membership and write roles, but never decrypts item envelopes.

```http
POST /api/v1/vaults/:vault_id/items
PUT /api/v1/vaults/:vault_id/items/:item_id
DELETE /api/v1/vaults/:vault_id/items/:item_id
POST /api/v1/sync
```

`DELETE /api/v1/vaults/:vault_id/items/:item_id` accepts `DeleteItemRequest` with `expected_revision`. The server checks writer permission and revision preconditions, then soft-deletes the item and increments the vault revision. Sync returns deleted item ids through `VaultSyncChanges.deleted_items`; item plaintext is never sent to or decrypted by the server.

`POST /api/v1/sync` accepts per-vault cursors:

```json
{
  "protocol_version": 1,
  "device_id": "00000000-0000-0000-0000-000000000000",
  "vaults": [
    {
      "vault_id": "00000000-0000-0000-0000-000000000000",
      "since_vault_revision": 0
    }
  ]
}
```

The response includes typed encrypted item revisions and vault key wrappings:

```json
{
  "protocol_version": 1,
  "vaults": [
    {
      "vault_id": "00000000-0000-0000-0000-000000000000",
      "latest_vault_revision": 2,
      "latest_access_revision": 1,
      "items": [
        {
          "item_id": "00000000-0000-0000-0000-000000000000",
          "vault_id": "00000000-0000-0000-0000-000000000000",
          "revision": 1,
          "vault_revision": 1,
          "key_generation": 1,
          "author_user_id": "00000000-0000-0000-0000-000000000000",
          "envelope": {
            "version": 1,
            "ciphertext": "base64url..."
          }
        }
      ],
      "deleted_items": [],
      "key_wrappings": []
    }
  ]
}
```

`POST /api/v1/sync/status` lets a client check whether a full sync is needed without downloading encrypted item envelopes:

```json
{
  "protocol_version": 1,
  "vaults": [
    {
      "vault_id": "00000000-0000-0000-0000-000000000000",
      "known_vault_revision": 2,
      "known_access_revision": 1
    }
  ]
}
```

The response reports only revision movement:

```json
{
  "protocol_version": 1,
  "vaults": [
    {
      "vault_id": "00000000-0000-0000-0000-000000000000",
      "latest_vault_revision": 2,
      "latest_access_revision": 3,
      "items_changed": false,
      "access_changed": true
    }
  ]
}
```

The endpoint is authenticated and uses the same vault membership checks as full sync. It does not expose plaintext, ciphertext, item counts, or member counts.

## Protocol v2: signed sync checkpoints

Version 2 is opt-in. A client sends `"protocol_version": 2`; v1 remains byte-for-byte compatible and omits checkpoint fields. A v1 client must never be made to parse or validate checkpoint data, and a v2 client must not silently fall back to v1 after an integrity failure.

A v2 sync response carries the ordered checkpoint history needed after the caller's verified head. Checkpoint creation is accepted only from the authenticated signed-request device when it is trusted and has vault writer/editor permission. The author device ID in the payload must match that request identity. The server persists and transports the opaque record; it does not possess a checkpoint private key or use signature verification as a source of authority.

The canonical signed payload is domain separated as `UMBRA-SYNC-CHECKPOINT-V1` and encodes, in a fixed unambiguous order:

```txt
vault_id
vault_revision (fixed-width)
state_commitment (SHA-256)
previous_checkpoint_hash (SHA-256 or the defined genesis value)
author_device_id
sorted encrypted-state entries
```

State entries are sorted deterministically and include only item/conflict identifiers, revisions and state, deletion markers, key-generation metadata, and hashes of ciphertext envelopes. The checkpoint signature is Ed25519 over these bytes; its checkpoint hash identifies the signed record. Raw ciphertext envelopes, vault-key wrappings, plaintext, keys, passwords, sessions, and private keys are never part of the checkpoint payload or evidence bundle.

For a v2 vault, the client validates the signature against locally persisted trusted device keys, then validates predecessor, monotonic revision, commitment, and equivocation. An unknown or revoked signer fails even if its signature is mathematically valid. Any failure—including rollback, omitted/broken history, altered commitment, or different hashes for one vault/revision—must be recorded locally and cause the vault to be quarantined. The normal sync/status path returns an integrity error containing only vault, revision, and checkpoint identifiers; it must not apply the unsafe response.

`umbra sync integrity status --vault <selector>` reports the local integrity state. `umbra sync integrity export --vault <selector> --output <file>` writes a forensic bundle of checkpoint metadata and findings only. Exports must not overwrite an existing output by default and must exclude envelopes, wrappings, ciphertext, plaintext, vault keys, tokens, passwords, and private keys.

## Cacheable Sync Data

`SyncResponse` is safe for the CLI to cache because item data and vault keys are still encrypted envelopes.

The client may persist:

- `latest_vault_revision`;
- `latest_access_revision`;
- item revision envelopes;
- vault key wrapping envelopes;
- item ids, vault ids, revision numbers, and key generation metadata.

The server remains the source of truth. The cache is a local acceleration and offline inspection layer, not an authority for membership or writes. Online CLI reads compare cached revisions with sync status and full-sync only when item data or access metadata changed.
# Conflitos de item

`UpdateItemRequest` e `DeleteItemRequest` podem retornar HTTP `409` com `ItemConflictResponse`. A resposta inclui o ID da candidata, item, revisão-base, revisão atual, tipo, estado e envelope cifrado opcional; não inclui plaintext.

`VaultSyncChanges.conflicts` contém todas as candidatas abertas da vault. As rotas autenticadas são:

- `GET /api/v1/vaults/:vault_id/conflicts`
- `GET /api/v1/vaults/:vault_id/conflicts/:conflict_id`
- `POST /api/v1/vaults/:vault_id/conflicts/:conflict_id/resolve`

O pedido de resolução inclui `expected_current_revision` e `resolution` (`remote`, `local` ou `merge`). `merge` traz somente o envelope final cifrado. A resolução de conflito de delete aceita apenas `remote` ou `local`.
