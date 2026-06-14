# Umbra Protocol

All API requests use explicit protocol versioning.

```json
{
  "protocol_version": 1
}
```

An HTTP header such as `Umbra-Protocol-Version: 1` may also be supported later, but body-level versioning is the initial contract.

## Initial Endpoints

```txt
GET  /health
GET  /ready

POST /api/v1/auth/register/start
POST /api/v1/auth/register/finish
POST /api/v1/auth/login/start
POST /api/v1/auth/login/finish

GET  /api/v1/devices
POST /api/v1/devices
POST /api/v1/devices/:id/trust
POST /api/v1/devices/:id/revoke

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
```

The server currently implements the OPAQUE register/login flow, organization creation/listing/member management, personal vault creation, organization vault creation, direct vault member grants, member removal, rotation status, rotation completion, encrypted item creation/update, and revision sync.

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
   - a legacy bearer session when device_id is omitted
```

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

Adding a user to a vault requires a client-generated vault key wrapping:

```json
{
  "protocol_version": 1,
  "user_id": "...",
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

The server stores this as an opaque JSON envelope. It does not validate or decrypt the vault key.

## Item And Sync API

Items are stored as encrypted revision envelopes. The server validates vault membership and write roles, but never decrypts item envelopes.

```http
POST /api/v1/vaults/:vault_id/items
PUT /api/v1/vaults/:vault_id/items/:item_id
POST /api/v1/sync
```

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
