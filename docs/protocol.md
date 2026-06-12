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

The server currently implements the OPAQUE register/login flow, organization creation/listing/member management, personal vault creation, organization vault creation, direct vault member grants, member removal, rotation status, and rotation completion.

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
4. server creates a bearer session token
```

The OPAQUE server setup must be persistent outside PostgreSQL. Generate it with:

```bash
umbra-server opaque setup generate
```

Then inject it as `UMBRA__AUTH__OPAQUE__SERVER_SETUP` or `auth.opaque.server_setup` in config. Development may opt into ephemeral setup with `UMBRA__AUTH__OPAQUE__ALLOW_EPHEMERAL_SETUP=true`, but production should fail closed when the persistent setup is missing.

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
