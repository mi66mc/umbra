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

POST /api/v1/auth/register
POST /api/v1/auth/login
POST /api/v1/auth/logout
POST /api/v1/auth/refresh

GET  /api/v1/devices
POST /api/v1/devices
POST /api/v1/devices/:id/trust
POST /api/v1/devices/:id/revoke

GET    /api/v1/vaults
POST   /api/v1/vaults
GET    /api/v1/vaults/:vault_id
PATCH  /api/v1/vaults/:vault_id
DELETE /api/v1/vaults/:vault_id

GET    /api/v1/vaults/:vault_id/members
POST   /api/v1/vaults/:vault_id/invites
POST   /api/v1/invites/:invite_id/accept
POST   /api/v1/invites/:invite_id/reject
DELETE /api/v1/vaults/:vault_id/members/:user_id

GET    /api/v1/vaults/:vault_id/items
POST   /api/v1/vaults/:vault_id/items
GET    /api/v1/vaults/:vault_id/items/:item_id
PUT    /api/v1/vaults/:vault_id/items/:item_id
DELETE /api/v1/vaults/:vault_id/items/:item_id

POST /api/v1/sync
```
