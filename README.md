# Umbra

Umbra is a zero-knowledge, self-hosted, developer-first vault for passwords, SSH keys, API keys, project secrets, personal vaults, and shared team vaults.

The server stores users, devices, vault metadata, memberships, encrypted envelopes, wrapped vault keys, revisions, and audit events. It must never receive plaintext secrets, plaintext vault keys, master passwords, user secret keys, or decrypted items.

## Initial Direction

- Cargo workspace with separate CLI and server packages.
- `umbra-cli` publishes the `umbra` binary.
- `umbra-server` publishes the `umbra-server` binary.
- Vault keys are random per vault and wrapped for authorized users/devices.
- User passwords unlock encrypted user private keys, not vaults directly.
- Client-side crypto and client-side encrypted data migrations.
- Server-side PostgreSQL schema migrations.

## Development

```bash
cargo test
cargo build
cargo run -p umbra-cli
cargo run -p umbra-server
```
