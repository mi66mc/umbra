# 0002: Cargo Workspace Monorepo

## Decision

Use a Cargo workspace with separate packages for CLI and server.

```txt
umbra-cli    -> binary `umbra`
umbra-server -> binary `umbra-server`
```

## Consequences

- CLI users do not install server dependencies unnecessarily.
- Server can evolve with Axum, SQLx, PostgreSQL, and Docker-specific concerns.
- Shared domain, protocol, and crypto crates remain reusable.
