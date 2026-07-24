# Umbra Distribution

Umbra uses separate packages with clean binary names.

```txt
package: umbra-cli
binary:  umbra

package: umbra-server
binary:  umbra-server
```

Expected install paths:

```bash
cargo install umbra-cli
cargo install umbra-server
```

Future distribution:

```bash
curl -fsSL https://get.umbra.dev | sh
docker run ghcr.io/umbra/umbra-server
docker compose up -d
```

## Verified releases

Release archives are accompanied by `SHA256SUMS` and a Sigstore bundle. Container images are signed and must be consumed by digest after verification. Follow [verification.md](verification.md) before executing a downloaded CLI or deploying an image. The release workflow publishes only version tags; it does not publish a mutable `latest` image.

## Self-hosted production checklist

- Configure a persistent `UMBRA__AUTH__OPAQUE__SERVER_SETUP`; never enable ephemeral setup in production.
- Set `UMBRA__SERVER__PUBLIC_URL` to the HTTPS URL exposed by the reverse proxy.
- Keep `UMBRA__MIGRATIONS__AUTO_MIGRATE=false` and `UMBRA__MIGRATIONS__REQUIRE_LATEST=true`.
- Configure `server.trusted_proxy_cidrs` only for proxy networks operated by the deployment. Umbra otherwise uses the TCP peer IP and ignores `X-Forwarded-For`.
- Run `umbra-server doctor --strict` before rollout and after restore. Use `--json` in automated checks.
- Back up PostgreSQL with `pg_dump`; restore and validate in an isolated database before promoting it. For SQLite, stop the server before copying the database or use a consistent SQLite backup.

Rate limiting is in-memory per Umbra instance. It is effective for single-node deployments; put a shared gateway limiter in front of multi-instance deployments.
