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
