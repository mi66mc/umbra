# Verify an Umbra release

Download the archive, `SHA256SUMS`, and `SHA256SUMS.sigstore.json` from the GitHub release. Verify the archive before extracting it:

```bash
sha256sum --ignore-missing --check SHA256SUMS
cosign verify-blob SHA256SUMS \
  --bundle SHA256SUMS.sigstore.json \
  --certificate-identity "https://github.com/mi66mc/umbra/.github/workflows/release.yml@refs/tags/vX.Y.Z" \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com
```

Verify a server image by immutable digest, never only by tag:

```bash
cosign verify ghcr.io/mi66mc/umbra-server@sha256:<digest> \
  --certificate-identity-regexp 'https://github.com/mi66mc/umbra/.github/workflows/release.yml@refs/tags/v.*' \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com
```

Then run `umbra --version` or `umbra-server --version`; the value must equal the release tag without its leading `v`.
