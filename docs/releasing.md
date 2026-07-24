# Umbra release procedure

Umbra releases use annotated and signed SemVer tags (`vX.Y.Z`) from `main`. The tag version must equal the workspace package version. CLI and server are versioned together until their protocol compatibility policy is independently versioned.

Before creating a tag, require green CI, dependency security checks, PostgreSQL and SQLite integration tests, and a clean worktree. Configure the repository variable `RELEASE_GPG_PUBLIC_KEY_B64` with the base64-encoded armored public key for the authorized release signer. Create and verify the tag with Git; the release workflow imports that key and rejects unsigned tags.

## Current security release block

Releases are blocked while `Cargo.lock` contains `rsa 0.9.10` affected by `RUSTSEC-2023-0071` (Marvin Attack). The advisory has no patched version, so Umbra does not add an audit exception or remove PostgreSQL support to suppress it. The tag validation job runs `cargo audit` and must fail until a compatible upstream fix or an explicitly approved architectural replacement removes the affected dependency chain. `quinn-proto` is maintained at `0.11.15` or newer to avoid `RUSTSEC-2026-0185` independently of this release block.

The release workflow produces native CLI archives, `SHA256SUMS`, a Sigstore bundle for that manifest, a signed multi-architecture server image, BuildKit provenance, and an image SBOM. It does not publish `latest`; promotion to a mutable convenience tag is a separate, reviewed action.

The release gate starts the final image against PostgreSQL, applies migrations explicitly, then requires `umbra-server doctor --strict --json` with a persistent OPAQUE setup, HTTPS public URL, automatic migrations disabled, latest migrations required, and no warnings.

Never place the OPAQUE setup secret, a private signing key, vault plaintext, or decrypted keys in a release workflow, image layer, build log, SBOM, checksum, or release note.
