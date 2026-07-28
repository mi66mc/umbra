# Sync Integrity Checkpoints Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Detect a zero-knowledge sync server's rollback or equivocation without transmitting plaintext or vault keys, and refuse to accept unsafe sync results while preserving signed evidence for forensic export.

**Architecture:** Add protocol-v2, device-signed checkpoint records to each vault sync response. A checkpoint binds the vault revision to a deterministic commitment of encrypted item/conflict state and the preceding checkpoint hash; the storage service only persists and returns this opaque signed metadata. Each client keeps a durable, locally trusted device-key set and its latest verified checkpoint, validates the signed chain before atomically applying sync changes, and quarantines the vault on any integrity violation.

**Tech Stack:** Rust 2024, ed25519-dalek, SHA-256, Serde JSON, Axum, SQLx (PostgreSQL/SQLite), Rusqlite, Clap, Tokio, Cargo.

## Global Constraints

- Keep `PROTOCOL_VERSION == 1` behaviour byte-for-byte compatible; request and emit checkpoints only under explicit protocol version 2 gating.
- A checkpoint payload contains only `vault_id`, `vault_revision`, a SHA-256 item/conflict-state commitment, `previous_checkpoint_hash`, `author_device_id`, and an Ed25519 signature over a fixed, canonical domain-separated encoding.
- The state commitment uses identifiers, revisions, deletion markers, conflict IDs/state/revisions, ciphertext-envelope hashes, and key-generation metadata; it must never contain item plaintext, raw encrypted envelopes, vault keys, passwords, sessions, or private keys.
- The server stores/transports signed public metadata and checkpoint hashes but never possesses signing private keys or attempts signature verification as an authority.
- A client’s locally persisted trusted-device public keys are the trust anchor. Server-provided device identities never overwrite that anchor during checkpoint validation.
- On non-monotonic revision, missing/broken predecessor, invalid signature, unknown/revoked signer, commitment mismatch, or different valid checkpoint at one revision, persist the evidence, mark the vault unsafe, and block further accepting sync. Do not auto-reset, force-full-sync, or delete evidence.
- Checkpoint authoring requires a trusted writer/editor device and uses the signed HTTP request identity. Audit events record only vault/device/checkpoint/revision/hash identifiers.
- Forensic exports contain signed checkpoint metadata and integrity findings only; never include ciphertext envelopes, plaintext, vault-key wrappings, secrets, tokens, or private keys.
- Preserve the RSA release block unchanged; this branch is independent of release PR #2.

---

## File Structure

- `crates/umbra-protocol/src/lib.rs`: protocol version constants, canonical checkpoint wire records, and v1/v2 sync request/response compatibility.
- `crates/umbra-crypto/src/lib.rs`: domain-separated checkpoint payload encoding, commitment hashing, signing, verification, and deterministic test fixtures.
- `crates/umbra-storage/src/{models.rs,backend.rs}`: storage input/output records and backend interfaces.
- `crates/umbra-storage/src/{postgres,sqlite}/checkpoints.rs`: transactional opaque-checkpoint persistence, ordered retrieval, same-revision conflict detection, and audit metadata.
- `crates/umbra-migrations/{migrations,sqlite}/000009_sync_checkpoints.sql`: matching PostgreSQL/SQLite checkpoint and audit-index migrations.
- `crates/umbra-server/src/{http.rs,authz.rs,tests.rs}`: v2 routes/sync integration, writer authorization, request-device attribution, ciphertext-safe audit, and malicious-server fixtures.
- `crates/umbra-cli/src/{cache.rs,sync.rs,commands.rs,error.rs,output.rs,tests.rs}`: local trust-anchor/checkpoint/evidence tables, validator, quarantine gate, CLI integrity status/export, and redacted output.
- `README.md`, `docs/architecture.md`, `docs/protocol.md`, `docs/threat-model.md`, `docs/migrations.md`: deployment, protocol, trust-boundary, limitations, and migration documentation.

### Task 1: Define the versioned checkpoint protocol and cryptographic contract

**Files:** Modify `crates/umbra-protocol/src/lib.rs`, `crates/umbra-crypto/src/lib.rs`, and their unit tests.

**Interfaces:** Produces `SYNC_INTEGRITY_PROTOCOL_VERSION: u16 = 2`, `SyncCheckpoint`, `CheckpointSignature`, `CheckpointPayload`, `CheckpointStateEntry`, `CheckpointForensicsBundle`, `CheckpointValidationError`, `canonical_checkpoint_payload(&CheckpointPayload) -> Vec<u8>`, `checkpoint_hash(&SyncCheckpoint) -> [u8; 32]`, `sign_checkpoint(...)`, and `verify_checkpoint(...)`.

- [ ] **Step 1: Write failing protocol and crypto tests.** Cover v1 sync JSON omitting every checkpoint field, v2 round-tripping a signed checkpoint, stable payload bytes regardless of map/input order, valid Ed25519 verification, and failure if vault ID, revision, prior hash, author device ID, commitment, or signature changes.
- [ ] **Step 2: Run the focused tests.** Run `cargo test -p umbra-protocol checkpoint` and `cargo test -p umbra-crypto checkpoint`; expect compile/test failure because the types and functions do not yet exist.
- [ ] **Step 3: Implement the smallest protocol types and crypto functions.** Add an explicit `protocol_version` validator accepting v1 and v2 only; make v2 checkpoint fields optional on v1 response decoding; encode `UMBRA-SYNC-CHECKPOINT-V1`, fixed-width revision, UUID bytes, fixed hash lengths, and sorted state entries before signing; use SHA-256 and the existing Ed25519 dependency.
- [ ] **Step 4: Run the focused tests again.** Expect both test groups to pass, including deterministic hash assertions.
- [ ] **Step 5: Commit.** `git add crates/umbra-protocol/src/lib.rs crates/umbra-crypto/src/lib.rs && git commit -m "feat(protocol): define signed sync checkpoints"`.

### Task 2: Persist opaque checkpoint history in PostgreSQL and SQLite

**Files:** Create `crates/umbra-migrations/migrations/000009_sync_checkpoints.sql` and `crates/umbra-migrations/sqlite/000009_sync_checkpoints.sql`; modify `crates/umbra-migrations/src/lib.rs`, `crates/umbra-storage/src/{models.rs,backend.rs,lib.rs,tests.rs}`, and create `crates/umbra-storage/src/{postgres,sqlite}/checkpoints.rs` plus module declarations.

**Interfaces:** Produces `CreateSyncCheckpoint`, `StoredSyncCheckpoint`, `CheckpointConflict`, and backend methods `append_sync_checkpoint(input)`, `list_sync_checkpoints_since(vault_id, revision)`, and `find_sync_checkpoint(vault_id, revision)`.

- [ ] **Step 1: Write failing SQLite storage tests.** Assert a checkpoint row stores UUIDs, revisions, commitment/hash/signature bytes, and no envelope column; a duplicate identical `(vault_id, vault_revision, checkpoint_hash)` is idempotent; a different hash at the same vault revision returns `CheckpointConflict`; ordered retrieval includes every stored checkpoint after a cursor.
- [ ] **Step 2: Run the failing test.** Run `cargo test -p umbra-storage sqlite_sync_checkpoint`; expect the storage API and migration to be absent.
- [ ] **Step 3: Add matching migrations and backend implementation.** Create an append-only `sync_checkpoints` table keyed by checkpoint hash with unique `(vault_id, vault_revision, checkpoint_hash)`, indexed revision retrieval, and an explicit same-revision lookup; use a transaction that rejects a competing hash before insert. Extend migration-count tests from 8 to 9.
- [ ] **Step 4: Add PostgreSQL parity tests/implementation.** Exercise the same backend contract against the project test database, retaining only identifiers, revisions, hashes, signatures, device IDs, and timestamps.
- [ ] **Step 5: Run `cargo test -p umbra-migrations -p umbra-storage`.** Expect migration and both-backend storage tests to pass.
- [ ] **Step 6: Commit.** `git add crates/umbra-migrations crates/umbra-storage && git commit -m "feat(storage): persist opaque sync checkpoints"`.

### Task 3: Author and transport authorized checkpoints through protocol v2

**Files:** Modify `crates/umbra-server/src/{http.rs,authz.rs,tests.rs,state.rs}` and storage model/backend call sites.

**Interfaces:** Consumes authenticated `TrustedRequestContext { user_id, device_id }`, an editor/writer membership, v2 `SyncRequest`, and a client-supplied `CreateSyncCheckpointRequest`; produces `SyncResponse { checkpoints }` and a checkpoint-creation route or sync append operation that records only metadata.

- [ ] **Step 1: Write failing Axum tests.** Add fixtures showing a v2 writer device can submit a correctly shaped signed checkpoint; a viewer, pending/revoked device, mismatched body device, and v1 request are rejected; sync returns sorted checkpoint metadata to a vault member; serialized responses and audit records omit `envelope`, `wrapping`, `plaintext`, and fixture secrets.
- [ ] **Step 2: Run `cargo test -p umbra-server checkpoint`.** Expect route/authorization failures before implementation.
- [ ] **Step 3: Implement v2-gated request handling.** Authenticate the signed HTTP device, call `ensure_vault_writer`, bind `author_device_id` to that context, persist opaque checkpoint fields via storage, append audit metadata `{vault_id, revision, checkpoint_hash, author_device_id}`, and include history since cursor in v2 sync responses. Do not allow server signature generation or verification to determine trust.
- [ ] **Step 4: Add malicious transport tests.** Simulate a server returning a lower revision, missing predecessor, and two different stored checkpoints at one revision; the server may transport each fixture, while client validation remains the decision point.
- [ ] **Step 5: Run `cargo test -p umbra-server`.** Expect server route, authorization, audit-redaction, and existing sync tests to pass.
- [ ] **Step 6: Commit.** `git add crates/umbra-server crates/umbra-storage && git commit -m "feat(server): transport authorized sync checkpoints"`.

### Task 4: Add durable client trust anchors, validation, and quarantine

**Files:** Modify `crates/umbra-cli/src/{cache.rs,sync.rs,error.rs,tests.rs}` and add focused cache/sync test modules only if existing file size requires it.

**Interfaces:** Produces `TrustedCheckpointDevice`, `VerifiedCheckpoint`, `IntegrityFinding`, `VaultIntegrityState`, `LocalCache::{record_trusted_checkpoint_device,verify_and_record_checkpoints,integrity_state,export_checkpoint_evidence}`, and `CliError::SyncIntegrity { vault_id, revision, checkpoint_id }`.

- [ ] **Step 1: Write failing LocalCache tests.** Seed trusted device public keys and a verified checkpoint; assert a valid successor is recorded atomically; assert lower revision, wrong predecessor, invalid signature, untrusted signer, mismatched commitment, and two checkpoints at one revision each create immutable evidence, leave the verified head unchanged, and set `unsafe`.
- [ ] **Step 2: Run `cargo test -p umbra-cli checkpoint_validation`.** Expect missing tables/types/validation failure.
- [ ] **Step 3: Implement cache schema and validator.** Add durable tables for trusted checkpoint devices, observed checkpoint history, verified checkpoint head, and integrity findings. Compute the state commitment from cached encrypted metadata only; verify against the local trust anchor; use one SQLite transaction to persist a valid successor and apply sync changes, or persist a finding and refuse all unsafe changes.
- [ ] **Step 4: Gate status and normal sync.** Before sync/status accepts a v2 response, validate checkpoint chain and commitment; once unsafe, return a stable safe error naming only vault ID, revision, and checkpoint hash/ID. Continue blocking even with `--force-full`; only a separately explicit investigation/export command may read evidence.
- [ ] **Step 5: Run `cargo test -p umbra-cli checkpoint`.** Expect all local validation and refusal tests to pass.
- [ ] **Step 6: Commit.** `git add crates/umbra-cli/src/cache.rs crates/umbra-cli/src/sync.rs crates/umbra-cli/src/error.rs crates/umbra-cli/src/tests.rs && git commit -m "feat(cli): reject unsafe checkpoint sync"`.

### Task 5: Expose safe integrity status and forensic export

**Files:** Modify `crates/umbra-cli/src/{main.rs,commands.rs,output.rs,tests.rs}` and, if needed, `cache.rs`.

**Interfaces:** Produces `umbra sync integrity status --vault ...` and `umbra sync integrity export --vault ... --output FILE`, emitting `CheckpointForensicsBundle` with only signed public checkpoint metadata and findings.

- [ ] **Step 1: Write failing parser/output tests.** Assert the two commands parse; human and JSON unsafe-status output contain only vault/revision/checkpoint/device IDs and an error code; exported JSON excludes known plaintext, ciphertext string, envelope, wrapping, token, and vault-key fixture values.
- [ ] **Step 2: Run `cargo test -p umbra-cli sync_integrity`.** Expect commands/output to be absent.
- [ ] **Step 3: Implement commands and secure export.** Resolve a vault using existing selectors, require an explicit destination that does not overwrite by default, serialize only `CheckpointForensicsBundle`, and make the normal `status`/`sync run` path return `CliError::SyncIntegrity` before displaying potentially unsafe state.
- [ ] **Step 4: Run the focused test group.** Expect parser, safe-error, and secret-redaction tests to pass.
- [ ] **Step 5: Commit.** `git add crates/umbra-cli/src/main.rs crates/umbra-cli/src/commands.rs crates/umbra-cli/src/output.rs crates/umbra-cli/src/tests.rs crates/umbra-cli/src/cache.rs && git commit -m "feat(cli): export sync integrity evidence"`.

### Task 6: Prove adversarial and normal multi-device behaviour end to end

**Files:** Modify `crates/umbra-server/src/tests.rs`, `crates/umbra-cli/src/tests.rs`, and only production files exposed by failing tests.

**Interfaces:** Consumes v2 sync, two independent local caches/trust anchors, signed device fixtures, checkpoint history, and encrypted-only item fixtures; produces rejection proof for rollback/equivocation and convergence proof for honest devices.

- [ ] **Step 1: Write failing end-to-end tests.** Cover: honest A/B convergence through item update/conflict resolution and successive checkpoints; server rollback from revision N to N-1; omission of checkpoint N; altered item/conflict commitment; invalid signature; and two validly signed but different same-revision checkpoints. Assert no unsafe payload is applied and the forensic bundle has both signed records where applicable.
- [ ] **Step 2: Run focused malicious tests.** Run `cargo test -p umbra-cli malicious_checkpoint` and `cargo test -p umbra-server checkpoint_equivocation`; expect failures before any uncovered integration seam is fixed.
- [ ] **Step 3: Make minimal production fixes.** Correct only canonicalization, cursor/history selection, transaction ordering, trusted-device bootstrapping, or CLI refusal behaviour directly identified by the failing test. Never fix an integrity failure by clearing cache/evidence, accepting a server key, or dropping to v1 silently.
- [ ] **Step 4: Run package tests.** Run `cargo test -p umbra-protocol -p umbra-crypto -p umbra-storage -p umbra-server -p umbra-cli`; expect all package tests to pass.
- [ ] **Step 5: Commit.** `git add crates/umbra-protocol crates/umbra-crypto crates/umbra-storage crates/umbra-server crates/umbra-cli && git commit -m "test(sync): cover rollback and equivocation checkpoints"`.

### Task 7: Document compatibility, trust limits, and migrations; run release verification

**Files:** Modify `README.md`, `docs/{architecture.md,protocol.md,threat-model.md,migrations.md}` and test/documentation references as required.

**Interfaces:** Documents v1/v2 compatibility, client-held trust anchors, checkpoint canonical payload, storage limits, integrity error behaviour, forensic export contents, operational migration procedure, and residual limitations.

- [ ] **Step 1: Write documentation assertions/checklist.** Add or extend existing doc tests/checklists to require explicit v2 negotiation, no automatic evidence-discarding recovery, no plaintext/key/envelope export, server zero-knowledge, and the limitation that a newly bootstrapped client needs an authenticated local trust-anchor transfer.
- [ ] **Step 2: Make the documentation edits.** Specify checkpoint creation authorization, server persistence semantics, PostgreSQL/SQLite migration 9, forensic workflow, and why a valid signature alone does not make an unknown device trusted.
- [ ] **Step 3: Run formatting and full verification.** Run `cargo fmt --all`, `cargo clippy --all-targets --all-features -- -D warnings`, `cargo test --all`, and `git diff --check`; expect exit code 0 from every command.
- [ ] **Step 4: Commit.** `git add README.md docs && git commit -m "docs: describe sync integrity checkpoints"`.

## Self-Review

- Scope coverage: Task 1 defines signed commitments and version gating; Task 2 stores them on both backends; Task 3 adds authorized server transport/audit; Task 4 persists client verification/evidence and blocks unsafe sync; Task 5 supplies safe status/export; Task 6 proves rollback/equivocation rejection and honest convergence; Task 7 records architecture/protocol/limitations and runs required checks.
- No-plaintext review: every checkpoint and forensic field is an identifier, revision, state hash, checkpoint hash, signer ID, public key fingerprint, or signature. Envelopes and wrappings are hashed for commitment and never emitted as evidence.
- Type consistency: `SyncCheckpoint` is the protocol record, `StoredSyncCheckpoint` is the storage record, `VerifiedCheckpoint` is the local trusted head, and `CheckpointForensicsBundle` is the redacted CLI export.
