# Device-Scoped Vault Wrapping Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Make every active vault key envelope address one approved device encryption key, preventing pending or revoked devices from receiving or decrypting subsequent generations while preserving a zero-knowledge server.

**Architecture:** Add an X25519 encryption public key to every device and retain the matching private key only in that device profile. Require device-addressed wrapping records (`device_id` non-null, `wrapping_type = "device_public_key"`) for all new vault creation, membership grants, invite acceptance, approval distribution, and rotation. The server validates only identity/state/membership/target-device consistency and persists opaque envelopes; it never unwraps, rewraps, logs, or commits envelope bytes. Sync filters envelopes to its authenticated trusted device. A protocol-v3 checkpoint commitment includes deterministic hashes of authorized device-wrapping metadata, so clients reject omission/substitution of the key-distribution state.

**Tech Stack:** Rust 2024, Axum, SQLx PostgreSQL/SQLite, rusqlite encrypted CLI cache, X25519/ChaCha20-Poly1305, Ed25519 checkpoints, OPAQUE sessions.

## Global Constraints

- Keep PostgreSQL and SQLite migrations/implementations behaviorally equivalent; do not remove PostgreSQL.
- Keep the release blocked by `RUSTSEC-2023-0071`; do not add advisories, ignores, or dependency-policy exceptions.
- All vault keys, device encryption private keys, plaintext items, and envelope bodies remain client-only; logs/audit/checkpoints/cache diagnostics contain only IDs, state, generations, wrapping metadata, and SHA-256 hashes.
- A pending or revoked device receives no key wrapping through sync, bootstrap, invite acceptance, rotation, or list endpoints; its existing local key/cache cannot be remotely erased.
- Revocation and member removal set `needs_key_rotation`; owners must rotate after compromise to exclude material already seen. Rotation writes envelopes only for active member devices.
- Legacy user-scoped/`device_id = NULL` records are never silently accepted as a device key. Protocol v1/v2 clients may read existing data but cannot unlock a vault lacking an envelope for their own device; protocol v3 is required for all writes that create key material.
- Checkpoint v3 is fail-closed: missing, non-device-scoped, wrong-device, duplicate, inactive-device, altered metadata, or altered wrapping hash is an integrity error and applies no sync state.

## File structure

- `crates/umbra-protocol/src/lib.rs`: protocol v3, device encryption-key fields, device-addressed vault-wrapping request/response records, and checkpoint wrapping-commitment fields.
- `crates/umbra-crypto/src/{lib.rs,checkpoints.rs}`: domain-separated device wrapping AAD and canonical metadata/hash commitment encoding.
- `crates/umbra-migrations/{migrations,sqlite}/000010_device_scoped_vault_wrappings.sql`: non-secret device encryption public key plus device-scoped wrapping constraints/indexes.
- `crates/umbra-migrations/src/lib.rs`: migration version 10 test coverage.
- `crates/umbra-storage/src/{models.rs,backend.rs,postgres/{devices.rs,vaults.rs,convert.rs,invites.rs},sqlite/{devices.rs,vaults.rs,convert.rs,invites.rs},tests.rs}`: target-device validation queries, state-aware filtering, atomic approval distribution and rotation persistence.
- `crates/umbra-server/src/{http.rs,tests.rs}`: trusted-device-bound authorization and opaque transport/audit behavior.
- `crates/umbra-cli/src/{config.rs,commands.rs,sync.rs,cache.rs,tests.rs}`: local device X25519 key lifecycle, client-only rewrapping, own-device lookup/unlock, v3 wrapping/checkpoint validation, two-device integration fixtures.
- `README.md`, `docs/{architecture.md,protocol.md,threat-model.md,operations.md}`: protocol, recovery/revocation, migration, emergency-kit, and operational rotation procedure.

### Task 1: Define protocol-v3 and device-key crypto contract

**Files:** Modify `crates/umbra-protocol/src/lib.rs`, `crates/umbra-crypto/src/lib.rs`, `crates/umbra-crypto/src/checkpoints.rs`; test in their existing module test blocks.

**Interfaces:** Produce `DEVICE_SCOPED_WRAPPING_PROTOCOL_VERSION: u16 = 3`, `DeviceEncryptionKey { public_key: String }`, `DeviceResponse { encryption_public_key: Option<String> }`, `DeviceRegisterRequest { encryption_public_key: String }`, `PendingDeviceRequest { encryption_public_key: String }`, `VaultKeyWrappingResponse { device_id: DeviceId }`, `RotationVaultKeyWrapping { device_id: DeviceId }`, `AadV1::device_vault_key_wrapping(vault_id, device_id, generation)`, and `device_wrapping_commitment(entries) -> String`.

- [ ] **Step 1: Write failing protocol/crypto tests.** Serialize/deserialize v3 registration, pending-device, create-vault, invite, and rotation payloads with a required encryption public key/device ID; reject v3 wrapping records with null `device_id`, `user_public_key`, invalid Base64Url key, or invalid generation. Assert the wrapping AAD differs by vault, recipient device, and generation. Assert canonical metadata hashes are stable after input ordering changes and change when device ID, key generation, wrapping type, or envelope hash changes.
- [ ] **Step 2: Run focused tests.** Run `cargo test -p umbra-protocol device_scoped` and `cargo test -p umbra-crypto device_wrapping`; expect failures because protocol v3 fields/commitment do not exist.
- [ ] **Step 3: Implement minimal contract.** Add supported version 3 without changing v1/v2 JSON defaults; add strict v3 validators used by server routes. Define domain-separated `UMBRA-DEVICE-VAULT-WRAPPING-V1` AAD using UUID bytes and big-endian generation. Hash serialized envelope bytes into the commitment rather than returning envelope bytes.
- [ ] **Step 4: Run focused tests.** Run the commands from step 2; expect PASS.
- [ ] **Step 5: Commit.** `git add crates/umbra-protocol crates/umbra-crypto && git commit -m "feat(protocol): define device-scoped vault wrapping"`.

### Task 2: Persist device encryption identities and constrained opaque wrappings

**Files:** Create the two `000010_device_scoped_vault_wrappings.sql` migrations; modify migration library, storage models/backend/converters/devices/vaults/invites/tests.

**Interfaces:** Produce `DeviceRecord.encryption_public_key: Option<String>`, `CreateDevice.encryption_public_key: Option<String>`, `list_active_devices_for_user(user_id)`, `list_active_member_devices(vault_id)`, `list_key_wrappings_for_device_vault(user_id, device_id, vault_id)`, and `CreateVaultKeyWrapping { device_id: DeviceId, wrapping_type: "device_public_key" }` for v3 paths.

- [ ] **Step 1: Write failing storage tests for both backends.** Seed two trusted devices and one pending/revoked device. Assert an active user/device/vault-member target can store/retrieve only its own envelope; other devices, pending devices, revoked devices, cross-user targets, and null device IDs are rejected. Assert revoking a device marks its rows unavailable and member removal marks rotation required. Assert invite acceptance creates no user-scoped envelope. Assert storage/audit serialized fixtures do not contain envelope plaintext fixture strings outside the opaque wrapping column.
- [ ] **Step 2: Run focused tests.** Run `cargo test -p umbra-storage device_scoped` and `cargo test -p umbra-migrations embeds_postgres_and_sqlite_migrations`; expect missing migration/API failures.
- [ ] **Step 3: Implement migrations and queries.** Add nullable `devices.encryption_public_key` for legacy rows, `vault_key_wrappings` indexes on `(vault_id,user_id,device_id,key_generation)`, and database checks that v3 records are device scoped. Use joins against active device and active membership for retrieval; never select legacy/null-device rows through device-scoped retrieval. Make removal/revocation transactional with access revision/rotation updates.
- [ ] **Step 4: Run focused tests.** Re-run step 2 and repeat selected tests under PostgreSQL using the repository integration configuration; expect PASS.
- [ ] **Step 5: Commit.** `git add crates/umbra-migrations crates/umbra-storage && git commit -m "feat(storage): scope vault envelopes to active devices"`.

### Task 3: Enforce server-side distribution authorization and sync filtering

**Files:** Modify `crates/umbra-server/src/http.rs` and `crates/umbra-server/src/tests.rs`.

**Interfaces:** Consume authenticated `TrustedRequestContext { user_id, device_id }`; produce v3 create/add/invite/approve/rotate handlers that accept envelopes only for active intended devices, `sync` that calls `list_key_wrappings_for_device_vault`, and checkpoint records that bind `wrapping_commitment`.

- [ ] **Step 1: Write failing Axum tests.** Cover initial vault creation yielding exactly the current device envelope; approval only accepting envelopes addressed to the approved device; two trusted devices syncing only their own envelope; pending/revoked caller or target rejected; member invite/accept creating target-member-device envelopes only; member removal/revocation requiring rotation; rotation rejecting missing/duplicate/inactive-device targets; and responses/audits excluding raw envelope, plaintext, vault key, private key, and fixture secret.
- [ ] **Step 2: Run focused tests.** Run `cargo test -p umbra-server device_scoped`; expect route/authorization failures.
- [ ] **Step 3: Implement minimal authorization.** Bind every target device to the intended user and required state, require the authenticated device to be trusted, require vault owner/admin role for distribution/rotation, and use transaction-safe storage methods. On `sync`, authorize membership then return only envelopes for `context.device_id`. Audit only action, vault/device IDs, generations, count, and commitment hash. Do not parse, log, decrypt, or validate envelope contents.
- [ ] **Step 4: Bind checkpoint integrity.** For protocol v3, compute/store/return the deterministic wrapping metadata commitment alongside the existing encrypted-item commitment; reject v3 checkpoint creation without the field. Leave v1/v2 checkpoint behavior unchanged.
- [ ] **Step 5: Run focused tests and commit.** Run `cargo test -p umbra-server device_scoped`; then `git add crates/umbra-server && git commit -m "feat(server): authorize device-scoped key distribution"`.

### Task 4: Implement client device-key lifecycle, local rewrapping, and fail-closed unlock

**Files:** Modify `crates/umbra-cli/src/config.rs`, `commands.rs`, `sync.rs`, `cache.rs`, and tests.

**Interfaces:** Produce `ProfileConfig.device_encryption_private_key`, `device_encryption_public_key(profile)`, `wrap_vault_key_for_device(recipient, vault_id, device_id, generation)`, `latest_key_wrapping_for_device(vault_id, user_id, device_id)`, and `build_device_scoped_rotation_request(...)`.

- [ ] **Step 1: Write failing CLI tests.** Assert register/new-device generates and persists a distinct X25519 device key, only public key reaches protocol fixtures, bootstrap retains the pending device key only locally, unlock rejects account/user-scoped legacy wrapping and wrong-device AAD, cache lookup does not return another device's record, and config/debug/cache status never print device private key or envelope contents.
- [ ] **Step 2: Run focused tests.** Run `cargo test -p umbra-cli device_scoped`; expect compilation/test failures.
- [ ] **Step 3: Implement key lifecycle.** Generate the X25519 keypair at initial registration and `login --new-device`; preserve a pending key through bootstrap and promote it after success. Keep it redacted in `Debug`, never export it in the emergency kit, and use it solely for vault-envelope unwrap. Change create-vault, add-member, invite acceptance, device approval, and rotation to enumerate active member devices and wrap locally with recipient device key/AAD.
- [ ] **Step 4: Implement fail-closed compatibility.** When a legacy cache/server response offers no envelope for the current device, return a specific migration/security error directing the user to approve/re-enroll the device from a trusted device; never fall back to account private key. Emergency-kit recovery creates a fresh pending device encryption key and requires approval, so it receives no vault material until trusted.
- [ ] **Step 5: Run focused tests and commit.** Run `cargo test -p umbra-cli device_scoped`; then `git add crates/umbra-cli && git commit -m "feat(cli): unwrap vault keys per trusted device"`.

### Task 5: Validate protocol-v3 sync/checkpoint metadata and adversarial flows

**Files:** Modify `crates/umbra-cli/src/{sync.rs,cache.rs,tests.rs}`, `crates/umbra-crypto/src/checkpoints.rs`, `crates/umbra-server/src/tests.rs` as required.

**Interfaces:** Produce `validate_device_wrapping_commitment(vault_id, device_id, changes, checkpoint)` and persisted integrity evidence containing IDs/generation/hash only.

- [ ] **Step 1: Write failing two-device integration tests.** Create a vault on device A, approve B with a device-targeted envelope, sync both devices, and prove A/B decrypt their own generation. Revoke B, then verify B cannot sync/login/unlock new generation and A rotates/re-encrypts only A/remaining active devices. Add member invite/accept then remove-member/rotate scenario, pending-device access attempt, emergency-kit recovery pending attempt, and legacy wrapping migration refusal.
- [ ] **Step 2: Add corruption/tampering tests.** Alter a target device ID, generation, wrapping type, envelope hash, checkpoint wrapping commitment, or sync order; assert atomic rejection, unchanged cache head, redacted evidence, and no plaintext/secret fixture in cache/sync/audit/log output.
- [ ] **Step 3: Run focused tests.** Run `cargo test -p umbra-cli device_scoped_sync` and `cargo test -p umbra-server device_scoped`; expect failures for uncovered integration seams.
- [ ] **Step 4: Implement only test-identified fixes.** Verify wrapping commitment before applying v3 sync changes, store only hashes in integrity evidence, invalidate old local generation after a successful rotation, and prevent cached wrong-device entries from satisfying unlock. Do not downgrade to v1/v2 or clear integrity evidence.
- [ ] **Step 5: Run tests and commit.** Re-run step 3; then `git add crates/umbra-cli crates/umbra-crypto crates/umbra-server && git commit -m "test(sync): cover device-scoped envelope security"`.

### Task 6: Document architecture, operations, and residual risk

**Files:** Modify `README.md`, `docs/architecture.md`, `docs/protocol.md`, `docs/threat-model.md`; create or modify `docs/operations.md`.

**Interfaces:** Document protocol v3 device-envelope schema/AAD/commitment, trust states, migration behavior, user/device/member lifecycle, recovery procedure, and incident rotation runbook.

- [ ] **Step 1: Write documentation assertions in prose-oriented tests/checklist.** Verify each document explicitly says: server stores opaque device envelopes only; pending/revoked devices do not receive new envelopes; revocation cannot erase previously viewed data; rotation is required after compromise/removal; recovery remains pending until approval; legacy records fail closed; no plaintext/log/audit/cache leakage; and PostgreSQL/SQLite migration 10 is required.
- [ ] **Step 2: Edit documentation.** Add exact CLI/operator sequence for approving a new device, revoking and rotating affected vaults, member removal, and recovery from emergency kit. Include the existing RUSTSEC release block unchanged.
- [ ] **Step 3: Review docs and commit.** Run `rg -n "TBD|TODO|plaintext vault key|ignore.*RUSTSEC|advisory" README.md docs`; manually inspect all new claims against implementation; then `git add README.md docs && git commit -m "docs: document device-scoped vault key distribution"`.

### Task 7: Full verification and self-review

**Files:** All changed files; no feature changes unless a verification failure identifies a minimal direct fix.

- [ ] **Step 1: Format and lint.** Run `cargo fmt --check` then `cargo clippy --workspace --all-targets -- -D warnings`; fix only reported issues and repeat until both pass.
- [ ] **Step 2: Run all supported-backend tests.** Run `cargo test --workspace`; run the repository PostgreSQL integration test command/environment and the SQLite storage/migration suite. Confirm both migrations are embedded/version 10 and PostgreSQL remains enabled.
- [ ] **Step 3: Security self-review.** Inspect every change involving `envelope`, `wrapping`, `vault_key`, `private_key`, `audit`, `tracing`, cache exports, and checkpoint evidence. Confirm no logs/metadata contain raw envelope or secret, every sync envelope filters by authenticated trusted device, every v3 unwrap binds device/generation AAD, and no legacy fallback weakens the gate.
- [ ] **Step 4: Review diff and commit any direct corrections.** Run `git diff main...HEAD --check` and `git status --short`; address whitespace or directly identified omissions, then commit with a precise conventional message.
- [ ] **Step 5: Push and open PR.** Push the feature branch and create a PR against `main` summarizing the device-scoped envelope boundary, migrations, compatibility failure mode, test results, and unchanged RUSTSEC-2023-0071 release gate.

## Plan self-review

- Coverage: Tasks 1-5 implement registration/vault creation/bootstrap/approval/two-device sync/invites/membership/revocation/removal/rotation/recovery/legacy compatibility/checkpoints and both storage backends. Task 6 covers every requested public/security/operational document. Task 7 covers formatting, lint, tests, review, push, and PR.
- No placeholders: every task names concrete files, interfaces, commands, expected test direction, and commit boundary.
- Type consistency: `DeviceId` is required from request through `CreateVaultKeyWrapping`, storage retrieval, sync filtering, cache lookup, AAD, rotation, and v3 checkpoint commitment.
