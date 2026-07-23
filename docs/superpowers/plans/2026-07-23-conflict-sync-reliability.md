# Conflict Sync Reliability Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Prove and harden encrypted item-conflict handling across offline devices, explicit resolution, ordinary synchronization, and zero-plaintext boundaries.

**Architecture:** Preserve the existing split: `item_conflicts` holds only server-side ciphertext metadata, while the CLI decrypts only locally for show/merge. Tests first define storage, HTTP, cache, and two-device contracts; code changes are limited to the seam exposed by a failing test.

**Tech Stack:** Rust, Tokio, Axum, SQLx (PostgreSQL/SQLite), Rusqlite, Clap, Serde JSON, Cargo.

## Global Constraints

- Never place item plaintext, vault keys, passwords, tokens, or secrets in server storage, HTTP bodies, audit metadata, cache, logs, or examples.
- Do not add automatic merge, last-write-wins, conflict copying, Redis, or distributed rate limiting.
- Update conflicts use `remote`, `local`, or `merge`; delete conflicts use `remote` or `local` only.
- Viewers list/show but never resolve; writers resolve only with the current revision precondition.
- Before integration run `cargo fmt --all -- --check`, `cargo check --workspace`, `cargo test --workspace`, and `git diff --check`.

---

## File Structure

- `crates/umbra-storage/src/tests.rs`: transaction and resolution regressions.
- `crates/umbra-server/src/tests.rs`: signed HTTP authorization, typed `409`, sync, and two-device coverage.
- `crates/umbra-cli/src/cache.rs`: atomic conflict-cache replacement and redaction tests.
- `crates/umbra-cli/src/{commands.rs,tests.rs}`: parser and local manual-merge behavior tests.
- `crates/umbra-storage/src/{postgres,sqlite}/conflicts.rs`, `crates/umbra-server/src/http.rs`, and `crates/umbra-cli/src/sync.rs`: alter only when a failing test identifies a defect.

### Task 1: Lock down conflict storage transactions

**Files:** `crates/umbra-storage/src/tests.rs`; if required, `crates/umbra-storage/src/postgres/conflicts.rs` and `crates/umbra-storage/src/sqlite/conflicts.rs`.

**Interfaces:** consumes `create_item_conflict(CreateItemConflict)`, `resolve_item_conflict(ResolveItemConflict)`, and `list_open_item_conflicts(VaultId)`; produces atomic candidate closure and vault revision change for remote resolution.

- [ ] Add `sqlite_remote_conflict_resolution_advances_vault_revision`: create revision 1, advance it to 2, create an update candidate based on 1, record vault revision, resolve `remote`, and assert no returned item revision, no open candidates, and a higher vault revision.
- [ ] Run `cargo test -p umbra-storage sqlite_remote_conflict_resolution_advances_vault_revision`; expected PASS if current behavior is correct, otherwise failure on vault revision.
- [ ] Add local-update resolution coverage: candidate envelope `json!({"ciphertext":"candidate"})` becomes revision `current + 1`, returns the identical ciphertext, and closes every candidate for the item.
- [ ] Add local-delete coverage: selected delete candidate returns a deletion and `list_deleted_item_ids_since` returns the item.
- [ ] If a test fails, retain all resolution state changes inside the existing transaction. The selected candidate becomes `resolved`, other open candidates become `discarded`, and remote resolution increments `vaults.vault_revision` in that same transaction. Never store a decrypted envelope.
- [ ] Run `cargo test -p umbra-storage`; expected PASS. Commit with `git add crates/umbra-storage/src/tests.rs crates/umbra-storage/src/postgres/conflicts.rs crates/umbra-storage/src/sqlite/conflicts.rs` then `git commit -m "test(storage): cover conflict resolution outcomes"`.

### Task 2: Verify HTTP conflict contract and authorization

**Files:** `crates/umbra-server/src/tests.rs`; if required, `crates/umbra-server/src/http.rs`.

**Interfaces:** consumes item update/delete, conflict list/get/resolve, `/api/v1/sync`, and `/api/v1/sync/status`; produces typed ciphertext-only `409`, correct viewer/writer authorization, and resolution visibility during normal sync.

- [ ] Add `stale_update_returns_encrypted_conflict_candidate`: signed client creates item revision 1, advances to 2, submits `expected_revision: 1` with `json!({"ciphertext":"candidate"})`, asserts HTTP `409`, base `1`, current `2`, the ciphertext envelope, and no `plaintext` key in serialized response.
- [ ] Run `cargo test -p umbra-server stale_update_returns_encrypted_conflict_candidate`; expected PASS.
- [ ] Add an active viewer and editor. Assert viewer list/get are `200`, viewer resolve is `403`, and editor resolve succeeds.
- [ ] Submit a stale delete and assert `candidate_kind == "delete"`, no candidate envelope, and a `merge` request returns `400`.
- [ ] Add normal-sync convergence: after remote resolution, `/sync/status` queried from the old vault revision reports `items_changed`; `/sync` returns `VaultSyncChanges.conflicts.is_empty()` without force-full sync.
- [ ] Run `cargo test -p umbra-server`; expected PASS. Commit with `git add crates/umbra-server/src/tests.rs crates/umbra-server/src/http.rs` then `git commit -m "test(server): cover encrypted conflict synchronization"`.

### Task 3: Verify encrypted cache and CLI behavior

**Files:** `crates/umbra-cli/src/cache.rs`, `crates/umbra-cli/src/tests.rs`; if required, `crates/umbra-cli/src/commands.rs` and `crates/umbra-cli/src/sync.rs`.

**Interfaces:** consumes `LocalCache::apply_sync_changes`, `list_item_conflicts`, `item_conflict`, and `ConflictCommand::{List,Show,Resolve}`; produces atomic cache replacement, no-plaintext list output, and local-only manual merge ciphertext.

- [ ] Add `sync_replaces_open_conflicts_atomically`: seed one conflict, sync a different conflict and assert only the replacement remains, then sync `conflicts: vec![]` and assert no row remains.
- [ ] Run `cargo test -p umbra-cli sync_replaces_open_conflicts_atomically`; expected PASS. If it fails, retain delete-and-insert work inside `LocalCache::apply_sync_changes`' existing transaction.
- [ ] Extend parser coverage for `conflict list`, `conflict show <uuid> --vault Personal`, `--use remote`, and `--merge-from local --field NAME=VALUE --remove-field NAME --title T --notes N`.
- [ ] Test human and JSON list output contain IDs, revisions, kind, and state but never candidate envelope values or plaintext fields.
- [ ] Add a manual-merge test: decrypt a remote cached revision and local candidate in the test process only, apply `set_plaintext_field` and `remove_plaintext_field`, construct the final `ItemEnvelopeWrapper`, and assert serialized post data includes its ciphertext wrapper but not `"secret-value"`.
- [ ] Run `cargo test -p umbra-cli`; expected PASS. Commit with `git add crates/umbra-cli/src/cache.rs crates/umbra-cli/src/tests.rs crates/umbra-cli/src/commands.rs crates/umbra-cli/src/sync.rs` then `git commit -m "test(cli): harden conflict cache and commands"`.

### Task 4: Prove two-device convergence

**Files:** `crates/umbra-server/src/tests.rs`; alter cache/storage/server production files only if the regression exposes the responsible seam.

**Interfaces:** consumes signed request helpers, two isolated caches, `SyncRequest`, `UpdateItemRequest`, and `ResolveItemConflictRequest`; produces proof that both devices reach the same revision with zero cached open conflicts.

- [ ] Add `two_devices_converge_after_conflict_resolution` with this sequence: A/B cache revision 1; A updates to 2 and syncs; B submits an update from 1 and receives `409`; A/B sync and receive the candidate; A resolves using expected revision 2; both execute normal sync-status plus sync; both caches share the latest revision and have no conflicts.
- [ ] Use only `json!({"ciphertext": ...})` envelopes in server fixtures. Do not use item plaintext in audit, cache, log, or request assertions.
- [ ] Run `cargo test -p umbra-server two_devices_converge_after_conflict_resolution`; expected PASS.
- [ ] If it fails, correct only storage revision increment, sync-status reporting, sync response, or transactional cache replacement. Never solve it by forcing a full sync.
- [ ] Run `cargo test -p umbra-server two_devices_converge_after_conflict_resolution` and `cargo test -p umbra-cli sync_replaces_open_conflicts`; expected both PASS. Commit with `git add crates/umbra-server/src/tests.rs crates/umbra-cli/src/cache.rs crates/umbra-server/src/http.rs crates/umbra-storage/src/postgres/conflicts.rs crates/umbra-storage/src/sqlite/conflicts.rs` then `git commit -m "test(sync): prove conflict convergence across devices"`.

### Task 5: Documentation and release gate

**Files:** `README.md` and `docs/protocol.md` only if verification exposes a contract mismatch.

**Interfaces:** consumes verified CLI/HTTP behavior; produces accurate explicit-preservation/manual-merge docs and a clean release gate.

- [ ] Confirm README covers `list`, `show`, `--use local|remote`, `--merge-from`, no automatic merge, and delete limitations. Confirm protocol docs list typed `409`, ciphertext-only candidate transport, and all three conflict routes.
- [ ] Make only behavior-correction edits; do not add speculative roadmap claims.
- [ ] Run `cargo fmt --all -- --check`, `cargo check --workspace`, `cargo test --workspace`, and `git diff --check`; expected exit code `0` from every command.
- [ ] If docs changed, commit with `git add README.md docs/protocol.md` then `git commit -m "docs: clarify encrypted conflict resolution"`.

## Self-Review

- Spec coverage: Task 1 covers transactions; Task 2 covers HTTP/authorization; Task 3 covers cache/CLI secrecy; Task 4 proves two-device convergence; Task 5 verifies docs and release quality.
- Placeholder scan: every task specifies files, assertions, commands, expected results, and commit scope.
- Type consistency: storage uses `CreateItemConflict`/`ResolveItemConflict`, protocol uses `ItemConflictResponse`/`ResolveItemConflictRequest`, cache sync uses `VaultSyncChanges`, and CLI uses `ConflictCommand`.
