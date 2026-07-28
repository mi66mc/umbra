# Encrypted Local Cache Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Persist the Umbra CLI SQLite cache as a whole, versioned authenticated encrypted snapshot with a key held only in the local OS keychain.

**Architecture:** Keep the cache schema and query API in an in-memory SQLite connection. Serialize only after committed mutations, encrypt bytes using Umbra's XChaCha20-Poly1305 local envelope bound to profile/version AAD, and atomically replace `cache.enc`. Detect legacy plaintext `cache.db` and fail closed without modifying it.

**Tech Stack:** Rust 2024, rusqlite `serialize`, `umbra-crypto` XChaCha20-Poly1305 envelopes, OS keyring, tempfile.

## Global Constraints

- The server remains zero-knowledge; cache key, SQLite bytes and plaintext never leave the CLI.
- Persistent cache format is versioned and AEAD authenticated.
- Cache key must never be persisted outside the OS keychain.
- Legacy cache detection preserves the source file and fails safely.
- Do not weaken RUSTSEC-2023-0071 gate or change RSA/release policy.

---

### Task 1: Encrypted snapshot primitives

**Files:**
- Modify: `crates/umbra-cli/Cargo.toml`
- Modify: `crates/umbra-cli/src/cache.rs`
- Test: `crates/umbra-cli/src/cache.rs`

**Interfaces:**
- Produces: encrypted `LocalCache::open`, `LocalCache::open_path`, test-injected key store, and atomic snapshot persistence.

- [ ] **Step 1: Write a failing reopen/artifact test**

```rust
#[test]
fn persisted_cache_reopens_without_plaintext_artifacts() {
    let (path, keys) = test_cache_path_and_key_store();
    let cache = LocalCache::open_path_with_key_store("personal", path.clone(), keys.clone()).unwrap();
    cache.upsert_vault(&fixture_vault("fixture-plaintext")).unwrap();
    let bytes = std::fs::read(path.with_file_name("cache.enc")).unwrap();
    assert!(!bytes.windows(b"fixture-plaintext".len()).any(|v| v == b"fixture-plaintext"));
    assert_eq!(LocalCache::open_path_with_key_store("personal", path, keys).unwrap().list_vaults().unwrap().len(), 1);
}
```

- [ ] **Step 2: Verify RED**

Run: `cargo test -p umbra-cli cache::tests::persisted_cache_reopens_without_plaintext_artifacts`

Expected: compile failure because encrypted constructors do not exist.

- [ ] **Step 3: Implement minimal persistence**

```rust
let bytes = self.connection.serialize(DatabaseName::Main)?;
let envelope = encrypt_local_unlock_state(&key, self.cache_aad(), &bytes)?;
write_atomic(&self.encrypted_path, serde_json::to_vec(&PersistedCacheV1 { version: 1, envelope })?)
```

Use versioned `cache:v1:<base64url(profile)>` keyring account, `Connection::deserialize` for load, and a same-directory randomized temporary file.

- [ ] **Step 4: Verify GREEN and commit**

Run: `cargo test -p umbra-cli cache::tests`

Expected: PASS.

```bash
git add crates/umbra-cli/Cargo.toml crates/umbra-cli/src/cache.rs Cargo.lock
git commit -m "feat(cli): encrypt local cache snapshots"
```

### Task 2: Closed failures and recovery

**Files:**
- Modify: `crates/umbra-cli/src/cache.rs`
- Test: `crates/umbra-cli/src/cache.rs`

**Interfaces:**
- Consumes: Task 1 persistence and key store.
- Produces: explicit legacy/key/corruption failure handling and `LocalCache::clear_persistent`.

- [ ] **Step 1: Write failing behavior tests**

```rust
#[test] fn legacy_cache_is_left_untouched_and_refused() { /* create cache.db; assert error and unchanged bytes */ }
#[test] fn absent_wrong_key_and_tampering_fail_closed() { /* remove/replace key, then alter artifact; assert errors */ }
#[test] fn failed_promotion_keeps_previous_snapshot() { /* inject promotion failure; assert old artifact reopens */ }
#[test] fn clear_removes_snapshot_and_cache_key() { /* persist, clear, assert both absent */ }
```

- [ ] **Step 2: Verify RED**

Run: `cargo test -p umbra-cli cache::tests::legacy_cache_is_left_untouched_and_refused`

Expected: FAIL because the legacy cache is currently opened.

- [ ] **Step 3: Implement precise recovery behavior**

```rust
if legacy_path.exists() && !encrypted_path.exists() {
    return Err(CliError::Input("legacy plaintext cache detected; back it up, remove it intentionally, then sync again"));
}
```

Reject absent/wrong keys and malformed/version-mismatched envelopes without deletion. Clear only known `cache.enc` and its matching credential.

- [ ] **Step 4: Verify GREEN and commit**

Run: `cargo test -p umbra-cli cache::tests`

Expected: PASS.

```bash
git add crates/umbra-cli/src/cache.rs
git commit -m "fix(cli): fail closed for encrypted cache recovery"
```

### Task 3: Intentional cleanup and operations documentation

**Files:**
- Modify: `crates/umbra-cli/src/main.rs`
- Modify: `crates/umbra-cli/src/commands.rs`
- Modify: `crates/umbra-cli/src/tests.rs`
- Modify: `README.md`, `docs/architecture.md`, `docs/threat-model.md`

**Interfaces:**
- Consumes: `LocalCache::clear_persistent(profile)`.
- Produces: `umbra cache clear`.

- [ ] **Step 1: Write failing parser test**

```rust
#[test]
fn parses_cache_clear_command() {
    assert!(matches!(Cli::parse_from(["umbra", "cache", "clear"]).command, Command::Cache(CacheCommand::Clear)));
}
```

- [ ] **Step 2: Verify RED, implement and verify GREEN**

Run: `cargo test -p umbra-cli parses_cache_clear_command`

Expected before implementation: compile failure. Add `CacheCommand::Clear` and a handler that calls `LocalCache::clear_persistent(&config.active_profile)`; expected after implementation: PASS.

- [ ] **Step 3: Document exact operational boundary**

Document `cache.enc`, keychain key storage, fail-closed recovery, intentional `cache clear`, legacy recovery, and malware/keychain/process-memory limits in README, architecture and threat model.

- [ ] **Step 4: Verify and commit**

Run: `cargo test -p umbra-cli && cargo fmt --all --check && cargo clippy -p umbra-cli --all-targets -- -D warnings`

Expected: PASS.

```bash
git add README.md docs crates/umbra-cli/src
git commit -m "docs(cli): document encrypted local cache recovery"
```

### Task 4: Final verification, review, and delivery

**Files:** no source changes expected.

- [ ] **Step 1: Run required verification**

Run: `cargo fmt --all --check; cargo test --all; cargo build; cargo clippy --all-targets --all-features -- -D warnings; cargo deny check advisories; git diff --check`

Expected: all engineering gates pass. The existing RUSTSEC-2023-0071 advisory remains a release block and is neither suppressed nor excepted.

- [ ] **Step 2: Self-review**

Inspect the full diff for plaintext persistence, key serialization, server requests, error paths, atomic promotion, test evidence and documentation consistency. Correct every material finding.

- [ ] **Step 3: Push and open review**

```bash
git push -u origin HEAD
gh pr create --base main --title "feat(cli): encrypt local cache at rest"
```

## Self-Review

Task 1 covers normal/offline encrypted persistence and artifact secrecy. Task 2 covers legacy, absent/wrong key, tampering, write rollback and cleanup. Task 3 covers the operator workflow and required documentation. Task 4 preserves formatting, tests, clippy, and the advisory gate. All interfaces are introduced in the task that needs them; no implementation is deferred.

