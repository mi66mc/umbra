# Release Audit Unblock Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Remove SQLx's unused macro dependency path so the workspace release passes `cargo audit` without weakening PostgreSQL, SQLite, migrations, or Umbra's zero-knowledge boundary.

**Architecture:** SQLx is declared once in the workspace manifest. Removing only its `macros` feature prevents Cargo from resolving `sqlx-macros-core`, `sqlx-mysql`, and its vulnerable `rsa` transitive dependency while retaining the runtime and both database drivers. CI will make the release gates reproducible, and operator documentation will state the same gates and safe strict-doctor fixture.

**Tech Stack:** Rust 1.88, Cargo, SQLx 0.8, PostgreSQL 17, SQLite, GitHub Actions, cargo-audit.

## Global Constraints

- Keep SQLx features `runtime-tokio-rustls`, `postgres`, `sqlite`, `uuid`, `chrono`, `json`, and `migrate` exactly enabled.
- Remove only the SQLx `macros` feature; do not remove PostgreSQL support or introduce audit exceptions, allowlists, ignores, or `--ignore` flags.
- Preserve the server's zero-knowledge boundary: no plaintext secrets, vault keys, passwords, private keys, or decrypted items are introduced into server code, logs, fixtures, or documentation.
- Run real PostgreSQL tests with `UMBRA_TEST_DATABASE_URL`; SQLite tests are supplementary, not a substitute.
- Required final release gates: `cargo fmt --check`, `cargo build --workspace`, `cargo test --workspace`, `cargo clippy --workspace --all-targets -- -D warnings`, `cargo audit`, `cargo tree -i rsa@0.9.10`, and `cargo tree -i sqlx-mysql`.

---

### Task 1: Establish the dependency and SQLx-macro baseline

**Files:**
- Inspect: `Cargo.toml`, `Cargo.lock`, all Rust sources, `.github/workflows/ci.yml`
- Create: `docs/superpowers/plans/2026-07-29-release-audit-unblock.md`

**Interfaces:**
- Consumes: Cargo's resolved dependency graph and workspace SQLx dependency.
- Produces: recorded commands that demonstrate the pre-change `rsa` chain (when present) and confirm no compile-time SQLx macro call sites.

- [ ] **Step 1: Inspect the workspace SQLx feature declaration**

Run: `rg -n 'sqlx =|macros' Cargo.toml Cargo.lock`

Expected: workspace SQLx has the `macros` feature and the lockfile contains SQLx macro packages before resolution changes.

- [ ] **Step 2: Capture the vulnerable inverse dependency chain**

Run: `cargo tree -i rsa@0.9.10`

Expected: Cargo prints the inverse path through `sqlx-mysql` when that resolved package exists; otherwise it prints no package, which is the already-unblocked baseline that subsequent lockfile checks must preserve.

- [ ] **Step 3: Search all Rust sources for SQLx compile-time macros**

Run: `rg -n 'query(_as|_file|_file_as)?!' crates`

Expected: no matches. Runtime `sqlx::query` calls are not changed.

- [ ] **Step 4: Record the release plan**

Run: `git diff --check -- docs/superpowers/plans/2026-07-29-release-audit-unblock.md`

Expected: exit 0 with no whitespace errors.

### Task 2: Remove the unused macro feature and prove the reduced lockfile

**Files:**
- Modify: `Cargo.toml:39`
- Modify: `Cargo.lock` (Cargo-generated)

**Interfaces:**
- Consumes: workspace SQLx dependency with the preserved runtime, PostgreSQL, SQLite, UUID, chrono, JSON, and migration features.
- Produces: a lockfile with no `rsa`, `sqlx-mysql`, `sqlx-macros`, or `sqlx-macros-core` packages.

- [ ] **Step 1: Define the desired dependency behavior as a lockfile assertion**

Run: `rg -n '^name = "(rsa|sqlx-mysql|sqlx-macros|sqlx-macros-core)"$' Cargo.lock`

Expected before the edit: SQLx macro package entries may be present; after resolution, this command must have no output.

- [ ] **Step 2: Remove only `macros` from the workspace SQLx feature list**

Edit `Cargo.toml` so the feature array is exactly:

```toml
features = ["runtime-tokio-rustls", "postgres", "sqlite", "uuid", "chrono", "json", "migrate"]
```

- [ ] **Step 3: Regenerate Cargo.lock through Cargo resolution**

Run: `cargo check --workspace`

Expected: Cargo updates the lockfile and succeeds without enabling SQLx compile-time macros.

- [ ] **Step 4: Verify the dependency removal**

Run: `cargo tree -i rsa@0.9.10; cargo tree -i sqlx-mysql; rg -n '^name = "(rsa|sqlx-mysql|sqlx-macros|sqlx-macros-core)"$' Cargo.lock`

Expected: each inverse tree reports no package and the lockfile search has no output.

- [ ] **Step 5: Commit the dependency change**

Run: `git add Cargo.toml Cargo.lock && git commit -m "build: remove unused sqlx macros feature"`

Expected: a focused commit containing only the manifest and generated lockfile.

### Task 3: Make reproducible release gates cover both database backends and strict doctor

**Files:**
- Modify: `.github/workflows/ci.yml`
- Inspect/Test: `crates/umbra-storage/src/tests.rs`, `crates/umbra-server/src/tests.rs`, `crates/umbra-migrations/src/lib.rs`

**Interfaces:**
- Consumes: CI PostgreSQL 17 service, `UMBRA_TEST_DATABASE_URL`, server configuration environment variables.
- Produces: CI jobs that run format, workspace build, workspace tests (including real PostgreSQL tests), clippy, and audit without suppressions.

- [ ] **Step 1: Verify existing SQLite and PostgreSQL test behavior**

Run: `cargo test -p umbra-storage sqlite_migrations_create_required_schema; cargo test -p umbra-storage postgres_migrations_create_required_schema`

Expected: SQLite passes locally; PostgreSQL test runs against `UMBRA_TEST_DATABASE_URL` and is not replaced by SQLite.

- [ ] **Step 2: Verify strict doctor with a safe SQLite fixture**

Run with a temporary SQLite URL, `auto_migrate=false`, `require_latest=true`, loopback bind, HTTPS public URL, and generated OPAQUE setup: `cargo run -p umbra-server -- doctor --strict`.

Expected: exit 0 and no secret values written to the fixture or command output.

- [ ] **Step 3: Add audit tool installation and release commands to CI**

Add an explicit `cargo install cargo-audit --locked` step and run `cargo fmt --check`, `cargo build --workspace`, `cargo test --workspace`, `cargo clippy --workspace --all-targets -- -D warnings`, and `cargo audit` in CI.

- [ ] **Step 4: Verify CI YAML and local release commands**

Run: `cargo fmt --check; cargo build --workspace; cargo test --workspace; cargo clippy --workspace --all-targets -- -D warnings; cargo audit`

Expected: every command exits 0, audit has no ignored advisories, and PostgreSQL tests are executed when the configured service is reachable.

- [ ] **Step 5: Commit CI release gates**

Run: `git add .github/workflows/ci.yml && git commit -m "ci: audit the release dependency graph"`

Expected: CI remains PostgreSQL-backed and adds no audit suppression.

### Task 4: Document the release verification procedure

**Files:**
- Modify: `README.md`
- Modify: `docs/distribution.md`
- Modify: `docs/operations.md`

**Interfaces:**
- Consumes: the exact CI/release commands and safe server configuration requirements.
- Produces: contributor, distribution, and operator instructions that reproduce the audit and strict-doctor release gate without exposing secrets.

- [ ] **Step 1: Add an exact local release-gate command block**

Document `fmt`, workspace build/test, workspace-target clippy, `cargo audit`, and the two negative inverse-tree checks. State that `cargo audit` uses no suppression.

- [ ] **Step 2: Add a safe strict-doctor fixture example**

Document environment-variable names and a generated OPAQUE setup placeholder only; do not include a live setup secret or any vault data.

- [ ] **Step 3: Check documentation for zero-knowledge violations**

Run: `rg -n 'password=|vault key|private key|OPAQUE.*[A-Za-z0-9]{20,}' README.md docs/distribution.md docs/operations.md`

Expected: documentation discusses secret handling only as redacted placeholders and retains the zero-knowledge boundary.

- [ ] **Step 4: Commit documentation**

Run: `git add README.md docs/distribution.md docs/operations.md docs/superpowers/plans/2026-07-29-release-audit-unblock.md && git commit -m "docs: document audit-ready release gates"`

Expected: release instructions match CI and mention both PostgreSQL and SQLite coverage.

### Task 5: Review scope, verify fresh evidence, and submit against main

**Files:**
- Inspect: `Cargo.toml`, `Cargo.lock`, `.github/workflows/ci.yml`, `README.md`, `docs/distribution.md`, `docs/operations.md`, `docs/superpowers/plans/2026-07-29-release-audit-unblock.md`

**Interfaces:**
- Consumes: all previous commits and live verification outputs.
- Produces: a narrow `codex/release-audit-unblock` branch and ready pull request targeting `main`.

- [ ] **Step 1: Review diff and scope**

Run: `git diff main...HEAD --check; git diff --stat main...HEAD; git diff main...HEAD -- Cargo.toml Cargo.lock`

Expected: only SQLx's unused `macros` feature is removed; PostgreSQL, SQLite, migrations, zero-knowledge code, and unrelated work remain unchanged.

- [ ] **Step 2: Run fresh final release evidence**

Run: `cargo fmt --check; cargo build --workspace; cargo test --workspace; cargo clippy --workspace --all-targets -- -D warnings; cargo audit; cargo tree -i rsa@0.9.10; cargo tree -i sqlx-mysql`

Expected: quality gates exit 0; both inverse dependency commands report no package.

- [ ] **Step 3: Push and open a ready PR**

Run: `git push -u origin codex/release-audit-unblock` followed by `gh pr create --base main --head codex/release-audit-unblock --title "build: unblock audit-ready release" --body-file <reviewed-body-file>`.

Expected: a ready (not draft) PR URL targeting `main`.

- [ ] **Step 4: Report exact evidence**

Report the saved plan path, PR URL, commands, exit statuses, and any environment limitation affecting PostgreSQL execution. Do not claim a green release without fresh command outputs.
