# CLI Env Workflows Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Make Umbra usable for developer `.env` workflows by adding `umbra env get`, `umbra env inject`, and `umbra run` on top of existing encrypted `secret` bundles.

**Architecture:** Reuse the current `SecretCommand` env-bundle storage model and local encrypted cache. Add a thin CLI workflow layer that decrypts a selected `project/env` bundle locally, renders deterministic dotenv output, writes `.env` files when requested, and launches child processes with decrypted variables in-memory. The server protocol and database do not change.

**Tech Stack:** Rust, clap, existing `umbra-cli` cache/sync/decrypt helpers, `std::process::Command`, current `ItemPlaintextV1` env bundle fields.

---

## Scope

This plan implements:

- `umbra env get <project/env> [--vault ...] [--offline]`
- `umbra env inject <project/env> --output .env [--vault ...] [--offline] [--yes]`
- `umbra run <project/env> -- <command> [args...]`
- deterministic dotenv rendering with shell-safe quoting
- parser, helper, command, and docs tests

This plan does not implement:

- server-side changes
- frontend/web UI
- shell-specific source hooks
- background secret watching
- plaintext local cache

## File Structure

- Modify `crates/umbra-cli/src/main.rs`
  - Add top-level `Env(EnvCommand)` and `Run` commands.
  - Add `EnvCommand::{Get, Inject}`.
- Modify `crates/umbra-cli/src/item_plaintext.rs`
  - Add deterministic env field extraction and dotenv rendering helpers.
- Modify `crates/umbra-cli/src/commands.rs`
  - Add execution branches for `env get`, `env inject`, and `run`.
  - Reuse existing `find_secret_bundle`, `resolve_vault_id_for_output`, `unlock_vault_key`, and sync/cache flow.
- Modify `crates/umbra-cli/src/tests.rs`
  - Add parser tests for new CLI sugar.
- Modify `README.md`
  - Document the new dev-secret workflow.

---

### Task 1: Add Dotenv Rendering Helpers

**Files:**
- Modify: `crates/umbra-cli/src/item_plaintext.rs`

- [ ] **Step 1: Write failing helper tests**

Add these tests inside the existing `#[cfg(test)] mod tests` in `crates/umbra-cli/src/item_plaintext.rs`:

```rust
#[test]
fn env_pairs_are_sorted_by_key() {
    let mut item = build_secret_bundle("pulzar/dev", "DATABASE_URL", "postgres://localhost");
    set_plaintext_field(&mut item, "OPENAI_API_KEY", "sk-test".to_owned());
    set_plaintext_field(&mut item, "REDIS_URL", "redis://localhost".to_owned());

    let pairs = env_pairs(&item);

    assert_eq!(
        pairs,
        vec![
            ("DATABASE_URL".to_owned(), "postgres://localhost".to_owned()),
            ("OPENAI_API_KEY".to_owned(), "sk-test".to_owned()),
            ("REDIS_URL".to_owned(), "redis://localhost".to_owned()),
        ]
    );
}

#[test]
fn dotenv_output_quotes_values_safely() {
    let mut item = build_secret_bundle("pulzar/dev", "DATABASE_URL", "postgres://localhost/db");
    set_plaintext_field(&mut item, "PLAIN", "abc_123".to_owned());
    set_plaintext_field(&mut item, "SPACED", "hello world".to_owned());
    set_plaintext_field(&mut item, "QUOTE", "a\"b".to_owned());
    set_plaintext_field(&mut item, "MULTILINE", "a\nb".to_owned());

    let rendered = render_dotenv(&item);

    assert_eq!(
        rendered,
        "DATABASE_URL=postgres://localhost/db\nMULTILINE=\"a\\nb\"\nPLAIN=abc_123\nQUOTE=\"a\\\"b\"\nSPACED=\"hello world\"\n"
    );
}

#[test]
fn invalid_env_names_are_omitted_from_dotenv_output() {
    let mut item = build_secret_bundle("pulzar/dev", "VALID_KEY", "ok");
    set_plaintext_field(&mut item, "not-valid", "bad".to_owned());
    set_plaintext_field(&mut item, "1INVALID", "bad".to_owned());

    let rendered = render_dotenv(&item);

    assert_eq!(rendered, "VALID_KEY=ok\n");
}
```

- [ ] **Step 2: Run tests and verify they fail**

Run:

```bash
cargo test -p umbra-cli env_pairs_are_sorted_by_key dotenv_output_quotes_values_safely invalid_env_names_are_omitted_from_dotenv_output
```

Expected: FAIL because `env_pairs` and `render_dotenv` are not defined.

- [ ] **Step 3: Implement helpers**

Add these functions to `crates/umbra-cli/src/item_plaintext.rs` after `remove_plaintext_field`:

```rust
pub fn env_pairs(item: &ItemPlaintextV1) -> Vec<(String, String)> {
    let mut pairs = item
        .fields
        .iter()
        .filter(|field| is_valid_env_name(&field.name))
        .map(|field| (field.name.clone(), field.value.clone()))
        .collect::<Vec<_>>();
    pairs.sort_by(|left, right| left.0.cmp(&right.0));
    pairs
}

pub fn render_dotenv(item: &ItemPlaintextV1) -> String {
    env_pairs(item)
        .into_iter()
        .map(|(name, value)| format!("{name}={}\n", quote_dotenv_value(&value)))
        .collect()
}

fn is_valid_env_name(name: &str) -> bool {
    let mut chars = name.chars();
    let Some(first) = chars.next() else {
        return false;
    };
    if !(first == '_' || first.is_ascii_uppercase()) {
        return false;
    }
    chars.all(|ch| ch == '_' || ch.is_ascii_uppercase() || ch.is_ascii_digit())
}

fn quote_dotenv_value(value: &str) -> String {
    if value
        .chars()
        .all(|ch| ch.is_ascii_alphanumeric() || matches!(ch, '_' | '-' | '.' | '/' | ':' | '@'))
    {
        return value.to_owned();
    }

    let escaped = value
        .replace('\\', "\\\\")
        .replace('\n', "\\n")
        .replace('\r', "\\r")
        .replace('"', "\\\"");
    format!("\"{escaped}\"")
}
```

- [ ] **Step 4: Run helper tests**

Run:

```bash
cargo test -p umbra-cli env_pairs_are_sorted_by_key dotenv_output_quotes_values_safely invalid_env_names_are_omitted_from_dotenv_output
```

Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add crates/umbra-cli/src/item_plaintext.rs
git commit -m "feat(cli): render env bundles as dotenv"
```

---

### Task 2: Add CLI Parser For Env And Run Commands

**Files:**
- Modify: `crates/umbra-cli/src/main.rs`
- Modify: `crates/umbra-cli/src/tests.rs`

- [ ] **Step 1: Write failing parser tests**

Add this test to `crates/umbra-cli/src/tests.rs` near the existing secret parser tests:

```rust
#[test]
fn parses_env_and_run_commands() {
    let get = Cli::parse_from([
        "umbra",
        "env",
        "get",
        "pulzar/dev",
        "--vault",
        "Personal",
        "--offline",
    ]);
    assert!(matches!(
        get.command,
        Command::Env(crate::EnvCommand::Get {
            project_env,
            vault: Some(vault),
            offline: true,
            ..
        }) if project_env == "pulzar/dev" && vault == "Personal"
    ));

    let inject = Cli::parse_from([
        "umbra",
        "env",
        "inject",
        "pulzar/dev",
        "--vault-id",
        "00000000-0000-0000-0000-000000000001",
        "--output",
        ".env",
        "--yes",
    ]);
    assert!(matches!(
        inject.command,
        Command::Env(crate::EnvCommand::Inject {
            project_env,
            output,
            yes: true,
            ..
        }) if project_env == "pulzar/dev" && output == std::path::PathBuf::from(".env")
    ));

    let run = Cli::parse_from([
        "umbra",
        "run",
        "pulzar/dev",
        "--vault",
        "Personal",
        "--",
        "cargo",
        "test",
        "-p",
        "app",
    ]);
    assert!(matches!(
        run.command,
        Command::Run {
            project_env,
            vault: Some(vault),
            command,
            ..
        } if project_env == "pulzar/dev"
            && vault == "Personal"
            && command == vec![
                "cargo".to_owned(),
                "test".to_owned(),
                "-p".to_owned(),
                "app".to_owned(),
            ]
    ));
}
```

- [ ] **Step 2: Run parser test and verify it fails**

Run:

```bash
cargo test -p umbra-cli parses_env_and_run_commands
```

Expected: FAIL because `Command::Env`, `EnvCommand`, and `Command::Run` do not exist.

- [ ] **Step 3: Add parser enums**

In `crates/umbra-cli/src/main.rs`, add `Env(EnvCommand)` near `Secret(SecretCommand)` and add a top-level `Run` command:

```rust
    #[command(subcommand)]
    Env(EnvCommand),
    Run {
        project_env: String,
        #[arg(long)]
        vault_id: Option<VaultId>,
        #[arg(long)]
        vault: Option<String>,
        #[arg(long, alias = "cached")]
        offline: bool,
        #[arg(last = true, required = true)]
        command: Vec<String>,
    },
```

Add this enum after `SecretCommand`:

```rust
#[derive(Debug, Subcommand)]
pub enum EnvCommand {
    Get {
        project_env: String,
        #[arg(long)]
        vault_id: Option<VaultId>,
        #[arg(long)]
        vault: Option<String>,
        #[arg(long, alias = "cached")]
        offline: bool,
    },
    Inject {
        project_env: String,
        #[arg(long)]
        vault_id: Option<VaultId>,
        #[arg(long)]
        vault: Option<String>,
        #[arg(long)]
        output: PathBuf,
        #[arg(long, alias = "cached")]
        offline: bool,
        #[arg(long)]
        yes: bool,
    },
}
```

Update the `use crate::{ ... }` import in `crates/umbra-cli/src/tests.rs` to include `EnvCommand` only if the test uses the unqualified name. The test above uses `crate::EnvCommand`, so no import change is required.

- [ ] **Step 4: Run parser test**

Run:

```bash
cargo test -p umbra-cli parses_env_and_run_commands
```

Expected: PASS after the command branches are added to `commands::run` in Task 3. If this fails now with non-exhaustive match in `commands.rs`, continue to Task 3 before rerunning.

---

### Task 3: Implement `env get` And `env inject`

**Files:**
- Modify: `crates/umbra-cli/src/commands.rs`
- Test: existing command/parser tests plus helper tests

- [ ] **Step 1: Add imports**

In `crates/umbra-cli/src/commands.rs`, add `Path` and `EnvCommand`:

```rust
use std::path::Path;
```

Update the command import block:

```rust
use crate::{
    AuthCommand, CacheCommand, Command, CryptoCommand, DeviceCommand, EmergencyKitCommand,
    EnvCommand, InviteCommand, ItemCommand, OrgCommand, ProfileCommand, SecretCommand, SyncCommand,
    TokenCommand, VaultCommand,
};
```

- [ ] **Step 2: Add shared env bundle loader**

Add this helper after `require_login`:

```rust
async fn load_env_bundle_for_command(
    config: &CliConfig,
    profile: &crate::config::ProfileConfig,
    output: OutputMode,
    project_env: &str,
    vault_id: Option<VaultId>,
    vault: Option<&str>,
    offline: bool,
) -> Result<ItemPlaintextV1, CliError> {
    let mut cache = crate::cache::LocalCache::open(&config.active_profile)?;
    let vault_id = resolve_vault_id_for_output(profile, &cache, vault_id, vault, output)?;
    let mode = if offline {
        crate::sync::SyncMode::Offline
    } else {
        require_login(profile)?;
        crate::sync::SyncMode::IfChanged
    };
    let sync_outcome = crate::sync::ensure_vault_synced(profile, &mut cache, vault_id, mode).await?;
    let _ = (
        sync_outcome.synced,
        sync_outcome.latest_vault_revision,
        sync_outcome.latest_access_revision,
    );
    let vault_key = unlock_vault_key(&config.active_profile, profile, &cache, vault_id)?;
    let Some((_revision, plaintext)) = find_secret_bundle(&cache, &vault_key, vault_id, project_env)? else {
        return Err(CliError::Input("secret bundle not found"));
    };
    Ok(plaintext)
}
```

`ItemPlaintextV1` is already imported at the top of `commands.rs`; if not, add it to the `umbra_core` import list.

- [ ] **Step 3: Add overwrite guard helper**

Add this helper near other private helpers:

```rust
fn ensure_can_write_env_file(path: &Path, yes: bool) -> Result<(), CliError> {
    if path.exists() && !yes {
        return Err(CliError::Input(
            "output file already exists; pass --yes to overwrite",
        ));
    }
    Ok(())
}
```

- [ ] **Step 4: Add command branches**

In the main `match command` in `crates/umbra-cli/src/commands.rs`, add these branches after the `SecretCommand::Rm` branch and before `SyncCommand::Run`:

```rust
        Command::Env(EnvCommand::Get {
            project_env,
            vault_id,
            vault,
            offline,
        }) => {
            let profile = active_profile(&config)?;
            let plaintext = load_env_bundle_for_command(
                &config,
                profile,
                output,
                &project_env,
                vault_id,
                vault.as_deref(),
                offline,
            )
            .await?;
            let dotenv = crate::item_plaintext::render_dotenv(&plaintext);
            print!("{dotenv}");
            Ok(())
        }
        Command::Env(EnvCommand::Inject {
            project_env,
            vault_id,
            vault,
            output: output_path,
            offline,
            yes,
        }) => {
            let profile = active_profile(&config)?;
            let plaintext = load_env_bundle_for_command(
                &config,
                profile,
                output,
                &project_env,
                vault_id,
                vault.as_deref(),
                offline,
            )
            .await?;
            ensure_can_write_env_file(&output_path, yes)?;
            let dotenv = crate::item_plaintext::render_dotenv(&plaintext);
            std::fs::write(&output_path, dotenv)?;
            if output.is_json() {
                print_json(&serde_json::json!({
                    "project_env": project_env,
                    "output": output_path,
                    "written": true
                }))
            } else {
                crate::output::print_kv(&[
                    ("project_env", project_env),
                    ("output", output_path.display().to_string()),
                    ("written", "true".to_owned()),
                ]);
                Ok(())
            }
        }
```

- [ ] **Step 5: Run targeted tests**

Run:

```bash
cargo test -p umbra-cli parses_env_and_run_commands env_pairs_are_sorted_by_key dotenv_output_quotes_values_safely invalid_env_names_are_omitted_from_dotenv_output
cargo check -p umbra-cli
```

Expected: parser/helper tests PASS and `cargo check` PASS except for the still-unimplemented `Command::Run` branch if Task 2 already added it. If `Command::Run` is non-exhaustive, implement Task 4 before committing.

- [ ] **Step 6: Commit after `env get`/`inject` compiles**

```bash
git add crates/umbra-cli/src/main.rs crates/umbra-cli/src/tests.rs crates/umbra-cli/src/commands.rs
git commit -m "feat(cli): add env get and inject"
```

---

### Task 4: Implement `umbra run`

**Files:**
- Modify: `crates/umbra-cli/src/commands.rs`
- Modify: `crates/umbra-cli/src/error.rs`

- [ ] **Step 1: Add process status error**

Add this variant to `CliError` in `crates/umbra-cli/src/error.rs`:

```rust
    #[error("child process exited with status {0}")]
    ProcessExit(std::process::ExitStatus),
```

- [ ] **Step 2: Add `run` command branch**

In `crates/umbra-cli/src/commands.rs`, add this branch after the `EnvCommand::Inject` branch:

```rust
        Command::Run {
            project_env,
            vault_id,
            vault,
            offline,
            command,
        } => {
            let profile = active_profile(&config)?;
            if command.is_empty() {
                return Err(CliError::Input("run requires a command after --"));
            }
            let plaintext = load_env_bundle_for_command(
                &config,
                profile,
                output,
                &project_env,
                vault_id,
                vault.as_deref(),
                offline,
            )
            .await?;
            let env_pairs = crate::item_plaintext::env_pairs(&plaintext);
            let mut child = std::process::Command::new(&command[0]);
            child.args(&command[1..]);
            child.envs(env_pairs);
            let status = child.status()?;
            if status.success() {
                Ok(())
            } else {
                Err(CliError::ProcessExit(status))
            }
        }
```

- [ ] **Step 3: Run parser and check**

Run:

```bash
cargo test -p umbra-cli parses_env_and_run_commands
cargo check -p umbra-cli
```

Expected: PASS.

- [ ] **Step 4: Commit**

```bash
git add crates/umbra-cli/src/commands.rs crates/umbra-cli/src/error.rs
git commit -m "feat(cli): run commands with injected secrets"
```

---

### Task 5: Add Focused Runtime Tests For Helpers

**Files:**
- Modify: `crates/umbra-cli/src/commands.rs`

- [ ] **Step 1: Add unit tests for overwrite guard**

Inside the existing `#[cfg(test)] mod tests` in `crates/umbra-cli/src/commands.rs`, add:

```rust
#[test]
fn env_inject_requires_yes_before_overwriting_existing_file() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join(".env");
    std::fs::write(&path, "DATABASE_URL=old\n").unwrap();

    let without_yes = ensure_can_write_env_file(&path, false);
    assert!(matches!(without_yes, Err(CliError::Input(_))));

    let with_yes = ensure_can_write_env_file(&path, true);
    assert!(with_yes.is_ok());
}

#[test]
fn env_inject_allows_new_file_without_yes() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join(".env");

    assert!(ensure_can_write_env_file(&path, false).is_ok());
}
```

`tempfile` is already available in the workspace through existing dev dependencies if used by the CLI crate. If it is not in `crates/umbra-cli/Cargo.toml`, add:

```toml
[dev-dependencies]
tempfile = "3"
```

- [ ] **Step 2: Run tests**

Run:

```bash
cargo test -p umbra-cli env_inject_requires_yes_before_overwriting_existing_file env_inject_allows_new_file_without_yes
```

Expected: PASS.

- [ ] **Step 3: Commit**

```bash
git add crates/umbra-cli/src/commands.rs crates/umbra-cli/Cargo.toml Cargo.lock
git commit -m "test(cli): cover env inject overwrite guard"
```

If `Cargo.toml` and `Cargo.lock` did not change because `tempfile` was already available, commit only `crates/umbra-cli/src/commands.rs`.

---

### Task 6: Document The Env Workflow

**Files:**
- Modify: `README.md`

- [ ] **Step 1: Update the happy path commands**

In `README.md`, under "Current CLI Happy Path", add these commands after the existing `secret get` examples:

```bash
umbra env get pulzar/dev --vault Personal
umbra env inject pulzar/dev --vault Personal --output .env --yes
umbra run pulzar/dev --vault Personal -- cargo run
```

- [ ] **Step 2: Add env workflow explanation**

Add this paragraph after the local cache paragraph that starts with "The CLI encrypts item plaintext locally before upload":

```markdown
`env get` prints a deterministic dotenv view of an encrypted `secret` bundle. `env inject` writes that dotenv output to a file and refuses to overwrite an existing file unless `--yes` is passed. `umbra run <project/env> -- <command>` decrypts the bundle locally and injects the variables into only the child process environment; it does not write plaintext to the local cache.
```

- [ ] **Step 3: Run docs-adjacent tests**

Run:

```bash
cargo test -p umbra-cli parses_env_and_run_commands
```

Expected: PASS.

- [ ] **Step 4: Commit**

```bash
git add README.md
git commit -m "docs(cli): document env workflows"
```

---

### Task 7: Final Verification And Integration

**Files:**
- No code files unless formatting changes are produced.

- [ ] **Step 1: Run formatting check**

Run:

```bash
cargo fmt --all -- --check
```

Expected: PASS. If it fails, run:

```bash
cargo fmt --all
git add .
git commit -m "chore: format env workflows"
```

- [ ] **Step 2: Run workspace check**

Run:

```bash
cargo check --workspace
```

Expected: PASS.

- [ ] **Step 3: Run workspace tests**

Run:

```bash
cargo test --workspace
```

Expected: PASS.

- [ ] **Step 4: Request code review**

Use a subagent review focused on:

```txt
Review the env workflow branch for plaintext leakage, command injection, unsafe file overwrite behavior, test coverage, and whether `umbra run` correctly injects variables only into the child process environment. Do not edit files.
```

- [ ] **Step 5: Fix review findings**

For each blocking finding:

1. Verify it against the code.
2. Add or update a focused test.
3. Implement the smallest fix.
4. Run the focused test.
5. Commit with a conventional message.

- [ ] **Step 6: Merge and push**

Run:

```bash
git switch main
git merge --ff-only <feature-branch>
git push origin main
git branch -d <feature-branch>
git push origin --delete <feature-branch>
```

If the remote branch does not exist, the delete command may fail with `remote ref does not exist`; that is acceptable after the local branch has been deleted.

---

## Self-Review

- Spec coverage: This plan covers CLI dotenv output, file injection, process env injection, parser tests, helper tests, docs, and full verification. It intentionally avoids server/frontend changes because env workflows use existing encrypted item and sync APIs.
- Placeholder scan: No task contains open-ended implementation placeholders. Every code-changing task includes concrete snippets and commands.
- Type consistency: `EnvCommand`, `Command::Env`, `Command::Run`, `env_pairs`, `render_dotenv`, `ensure_can_write_env_file`, and `load_env_bundle_for_command` are named consistently across tasks.
