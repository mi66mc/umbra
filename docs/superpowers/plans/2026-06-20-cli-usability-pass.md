# CLI Usability Pass Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Make the current remote CLI feel usable for day-to-day vault, item, and secret work without changing the zero-knowledge server protocol.

**Architecture:** Keep the server and protocol stable. Improve the CLI by adding explicit output modes, human-readable renderers, better vault selection, item lookup by title, and secret listing/removal. Split repeated command concerns into focused helpers only where they reduce current duplication in `commands.rs`.

**Tech Stack:** Rust, clap, dialoguer, serde/serde_json, rusqlite cache, existing Umbra crypto/sync/http crates.

---

## Scope

This plan is intentionally CLI-first. It does not add frontend, new server endpoints, local vault mode, or organization UX. It makes existing encrypted sync data easier to use.

The key product changes:

- Human-readable CLI output by default.
- `--json` available globally for scripts.
- `sync run` accepts `--vault Personal`, `--vault-id <uuid>`, or default vault.
- `item list` prints useful decrypted summaries when possible.
- `item get` can resolve an item by `--title GitHub` instead of only UUID.
- `secret list pulzar/dev` lists keys in an env bundle.
- `secret rm pulzar/dev DATABASE_URL` removes a key from an env bundle.
- README reflects the simpler workflow.

## File Structure

- Modify `crates/umbra-cli/src/main.rs`
  - Add global `--json`.
  - Add command shapes for `item get --title`, `secret list`, `secret rm`, and friendlier `sync run` vault selectors.

- Modify `crates/umbra-cli/src/output.rs`
  - Own output mode and human-vs-JSON rendering helpers.
  - Keep JSON behavior available for automation.

- Modify `crates/umbra-cli/src/cache.rs`
  - Expose cached vault list outside tests.
  - Add small cache lookup helpers needed for UX.

- Modify `crates/umbra-cli/src/commands.rs`
  - Pass `OutputMode`.
  - Render human output by default.
  - Resolve sync vault selectors through the same vault resolver used by item/secret commands.
  - Add decrypted item selection by title.
  - Add secret list/remove behavior.

- Modify `crates/umbra-cli/src/item_plaintext.rs`
  - Add a removal helper for plaintext fields.

- Modify `crates/umbra-cli/src/tests.rs`
  - Parser tests for new flags and commands.

- Modify `README.md`
  - Update happy path to show the simplified commands and `--json`.

---

### Task 1: Add Global Output Mode

**Files:**
- Modify: `crates/umbra-cli/src/main.rs`
- Modify: `crates/umbra-cli/src/output.rs`
- Modify: `crates/umbra-cli/src/commands.rs`
- Test: `crates/umbra-cli/src/tests.rs`

- [ ] **Step 1: Write parser test for global `--json`**

Add this test to `crates/umbra-cli/src/tests.rs`:

```rust
#[test]
fn parses_global_json_flag() {
    let cli = Cli::parse_from(["umbra", "--json", "vault", "list"]);

    assert!(cli.json);
    assert!(matches!(cli.command, Command::Vault(VaultCommand::List)));
}
```

- [ ] **Step 2: Run test to verify it fails**

Run:

```bash
cargo test -p umbra-cli parses_global_json_flag
```

Expected: FAIL because `Cli` has no `json` field.

- [ ] **Step 3: Add `--json` to the CLI root**

In `crates/umbra-cli/src/main.rs`, replace `Cli` with:

```rust
#[derive(Debug, Parser)]
#[command(name = "umbra")]
#[command(about = "Umbra command line client")]
pub struct Cli {
    #[arg(long, global = true, help = "Print machine-readable JSON output")]
    pub json: bool,
    #[command(subcommand)]
    pub command: Command,
}
```

- [ ] **Step 4: Add output mode and rendering helpers**

Replace `crates/umbra-cli/src/output.rs` with:

```rust
use serde::Serialize;

use crate::error::CliError;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OutputMode {
    Human,
    Json,
}

impl OutputMode {
    pub fn from_json_flag(json: bool) -> Self {
        if json {
            Self::Json
        } else {
            Self::Human
        }
    }

    pub fn is_json(self) -> bool {
        matches!(self, Self::Json)
    }
}

pub fn print_json<T: Serialize>(value: &T) -> Result<(), CliError> {
    println!("{}", serde_json::to_string_pretty(value)?);
    Ok(())
}

pub fn print_table(headers: &[&str], rows: &[Vec<String>]) {
    let mut widths = headers.iter().map(|header| header.len()).collect::<Vec<_>>();
    for row in rows {
        for (index, cell) in row.iter().enumerate() {
            if index >= widths.len() {
                widths.push(0);
            }
            widths[index] = widths[index].max(cell.len());
        }
    }

    print_row(headers.iter().map(|value| value.to_string()).collect(), &widths);
    print_row(
        widths.iter().map(|width| "-".repeat(*width)).collect(),
        &widths,
    );
    for row in rows {
        print_row(row.clone(), &widths);
    }
}

pub fn print_kv(rows: &[(&str, String)]) {
    let width = rows
        .iter()
        .map(|(key, _value)| key.len())
        .max()
        .unwrap_or(0);
    for (key, value) in rows {
        println!("{key:width$}  {value}", width = width);
    }
}

fn print_row(row: Vec<String>, widths: &[usize]) {
    for (index, cell) in row.iter().enumerate() {
        if index > 0 {
            print!("  ");
        }
        let width = widths[index];
        print!("{cell:width$}");
    }
    println!();
}
```

- [ ] **Step 5: Pass output mode into command execution**

In `crates/umbra-cli/src/main.rs`, replace the end of `main` with:

```rust
#[tokio::main]
async fn main() -> Result<(), CliError> {
    let cli = Cli::parse();
    let output = crate::output::OutputMode::from_json_flag(cli.json);
    let config = load_config_for_command(&cli.command)?;
    commands::run(cli.command, config, output).await
}
```

In `crates/umbra-cli/src/commands.rs`, change the imports:

```rust
use crate::output::{print_json, OutputMode};
```

Change the run signature:

```rust
pub async fn run(
    command: Command,
    mut config: CliConfig,
    output: OutputMode,
) -> Result<(), CliError> {
```

For this task, keep existing behavior by replacing every current `print_json(&value)` call with:

```rust
if output.is_json() {
    print_json(&value)
} else {
    print_json(&value)
}
```

Use a local variable named `value` only where the command already has a variable. For direct expressions, keep `print_json(...)` and convert them in later tasks.

- [ ] **Step 6: Run tests**

Run:

```bash
cargo test -p umbra-cli parses_global_json_flag
cargo test -p umbra-cli
```

Expected: PASS.

- [ ] **Step 7: Commit**

```bash
git add crates/umbra-cli/src/main.rs crates/umbra-cli/src/output.rs crates/umbra-cli/src/commands.rs crates/umbra-cli/src/tests.rs
git commit -m "feat(cli): add global json output mode"
```

---

### Task 2: Human Output For Vaults, Status, Cache, And Sync

**Files:**
- Modify: `crates/umbra-cli/src/cache.rs`
- Modify: `crates/umbra-cli/src/commands.rs`
- Test: `crates/umbra-cli/src/cache.rs`

- [ ] **Step 1: Make cached vault listing usable outside tests**

In `crates/umbra-cli/src/cache.rs`, remove `#[cfg(test)]` from `pub fn list_vaults`.

The function should remain:

```rust
pub fn list_vaults(&self) -> Result<Vec<CachedVault>, CliError> {
    let mut statement = self.connection.prepare(
        r#"
        SELECT vault_id, name, kind, latest_vault_revision, latest_access_revision,
               current_key_generation, needs_key_rotation
        FROM vaults
        ORDER BY name ASC, vault_id ASC
        "#,
    )?;
    let rows = statement.query_map([], cached_vault_from_row)?;
    rows.collect::<Result<Vec<_>, _>>().map_err(CliError::from)
}
```

- [ ] **Step 2: Add human render helpers**

In `crates/umbra-cli/src/commands.rs`, add these helpers near `profile_public_key`:

```rust
fn render_vaults(output: OutputMode, vaults: &[VaultResponse]) -> Result<(), CliError> {
    if output.is_json() {
        return print_json(vaults);
    }

    let rows = vaults
        .iter()
        .map(|vault| {
            vec![
                vault.name.clone(),
                vault.kind.to_string(),
                vault.vault_id.to_string(),
                vault.vault_revision.to_string(),
                vault.access_revision.to_string(),
                if vault.needs_key_rotation {
                    "yes".to_owned()
                } else {
                    "no".to_owned()
                },
            ]
        })
        .collect::<Vec<_>>();
    crate::output::print_table(
        &["name", "kind", "id", "vault_rev", "access_rev", "rotate"],
        &rows,
    );
    Ok(())
}

fn render_cache_status(
    output: OutputMode,
    status: &crate::cache::CacheStatus,
) -> Result<(), CliError> {
    if output.is_json() {
        return print_json(status);
    }

    crate::output::print_kv(&[
        ("profile", status.profile.clone()),
        ("synced vaults", status.synced_vault_count.to_string()),
        ("item revisions", status.item_revision_count.to_string()),
        ("key wrappings", status.key_wrapping_count.to_string()),
        ("sync states", status.sync_state_count.to_string()),
    ]);
    Ok(())
}

fn render_unlock_status(
    output: OutputMode,
    status: &crate::unlock_store::UnlockStatus,
) -> Result<(), CliError> {
    if output.is_json() {
        return print_json(status);
    }

    crate::output::print_kv(&[
        ("profile", status.profile.clone()),
        ("unlocked", status.unlocked.to_string()),
        (
            "expires",
            status
                .expires_at
                .map(|value| value.to_rfc3339())
                .unwrap_or_else(|| "-".to_owned()),
        ),
        ("vaults", status.vault_count.to_string()),
    ]);
    Ok(())
}

fn render_sync_response(output: OutputMode, response: &SyncResponse) -> Result<(), CliError> {
    if output.is_json() {
        return print_json(response);
    }

    let rows = response
        .vaults
        .iter()
        .map(|vault| {
            vec![
                vault.vault_id.to_string(),
                vault.latest_vault_revision.to_string(),
                vault.latest_access_revision.to_string(),
                vault.items.len().to_string(),
                vault.key_wrappings.len().to_string(),
            ]
        })
        .collect::<Vec<_>>();
    crate::output::print_table(
        &["vault_id", "vault_rev", "access_rev", "items", "wrappings"],
        &rows,
    );
    Ok(())
}
```

- [ ] **Step 3: Use human renderers in command branches**

In `crates/umbra-cli/src/commands.rs`:

For `Command::Vault(VaultCommand::List)`, replace:

```rust
print_json(&vaults)
```

with:

```rust
render_vaults(output, &vaults)
```

For `Command::Cache(CacheCommand::Status)`, replace:

```rust
print_json(&cache.status()?)
```

with:

```rust
let status = cache.status()?;
render_cache_status(output, &status)
```

For `Command::Status`, replace:

```rust
print_json(&status)
```

with:

```rust
render_unlock_status(output, &status)
```

For `Command::Sync(SyncCommand::Run { ... })`, replace:

```rust
print_json(&response)
```

with:

```rust
render_sync_response(output, &response)
```

- [ ] **Step 4: Run tests and clippy**

Run:

```bash
cargo test -p umbra-cli
cargo clippy -p umbra-cli --all-targets --all-features -- -D warnings
```

Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add crates/umbra-cli/src/cache.rs crates/umbra-cli/src/commands.rs
git commit -m "feat(cli): render common commands for humans"
```

---

### Task 3: Friendlier Sync Vault Selection

**Files:**
- Modify: `crates/umbra-cli/src/main.rs`
- Modify: `crates/umbra-cli/src/commands.rs`
- Test: `crates/umbra-cli/src/tests.rs`

- [ ] **Step 1: Write parser tests**

Add to `crates/umbra-cli/src/tests.rs`:

```rust
#[test]
fn parses_sync_vault_name_and_default() {
    let named = Cli::parse_from(["umbra", "sync", "run", "--vault", "Personal"]);
    let Command::Sync(crate::SyncCommand::Run {
        vault_id,
        vault,
        force_full,
        ..
    }) = named.command
    else {
        panic!("expected sync run");
    };
    assert_eq!(vault_id, None);
    assert_eq!(vault.as_deref(), Some("Personal"));
    assert!(!force_full);

    let defaulted = Cli::parse_from(["umbra", "sync", "run"]);
    let Command::Sync(crate::SyncCommand::Run {
        vault_id,
        vault,
        force_full,
        ..
    }) = defaulted.command
    else {
        panic!("expected sync run");
    };
    assert_eq!(vault_id, None);
    assert_eq!(vault, None);
    assert!(!force_full);
}
```

- [ ] **Step 2: Run test to verify it fails**

Run:

```bash
cargo test -p umbra-cli parses_sync_vault_name_and_default
```

Expected: FAIL because `sync run` requires a UUID-valued `--vault`.

- [ ] **Step 3: Change `SyncCommand::Run` shape**

In `crates/umbra-cli/src/main.rs`, replace `SyncCommand` with:

```rust
#[derive(Debug, Subcommand)]
pub enum SyncCommand {
    Run {
        #[arg(long)]
        vault_id: Option<VaultId>,
        #[arg(long)]
        vault: Option<String>,
        #[arg(long)]
        since_vault_revision: Option<RevisionId>,
        #[arg(long)]
        force_full: bool,
    },
}
```

- [ ] **Step 4: Resolve sync vault through cache/default**

In `crates/umbra-cli/src/commands.rs`, change the sync branch pattern from:

```rust
Command::Sync(SyncCommand::Run {
    vault_id,
    since_vault_revision,
    force_full,
}) => {
```

to:

```rust
Command::Sync(SyncCommand::Run {
    vault_id,
    vault,
    since_vault_revision,
    force_full,
}) => {
```

Inside the branch, after opening the cache, add:

```rust
let vault_id = resolve_vault_id(profile, &cache, vault_id, vault.as_deref())?;
```

The start of the branch must become:

```rust
let profile = active_profile(&config)?;
require_login(profile)?;
let client = UmbraHttpClient::new(profile)?;
let device_id = profile.device_id.ok_or(CliError::Input(
    "profile has no device id; run `umbra login` first",
))?;
let mut cache = crate::cache::LocalCache::open(&config.active_profile)?;
let vault_id = resolve_vault_id(profile, &cache, vault_id, vault.as_deref())?;
let since_vault_revision = if force_full {
    0
} else if let Some(value) = since_vault_revision {
    value
} else {
    cache
        .sync_state(vault_id)?
        .map(|state| state.latest_vault_revision)
        .unwrap_or(0)
};
```

- [ ] **Step 5: Update old sync parser test**

In `crates/umbra-cli/src/tests.rs`, update `parses_sync_force_full` to:

```rust
#[test]
fn parses_sync_force_full() {
    let vault_id = "00000000-0000-0000-0000-000000000001";
    let cli = Cli::parse_from([
        "umbra",
        "sync",
        "run",
        "--vault-id",
        vault_id,
        "--force-full",
    ]);

    let Command::Sync(crate::SyncCommand::Run {
        vault_id: parsed_vault_id,
        vault,
        since_vault_revision,
        force_full,
    }) = cli.command
    else {
        panic!("expected sync run");
    };

    assert_eq!(parsed_vault_id.unwrap().to_string(), vault_id);
    assert_eq!(vault, None);
    assert_eq!(since_vault_revision, None);
    assert!(force_full);
}
```

- [ ] **Step 6: Run tests**

Run:

```bash
cargo test -p umbra-cli parses_sync_vault_name_and_default
cargo test -p umbra-cli parses_sync_force_full
cargo test -p umbra-cli
```

Expected: PASS.

- [ ] **Step 7: Commit**

```bash
git add crates/umbra-cli/src/main.rs crates/umbra-cli/src/commands.rs crates/umbra-cli/src/tests.rs
git commit -m "feat(cli): allow sync by vault name"
```

---

### Task 4: Item Lookup By Title And Human Item Output

**Files:**
- Modify: `crates/umbra-cli/src/main.rs`
- Modify: `crates/umbra-cli/src/commands.rs`
- Test: `crates/umbra-cli/src/tests.rs`

- [ ] **Step 1: Write parser test for `item get --title`**

Add to `crates/umbra-cli/src/tests.rs`:

```rust
#[test]
fn parses_item_get_by_title() {
    let cli = Cli::parse_from(["umbra", "item", "get", "--vault", "Personal", "--title", "GitHub"]);

    let Command::Item(ItemCommand::Get {
        vault,
        item_id,
        title,
        offline,
        ..
    }) = cli.command
    else {
        panic!("expected item get");
    };

    assert_eq!(vault.as_deref(), Some("Personal"));
    assert_eq!(item_id, None);
    assert_eq!(title.as_deref(), Some("GitHub"));
    assert!(!offline);
}
```

- [ ] **Step 2: Run test to verify it fails**

Run:

```bash
cargo test -p umbra-cli parses_item_get_by_title
```

Expected: FAIL because `ItemCommand::Get` requires `--item-id` and has no `title`.

- [ ] **Step 3: Update `ItemCommand::Get`**

In `crates/umbra-cli/src/main.rs`, replace the `Get` variant with:

```rust
Get {
    #[arg(long)]
    vault_id: Option<VaultId>,
    #[arg(long)]
    vault: Option<String>,
    #[arg(long)]
    item_id: Option<ItemId>,
    #[arg(long)]
    title: Option<String>,
    #[arg(long, alias = "cached")]
    offline: bool,
},
```

- [ ] **Step 4: Add item selector helper**

In `crates/umbra-cli/src/commands.rs`, add this helper near `decrypt_cached_item_wrapper`:

```rust
fn select_cached_item_revision(
    cache: &crate::cache::LocalCache,
    vault_key: &VaultKey,
    vault_id: VaultId,
    item_id: Option<Uuid>,
    title: Option<&str>,
) -> Result<crate::cache::CachedItemRevision, CliError> {
    if item_id.is_some() && title.is_some() {
        return Err(CliError::Input("use either --item-id or --title, not both"));
    }

    if let Some(item_id) = item_id {
        return cache
            .latest_item_revision(vault_id, item_id)?
            .ok_or(CliError::Input("cached item not found"));
    }

    let Some(title) = title else {
        return Err(CliError::Input("pass --item-id or --title"));
    };

    let mut matches = Vec::new();
    for revision in cache.list_latest_item_revisions(vault_id)? {
        let item = decrypt_cached_item(vault_key, &revision)?;
        if item.plaintext.title == title {
            matches.push(revision);
        }
    }

    match matches.as_slice() {
        [revision] => Ok(revision.clone()),
        [] => Err(CliError::Input("cached item title not found")),
        _ => Err(CliError::Input("item title is ambiguous; pass --item-id")),
    }
}
```

- [ ] **Step 5: Add item render helpers**

In `crates/umbra-cli/src/commands.rs`, add:

```rust
fn render_item_plaintext(
    output: OutputMode,
    item_id: Uuid,
    plaintext: &ItemPlaintextV1,
) -> Result<(), CliError> {
    if output.is_json() {
        return print_json(plaintext);
    }

    crate::output::print_kv(&[
        ("item_id", item_id.to_string()),
        ("title", plaintext.title.clone()),
        (
            "tags",
            if plaintext.tags.is_empty() {
                "-".to_owned()
            } else {
                plaintext.tags.join(",")
            },
        ),
    ]);

    if !plaintext.fields.is_empty() {
        println!();
        let rows = plaintext
            .fields
            .iter()
            .map(|field| {
                vec![
                    field.name.clone(),
                    format!("{:?}", field.kind),
                    if field.sensitive {
                        "[secret]".to_owned()
                    } else {
                        field.value.clone()
                    },
                ]
            })
            .collect::<Vec<_>>();
        crate::output::print_table(&["field", "kind", "value"], &rows);
    }
    Ok(())
}

fn render_item_list(
    output: OutputMode,
    items: &[DecryptedListedItem],
) -> Result<(), CliError> {
    if output.is_json() {
        return print_json(items);
    }

    let rows = items
        .iter()
        .map(|item| {
            vec![
                item.title.clone(),
                item.kind.clone(),
                item.item_id.to_string(),
                item.revision.to_string(),
                item.field_count.to_string(),
            ]
        })
        .collect::<Vec<_>>();
    crate::output::print_table(&["title", "kind", "item_id", "rev", "fields"], &rows);
    Ok(())
}

#[derive(Debug, Clone, Serialize)]
struct DecryptedListedItem {
    item_id: Uuid,
    title: String,
    kind: String,
    revision: i64,
    field_count: usize,
}
```

- [ ] **Step 6: Update `item get` branch**

In `crates/umbra-cli/src/commands.rs`, change the `ItemCommand::Get` pattern to include `title`.

Replace the old cached lookup:

```rust
let Some(revision) = cache.latest_item_revision(vault_id, item_id)? else {
    return Err(CliError::Input("cached item not found"));
};
let vault_key = unlock_vault_key(&config.active_profile, profile, &cache, vault_id)?;
let item = decrypt_cached_item(&vault_key, &revision)?;
print_json(&item.plaintext)
```

with:

```rust
let vault_key = unlock_vault_key(&config.active_profile, profile, &cache, vault_id)?;
let revision =
    select_cached_item_revision(&cache, &vault_key, vault_id, item_id, title.as_deref())?;
let item = decrypt_cached_item(&vault_key, &revision)?;
render_item_plaintext(output, revision.item_id, &item.plaintext)
```

- [ ] **Step 7: Update `item list` branch**

Replace:

```rust
print_json(&cache.list_latest_item_revisions(vault_id)?)
```

with:

```rust
if output.is_json() {
    print_json(&cache.list_latest_item_revisions(vault_id)?)
} else {
    let vault_key = unlock_vault_key(&config.active_profile, profile, &cache, vault_id)?;
    let mut items = Vec::new();
    for revision in cache.list_latest_item_revisions(vault_id)? {
        let Ok(wrapper) = serde_json::from_value::<ItemEnvelopeWrapper>(revision.envelope.clone())
        else {
            continue;
        };
        let kind = wrapper.kind.clone();
        let item = decrypt_cached_item_wrapper(&vault_key, &revision, wrapper)?;
        items.push(DecryptedListedItem {
            item_id: revision.item_id,
            title: item.plaintext.title,
            kind,
            revision: revision.revision,
            field_count: item.plaintext.fields.len(),
        });
    }
    render_item_list(output, &items)
}
```

- [ ] **Step 8: Run tests and clippy**

Run:

```bash
cargo test -p umbra-cli parses_item_get_by_title
cargo test -p umbra-cli
cargo clippy -p umbra-cli --all-targets --all-features -- -D warnings
```

Expected: PASS.

- [ ] **Step 9: Commit**

```bash
git add crates/umbra-cli/src/main.rs crates/umbra-cli/src/commands.rs crates/umbra-cli/src/tests.rs
git commit -m "feat(cli): get items by title"
```

---

### Task 5: Secret List And Remove

**Files:**
- Modify: `crates/umbra-cli/src/main.rs`
- Modify: `crates/umbra-cli/src/commands.rs`
- Modify: `crates/umbra-cli/src/item_plaintext.rs`
- Test: `crates/umbra-cli/src/tests.rs`
- Test: `crates/umbra-cli/src/item_plaintext.rs`

- [ ] **Step 1: Write parser tests**

Add to `crates/umbra-cli/src/tests.rs`:

```rust
#[test]
fn parses_secret_list_and_rm() {
    let list = Cli::parse_from(["umbra", "secret", "list", "pulzar/dev", "--vault", "Personal"]);
    let Command::Secret(SecretCommand::List {
        project_env,
        vault,
        offline,
        ..
    }) = list.command
    else {
        panic!("expected secret list");
    };
    assert_eq!(project_env, "pulzar/dev");
    assert_eq!(vault.as_deref(), Some("Personal"));
    assert!(!offline);

    let rm = Cli::parse_from([
        "umbra",
        "secret",
        "rm",
        "pulzar/dev",
        "DATABASE_URL",
        "--vault",
        "Personal",
    ]);
    let Command::Secret(SecretCommand::Rm {
        project_env,
        key,
        vault,
        ..
    }) = rm.command
    else {
        panic!("expected secret rm");
    };
    assert_eq!(project_env, "pulzar/dev");
    assert_eq!(key, "DATABASE_URL");
    assert_eq!(vault.as_deref(), Some("Personal"));
}
```

- [ ] **Step 2: Add plaintext removal test**

Add to `crates/umbra-cli/src/item_plaintext.rs` tests:

```rust
#[test]
fn remove_plaintext_field_removes_existing_field() {
    let mut item = build_secret_bundle("umbra/prod", "DATABASE_URL", "old");
    set_plaintext_field(&mut item, "OPENAI_API_KEY", "secret".to_owned());

    assert!(remove_plaintext_field(&mut item, "DATABASE_URL"));
    assert!(!remove_plaintext_field(&mut item, "MISSING"));
    assert_eq!(item.fields.len(), 1);
    assert_eq!(item.fields[0].name, "OPENAI_API_KEY");
}
```

- [ ] **Step 3: Run tests to verify they fail**

Run:

```bash
cargo test -p umbra-cli parses_secret_list_and_rm
cargo test -p umbra-cli remove_plaintext_field_removes_existing_field
```

Expected: FAIL because command variants and helper do not exist.

- [ ] **Step 4: Add command variants**

In `crates/umbra-cli/src/main.rs`, replace `SecretCommand` with:

```rust
#[derive(Debug, Subcommand)]
pub enum SecretCommand {
    Set {
        project_env: String,
        key: String,
        value: Option<String>,
        #[arg(long)]
        vault_id: Option<VaultId>,
        #[arg(long)]
        vault: Option<String>,
    },
    Get {
        project_env: String,
        key: String,
        #[arg(long)]
        vault_id: Option<VaultId>,
        #[arg(long)]
        vault: Option<String>,
        #[arg(long)]
        offline: bool,
    },
    List {
        project_env: String,
        #[arg(long)]
        vault_id: Option<VaultId>,
        #[arg(long)]
        vault: Option<String>,
        #[arg(long)]
        offline: bool,
    },
    Rm {
        project_env: String,
        key: String,
        #[arg(long)]
        vault_id: Option<VaultId>,
        #[arg(long)]
        vault: Option<String>,
    },
}
```

- [ ] **Step 5: Add plaintext removal helper**

In `crates/umbra-cli/src/item_plaintext.rs`, add after `set_plaintext_field`:

```rust
pub fn remove_plaintext_field(item: &mut ItemPlaintextV1, name: &str) -> bool {
    let before = item.fields.len();
    item.fields.retain(|field| field.name != name);
    item.fields.len() != before
}
```

- [ ] **Step 6: Add secret bundle resolver**

In `crates/umbra-cli/src/commands.rs`, add:

```rust
fn find_secret_bundle(
    cache: &crate::cache::LocalCache,
    vault_key: &VaultKey,
    vault_id: VaultId,
    project_env: &str,
) -> Result<Option<(crate::cache::CachedItemRevision, ItemPlaintextV1)>, CliError> {
    for revision in cache.list_latest_item_revisions(vault_id)? {
        let Ok(wrapper) = serde_json::from_value::<ItemEnvelopeWrapper>(revision.envelope.clone())
        else {
            continue;
        };
        if wrapper.kind != "env_bundle" {
            continue;
        }
        let item = decrypt_cached_item_wrapper(vault_key, &revision, wrapper)?;
        if item.plaintext.title == project_env {
            return Ok(Some((revision, item.plaintext)));
        }
    }
    Ok(None)
}

fn render_secret_list(output: OutputMode, plaintext: &ItemPlaintextV1) -> Result<(), CliError> {
    if output.is_json() {
        return print_json(plaintext);
    }

    let rows = plaintext
        .fields
        .iter()
        .map(|field| {
            vec![
                field.name.clone(),
                if field.sensitive {
                    "[secret]".to_owned()
                } else {
                    field.value.clone()
                },
            ]
        })
        .collect::<Vec<_>>();
    crate::output::print_table(&["key", "value"], &rows);
    Ok(())
}
```

- [ ] **Step 7: Use resolver in `secret set`**

In `SecretCommand::Set`, replace the manual loop that fills `existing_bundle` with:

```rust
let existing_bundle = find_secret_bundle(&cache, &vault_key, vault_id, &project_env)?;
```

Keep the existing create/update behavior below it.

- [ ] **Step 8: Implement `secret list` branch**

Add this branch before `SecretCommand::Get` or after it:

```rust
Command::Secret(SecretCommand::List {
    project_env,
    vault_id,
    vault,
    offline,
}) => {
    let profile = active_profile(&config)?;
    let mut cache = crate::cache::LocalCache::open(&config.active_profile)?;
    let vault_id = resolve_vault_id(profile, &cache, vault_id, vault.as_deref())?;
    let mode = if offline {
        crate::sync::SyncMode::Offline
    } else {
        require_login(profile)?;
        crate::sync::SyncMode::IfChanged
    };
    crate::sync::ensure_vault_synced(profile, &mut cache, vault_id, mode).await?;
    let vault_key = unlock_vault_key(&config.active_profile, profile, &cache, vault_id)?;
    let Some((_revision, plaintext)) =
        find_secret_bundle(&cache, &vault_key, vault_id, &project_env)?
    else {
        return Err(CliError::Input("secret bundle not found"));
    };
    render_secret_list(output, &plaintext)
}
```

- [ ] **Step 9: Implement `secret rm` branch**

Add this branch:

```rust
Command::Secret(SecretCommand::Rm {
    project_env,
    key,
    vault_id,
    vault,
}) => {
    let profile = active_profile(&config)?;
    require_login(profile)?;
    let client = UmbraHttpClient::new(profile)?;
    let mut cache = crate::cache::LocalCache::open(&config.active_profile)?;
    let vault_id = resolve_vault_id(profile, &cache, vault_id, vault.as_deref())?;
    crate::sync::ensure_vault_synced(
        profile,
        &mut cache,
        vault_id,
        crate::sync::SyncMode::IfChanged,
    )
    .await?;
    let vault_key = unlock_vault_key(&config.active_profile, profile, &cache, vault_id)?;
    let Some((revision, mut plaintext)) =
        find_secret_bundle(&cache, &vault_key, vault_id, &project_env)?
    else {
        return Err(CliError::Input("secret bundle not found"));
    };
    if !crate::item_plaintext::remove_plaintext_field(&mut plaintext, &key) {
        return Err(CliError::Input("secret key not found"));
    }

    let kind = ItemKind::EnvBundle;
    let kind_name = item_kind_name(&kind);
    let next_revision = revision.revision + 1;
    let envelope = encrypt_item_plaintext(
        vault_id,
        revision.item_id,
        next_revision,
        kind_name,
        &vault_key,
        &plaintext,
    )?;
    let response: ItemRevisionResponse = client
        .put(
            &format!("/api/v1/vaults/{vault_id}/items/{}", revision.item_id),
            &UpdateItemRequest {
                protocol_version: PROTOCOL_VERSION,
                vault_id,
                item_id: revision.item_id,
                expected_revision: revision.revision,
                envelope,
            },
        )
        .await?;
    cache.upsert_item_revision(&response)?;
    crate::sync::ensure_vault_synced(
        profile,
        &mut cache,
        vault_id,
        crate::sync::SyncMode::Always,
    )
    .await?;
    if output.is_json() {
        print_json(&response)
    } else {
        println!("removed {key} from {project_env}");
        Ok(())
    }
}
```

- [ ] **Step 10: Run tests and clippy**

Run:

```bash
cargo test -p umbra-cli parses_secret_list_and_rm
cargo test -p umbra-cli remove_plaintext_field_removes_existing_field
cargo test -p umbra-cli
cargo clippy -p umbra-cli --all-targets --all-features -- -D warnings
```

Expected: PASS.

- [ ] **Step 11: Commit**

```bash
git add crates/umbra-cli/src/main.rs crates/umbra-cli/src/commands.rs crates/umbra-cli/src/item_plaintext.rs crates/umbra-cli/src/tests.rs
git commit -m "feat(cli): list and remove secrets"
```

---

### Task 6: Make Create Commands Print Useful Summaries

**Files:**
- Modify: `crates/umbra-cli/src/commands.rs`

- [ ] **Step 1: Add mutation render helpers**

In `crates/umbra-cli/src/commands.rs`, add:

```rust
fn render_vault_created(output: OutputMode, vault: &VaultResponse) -> Result<(), CliError> {
    if output.is_json() {
        return print_json(vault);
    }

    crate::output::print_kv(&[
        ("created vault", vault.name.clone()),
        ("id", vault.vault_id.to_string()),
        ("kind", vault.kind.to_string()),
    ]);
    Ok(())
}

fn render_item_revision_created(
    output: OutputMode,
    action: &str,
    response: &ItemRevisionResponse,
) -> Result<(), CliError> {
    if output.is_json() {
        return print_json(response);
    }

    crate::output::print_kv(&[
        ("action", action.to_owned()),
        ("item_id", response.item_id.to_string()),
        ("vault_id", response.vault_id.to_string()),
        ("revision", response.revision.to_string()),
        ("vault revision", response.vault_revision.to_string()),
    ]);
    Ok(())
}
```

- [ ] **Step 2: Use summary for vault create**

In `VaultCommand::Create`, replace:

```rust
print_json(&vault)
```

with:

```rust
render_vault_created(output, &vault)
```

- [ ] **Step 3: Use summary for item create**

In `ItemCommand::Create`, replace:

```rust
print_json(&response)
```

with:

```rust
render_item_revision_created(output, "created item", &response)
```

- [ ] **Step 4: Use summary for secret set**

In `SecretCommand::Set`, replace:

```rust
print_json(&response)
```

with:

```rust
render_item_revision_created(output, "saved secret", &response)
```

- [ ] **Step 5: Run tests**

Run:

```bash
cargo test -p umbra-cli
cargo clippy -p umbra-cli --all-targets --all-features -- -D warnings
```

Expected: PASS.

- [ ] **Step 6: Commit**

```bash
git add crates/umbra-cli/src/commands.rs
git commit -m "feat(cli): summarize create commands"
```

---

### Task 7: Update README With Usable CLI Flow

**Files:**
- Modify: `README.md`

- [ ] **Step 1: Replace the CLI happy path command block**

In `README.md`, replace the command block under "Current CLI Happy Path" with:

```bash
umbra register \
  --server http://127.0.0.1:8080 \
  --email miguel@example.com \
  --profile personal

umbra login --profile personal

umbra vault create Personal
umbra vault list

umbra unlock --vault Personal --ttl-minutes 30

umbra secret set pulzar/dev DATABASE_URL "postgres://user:pass@localhost:5432/app" --vault Personal
umbra secret list pulzar/dev --vault Personal
umbra secret get pulzar/dev DATABASE_URL --vault Personal

umbra item create \
  --vault Personal \
  --kind login \
  --title GitHub \
  --field username=miguel \
  --field password=secret

umbra item list --vault Personal
umbra item get --vault Personal --title GitHub

umbra sync run --vault Personal
umbra status
umbra lock
```

- [ ] **Step 2: Add output mode note**

After the command block, add:

```markdown
Commands print human-readable output by default. Pass `--json` for scriptable output:

```bash
umbra --json vault list
umbra --json item get --vault Personal --title GitHub
```
```

- [ ] **Step 3: Update local cache command examples**

In the "Local CLI Cache" command block, replace:

```bash
umbra sync run --vault "$VAULT_ID"
umbra cache status
umbra item list --vault Personal
umbra item get --vault Personal --item-id "$ITEM_ID"
umbra item list --vault Personal --offline
umbra item get --vault Personal --item-id "$ITEM_ID" --offline
```

with:

```bash
umbra sync run --vault Personal
umbra cache status
umbra item list --vault Personal
umbra item get --vault Personal --title GitHub
umbra item list --vault Personal --offline
umbra item get --vault Personal --title GitHub --offline
```

- [ ] **Step 4: Commit docs**

```bash
git add README.md
git commit -m "docs(cli): simplify usage examples"
```

---

### Task 8: Final Verification And Push

**Files:**
- Verify all changed files.

- [ ] **Step 1: Run full verification**

Run:

```bash
cargo fmt --all -- --check
cargo test
cargo clippy --all-targets --all-features -- -D warnings
```

Expected: all commands pass.

- [ ] **Step 2: Inspect final git state**

Run:

```bash
git status --short --branch
git log --oneline --decorate -n 10
```

Expected: branch is `main`, working tree is clean, commits from this plan are ahead of `origin/main`.

- [ ] **Step 3: Push main**

Run:

```bash
git push origin main
```

Expected: push succeeds to `https://github.com/mi66mc/umbra.git`.

---

## Self-Review

Spec coverage:

- "Simplificar coisas complexas": reduces user-facing JSON noise, reduces UUID-only workflows, and adds helpers so `commands.rs` can stop growing only by duplication.
- "Ficar usável": adds title lookup, human output, secret listing/removal, and sync by vault name/default.
- Zero-knowledge boundary: unchanged; item search by title happens after local decrypt only.
- Server/protocol stability: no new server API required.

Placeholder scan:

- No task contains undefined placeholder text.
- Each task has concrete file paths, commands, expected results, and code blocks for code changes.

Type consistency:

- `OutputMode` is defined in Task 1 before use in later tasks.
- `SecretCommand::List` and `SecretCommand::Rm` are defined before command branches use them.
- `select_cached_item_revision`, `find_secret_bundle`, and render helpers are defined before branch code calls them.
