# CLI Interactive Selection Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Make the CLI usable without memorizing UUIDs, item titles, or secret keys by adding explicit interactive selection for vaults, items, and secret fields in human mode.

**Architecture:** Keep the server/protocol unchanged and build interaction only in `umbra-cli`. Add a small `interactive` module that wraps `dialoguer::Select` and keeps prompt option formatting testable with pure functions. Commands use interactive prompts only in human output mode; JSON mode remains deterministic and fails with a clear selector error instead of prompting.

**Tech Stack:** Rust, clap, dialoguer, serde, existing local SQLite cache, existing client-side decrypt/sync helpers.

---

## Scope

This plan adds TUI-lite selection, not a full terminal app. It uses `dialoguer::Select` for short terminal lists.

New UX:

- `umbra item get --vault Personal` prompts the user to choose one decrypted item.
- `umbra secret get pulzar/dev --vault Personal` prompts the user to choose one key from that env bundle.
- `umbra secret rm pulzar/dev --vault Personal` prompts the user to choose one key to remove.
- Commands that need a vault and have no default vault can prompt for a cached vault in human mode.
- `--json` never prompts; it returns the existing clear input errors.

Non-goals:

- No full-screen TUI.
- No fuzzy search dependency.
- No new server endpoints.
- No interactive `item create` wizard yet.
- No interactive org/member management yet.

## File Structure

- Create `crates/umbra-cli/src/interactive.rs`
  - Contains testable option structs and label builders.
  - Contains thin `dialoguer::Select` wrappers for vault, item, and secret key selection.

- Modify `crates/umbra-cli/src/main.rs`
  - Add `mod interactive;`.
  - Change `SecretCommand::Get` and `SecretCommand::Rm` key positional argument to `Option<String>`.

- Modify `crates/umbra-cli/src/commands.rs`
  - Add human-mode vault fallback selection.
  - Add item prompt when `item get` has no `--item-id` and no `--title`.
  - Add secret key prompt when `secret get`/`secret rm` omit key.
  - Preserve non-interactive and JSON behavior.

- Modify `crates/umbra-cli/src/tests.rs`
  - Parser tests for optional secret key arguments.

- Modify `README.md`
  - Document the interactive commands.

---

### Task 1: Add Testable Interactive Selection Module

**Files:**
- Create: `crates/umbra-cli/src/interactive.rs`
- Modify: `crates/umbra-cli/src/main.rs`
- Test: `crates/umbra-cli/src/interactive.rs`

- [ ] **Step 1: Create `interactive.rs` with pure option builders**

Create `crates/umbra-cli/src/interactive.rs`:

```rust
use dialoguer::Select;
use umbra_core::{ItemField, ItemPlaintextV1};

use crate::cache::CachedVault;
use crate::error::CliError;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VaultChoice {
    pub vault_id: uuid::Uuid,
    pub label: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ItemChoice {
    pub item_id: uuid::Uuid,
    pub title: String,
    pub kind: String,
    pub revision: i64,
    pub label: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SecretFieldChoice {
    pub key: String,
    pub sensitive: bool,
    pub label: String,
}

pub fn vault_choices(vaults: &[CachedVault]) -> Vec<VaultChoice> {
    vaults
        .iter()
        .map(|vault| VaultChoice {
            vault_id: vault.vault_id,
            label: format!(
                "{}  {}  rev:{}",
                vault.name, vault.kind, vault.latest_vault_revision
            ),
        })
        .collect()
}

pub fn item_choices(items: &[crate::commands::DecryptedListedItem]) -> Vec<ItemChoice> {
    items
        .iter()
        .map(|item| ItemChoice {
            item_id: item.item_id,
            title: item.title.clone(),
            kind: item.kind.clone(),
            revision: item.revision,
            label: format!("{}  {}  rev:{}", item.title, item.kind, item.revision),
        })
        .collect()
}

pub fn secret_field_choices(plaintext: &ItemPlaintextV1) -> Vec<SecretFieldChoice> {
    plaintext
        .fields
        .iter()
        .map(secret_field_choice)
        .collect()
}

fn secret_field_choice(field: &ItemField) -> SecretFieldChoice {
    SecretFieldChoice {
        key: field.name.clone(),
        sensitive: field.sensitive,
        label: format!(
            "{}  {}",
            field.name,
            if field.sensitive { "[secret]" } else { "[value hidden]" }
        ),
    }
}

pub fn select_vault(vaults: &[CachedVault]) -> Result<Option<uuid::Uuid>, CliError> {
    let choices = vault_choices(vaults);
    select_index("Vault", choices.iter().map(|choice| choice.label.clone()).collect())
        .map(|selected| selected.map(|index| choices[index].vault_id))
}

pub fn select_item(items: &[crate::commands::DecryptedListedItem]) -> Result<Option<uuid::Uuid>, CliError> {
    let choices = item_choices(items);
    select_index("Item", choices.iter().map(|choice| choice.label.clone()).collect())
        .map(|selected| selected.map(|index| choices[index].item_id))
}

pub fn select_secret_key(plaintext: &ItemPlaintextV1) -> Result<Option<String>, CliError> {
    let choices = secret_field_choices(plaintext);
    select_index("Secret key", choices.iter().map(|choice| choice.label.clone()).collect())
        .map(|selected| selected.map(|index| choices[index].key.clone()))
}

fn select_index(prompt: &str, labels: Vec<String>) -> Result<Option<usize>, CliError> {
    if labels.is_empty() {
        return Ok(None);
    }

    let selected = Select::new()
        .with_prompt(prompt)
        .items(&labels)
        .default(0)
        .interact_opt()?;
    Ok(selected)
}

#[cfg(test)]
mod tests {
    use super::*;
    use umbra_core::{ItemField, ItemFieldKind, ItemPlaintextV1};

    #[test]
    fn vault_choices_include_name_kind_and_revision() {
        let vault_id = uuid::Uuid::parse_str("00000000-0000-0000-0000-000000000001").unwrap();
        let choices = vault_choices(&[CachedVault {
            vault_id,
            name: "Personal".to_owned(),
            kind: "personal".to_owned(),
            latest_vault_revision: 7,
            latest_access_revision: 3,
            current_key_generation: 1,
            needs_key_rotation: false,
        }]);

        assert_eq!(choices.len(), 1);
        assert_eq!(choices[0].vault_id, vault_id);
        assert_eq!(choices[0].label, "Personal  personal  rev:7");
    }

    #[test]
    fn secret_field_choices_never_include_values() {
        let mut item = ItemPlaintextV1::new("pulzar/dev");
        item.fields.push(ItemField::new(
            "DATABASE_URL".to_owned(),
            ItemFieldKind::Secret,
            "postgres://secret".to_owned(),
            true,
        ));
        item.fields.push(ItemField::new(
            "FEATURE_FLAG".to_owned(),
            ItemFieldKind::Text,
            "enabled".to_owned(),
            false,
        ));

        let choices = secret_field_choices(&item);

        assert_eq!(choices.len(), 2);
        assert_eq!(choices[0].key, "DATABASE_URL");
        assert!(choices[0].sensitive);
        assert!(!format!("{choices:?}").contains("postgres://secret"));
        assert!(!format!("{choices:?}").contains("enabled"));
    }
}
```

- [ ] **Step 2: Run test to verify compile failures are isolated**

Run:

```bash
cargo test -p umbra-cli interactive
```

Expected: FAIL because `main.rs` does not declare `mod interactive`, and `DecryptedListedItem` is not public yet.

- [ ] **Step 3: Declare module and expose listed item type**

In `crates/umbra-cli/src/main.rs`, add:

```rust
mod interactive;
```

near the other module declarations.

In `crates/umbra-cli/src/commands.rs`, change:

```rust
struct DecryptedListedItem {
    item_id: Uuid,
    title: String,
    kind: String,
    revision: i64,
    field_count: usize,
}
```

to:

```rust
pub(crate) struct DecryptedListedItem {
    pub(crate) item_id: Uuid,
    pub(crate) title: String,
    pub(crate) kind: String,
    pub(crate) revision: i64,
    pub(crate) field_count: usize,
}
```

- [ ] **Step 4: Run tests**

Run:

```bash
cargo test -p umbra-cli interactive
cargo test -p umbra-cli
```

Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add crates/umbra-cli/src/main.rs crates/umbra-cli/src/commands.rs crates/umbra-cli/src/interactive.rs
git commit -m "feat(cli): add interactive selection helpers"
```

---

### Task 2: Interactive Vault Selection Fallback

**Files:**
- Modify: `crates/umbra-cli/src/commands.rs`
- Test: `crates/umbra-cli/src/commands.rs`

- [ ] **Step 1: Add test for default vault fallback error in JSON mode**

Add this test to the existing `#[cfg(test)] mod tests` in `crates/umbra-cli/src/commands.rs`:

```rust
#[test]
fn resolve_vault_id_keeps_json_mode_non_interactive() {
    let profile = crate::config::ProfileConfig::default();
    let cache = crate::cache::LocalCache::open_in_memory("personal").unwrap();

    assert!(matches!(
        resolve_vault_id_for_output(&profile, &cache, None, None, OutputMode::Json),
        Err(CliError::Input(
            "no default vault configured; pass --vault-id/--vault or create a vault first"
        ))
    ));
}
```

- [ ] **Step 2: Run test to verify it fails**

Run:

```bash
cargo test -p umbra-cli resolve_vault_id_keeps_json_mode_non_interactive
```

Expected: FAIL because `resolve_vault_id_for_output` does not exist.

- [ ] **Step 3: Add output-aware vault resolver**

In `crates/umbra-cli/src/commands.rs`, keep the existing `resolve_vault_id` as a non-interactive resolver and add:

```rust
fn resolve_vault_id_for_output(
    profile: &crate::config::ProfileConfig,
    cache: &crate::cache::LocalCache,
    vault_id: Option<VaultId>,
    vault_name: Option<&str>,
    output: OutputMode,
) -> Result<VaultId, CliError> {
    match resolve_vault_id(profile, cache, vault_id, vault_name) {
        Ok(vault_id) => Ok(vault_id),
        Err(CliError::Input("no default vault configured; pass --vault-id/--vault or create a vault first"))
            if !output.is_json() =>
        {
            let vaults = cache.list_vaults()?;
            if vaults.is_empty() {
                return Err(CliError::Input(
                    "no cached vaults; run `umbra vault list` first",
                ));
            }
            crate::interactive::select_vault(&vaults)?
                .ok_or(CliError::Input("vault selection cancelled"))
        }
        Err(error) => Err(error),
    }
}
```

- [ ] **Step 4: Use output-aware resolver in user-facing commands**

In `crates/umbra-cli/src/commands.rs`, replace calls like:

```rust
resolve_vault_id(profile, &cache, vault_id, vault.as_deref())?
```

with:

```rust
resolve_vault_id_for_output(profile, &cache, vault_id, vault.as_deref(), output)?
```

only in these branches:

- `ItemCommand::List`
- `ItemCommand::Get`
- `ItemCommand::Create`
- `SecretCommand::Set`
- `SecretCommand::Get`
- `SecretCommand::List`
- `SecretCommand::Rm`
- `SyncCommand::Run`

Do not change low-level update commands that require explicit IDs.

- [ ] **Step 5: Run tests and clippy**

Run:

```bash
cargo test -p umbra-cli resolve_vault_id_keeps_json_mode_non_interactive
cargo test -p umbra-cli
cargo clippy -p umbra-cli --all-targets --all-features -- -D warnings
```

Expected: PASS.

- [ ] **Step 6: Commit**

```bash
git add crates/umbra-cli/src/commands.rs
git commit -m "feat(cli): prompt for vault selection"
```

---

### Task 3: Interactive Item Selection For `item get`

**Files:**
- Modify: `crates/umbra-cli/src/commands.rs`
- Test: `crates/umbra-cli/src/commands.rs`

- [ ] **Step 1: Add test for JSON mode missing item selector**

Add this test to `crates/umbra-cli/src/commands.rs` tests:

```rust
#[test]
fn item_selector_requires_selector_in_json_mode() {
    let cache = crate::cache::LocalCache::open_in_memory("personal").unwrap();
    let vault_id = Uuid::parse_str("00000000-0000-0000-0000-000000000001").unwrap();

    assert!(matches!(
        select_cached_item_revision_before_unlock_for_output(
            &cache,
            vault_id,
            None,
            None,
            OutputMode::Json
        ),
        Err(CliError::Input("pass --item-id or --title"))
    ));
}
```

- [ ] **Step 2: Run test to verify it fails**

Run:

```bash
cargo test -p umbra-cli item_selector_requires_selector_in_json_mode
```

Expected: FAIL because `select_cached_item_revision_before_unlock_for_output` does not exist.

- [ ] **Step 3: Add output-aware pre-unlock selector**

In `crates/umbra-cli/src/commands.rs`, add:

```rust
enum ItemSelectionNeed {
    Selected(crate::cache::CachedItemRevision),
    NeedsTitleDecrypt,
    NeedsInteractiveDecrypt,
}

fn select_cached_item_revision_before_unlock_for_output(
    cache: &crate::cache::LocalCache,
    vault_id: VaultId,
    item_id: Option<Uuid>,
    title: Option<&str>,
    output: OutputMode,
) -> Result<ItemSelectionNeed, CliError> {
    if item_id.is_some() && title.is_some() {
        return Err(CliError::Input("use either --item-id or --title, not both"));
    }

    if let Some(item_id) = item_id {
        return cache
            .latest_item_revision(vault_id, item_id)?
            .ok_or(CliError::Input("cached item not found"))
            .map(ItemSelectionNeed::Selected);
    }

    if title.is_some() {
        return Ok(ItemSelectionNeed::NeedsTitleDecrypt);
    }

    if output.is_json() {
        return Err(CliError::Input("pass --item-id or --title"));
    }

    Ok(ItemSelectionNeed::NeedsInteractiveDecrypt)
}
```

- [ ] **Step 4: Add decrypted item collection helper**

In `crates/umbra-cli/src/commands.rs`, add near `render_item_list`:

```rust
fn decrypted_listed_items(
    cache: &crate::cache::LocalCache,
    vault_key: &VaultKey,
    vault_id: VaultId,
) -> Result<Vec<DecryptedListedItem>, CliError> {
    let mut items = Vec::new();
    for revision in cache.list_latest_item_revisions(vault_id)? {
        let Ok(wrapper) = serde_json::from_value::<ItemEnvelopeWrapper>(revision.envelope.clone())
        else {
            continue;
        };
        let kind = wrapper.kind.clone();
        let item = decrypt_cached_item_wrapper(vault_key, &revision, wrapper)?;
        items.push(DecryptedListedItem {
            item_id: revision.item_id,
            title: item.plaintext.title,
            kind,
            revision: revision.revision,
            field_count: item.plaintext.fields.len(),
        });
    }
    Ok(items)
}
```

Then update `ItemCommand::List` human mode to call this helper instead of duplicating the loop.

- [ ] **Step 5: Add interactive item resolver**

Add:

```rust
fn select_cached_item_revision_interactively(
    cache: &crate::cache::LocalCache,
    vault_key: &VaultKey,
    vault_id: VaultId,
) -> Result<crate::cache::CachedItemRevision, CliError> {
    let items = decrypted_listed_items(cache, vault_key, vault_id)?;
    let item_id = crate::interactive::select_item(&items)?
        .ok_or(CliError::Input("item selection cancelled"))?;
    cache
        .latest_item_revision(vault_id, item_id)?
        .ok_or(CliError::Input("cached item not found"))
}
```

- [ ] **Step 6: Update `ItemCommand::Get` branch**

Replace the current pre-unlock selection:

```rust
let selected_revision = select_cached_item_revision_before_unlock(
    &cache,
    vault_id,
    item_id,
    title.as_deref(),
)?;
let vault_key = unlock_vault_key(&config.active_profile, profile, &cache, vault_id)?;
let revision = match selected_revision {
    Some(revision) => revision,
    None => select_cached_item_revision_by_title(
        &cache,
        &vault_key,
        vault_id,
        title.as_deref().expect("title selector was validated"),
    )?,
};
```

with:

```rust
let selection = select_cached_item_revision_before_unlock_for_output(
    &cache,
    vault_id,
    item_id,
    title.as_deref(),
    output,
)?;
let vault_key = unlock_vault_key(&config.active_profile, profile, &cache, vault_id)?;
let revision = match selection {
    ItemSelectionNeed::Selected(revision) => revision,
    ItemSelectionNeed::NeedsTitleDecrypt => select_cached_item_revision_by_title(
        &cache,
        &vault_key,
        vault_id,
        title.as_deref().expect("title selector was validated"),
    )?,
    ItemSelectionNeed::NeedsInteractiveDecrypt => {
        select_cached_item_revision_interactively(&cache, &vault_key, vault_id)?
    }
};
```

- [ ] **Step 7: Keep old tests passing**

Update any direct unit tests that called `select_cached_item_revision_before_unlock` to call `select_cached_item_revision_before_unlock_for_output(..., OutputMode::Json)`.

- [ ] **Step 8: Run tests and clippy**

Run:

```bash
cargo test -p umbra-cli item_selector_requires_selector_in_json_mode
cargo test -p umbra-cli
cargo clippy -p umbra-cli --all-targets --all-features -- -D warnings
```

Expected: PASS.

- [ ] **Step 9: Commit**

```bash
git add crates/umbra-cli/src/commands.rs
git commit -m "feat(cli): prompt for item selection"
```

---

### Task 4: Interactive Secret Key Selection

**Files:**
- Modify: `crates/umbra-cli/src/main.rs`
- Modify: `crates/umbra-cli/src/commands.rs`
- Modify: `crates/umbra-cli/src/tests.rs`

- [ ] **Step 1: Add parser tests for optional secret key**

Add to `crates/umbra-cli/src/tests.rs`:

```rust
#[test]
fn parses_secret_get_and_rm_without_key_for_interactive_selection() {
    let get = Cli::parse_from(["umbra", "secret", "get", "pulzar/dev", "--vault", "Personal"]);
    let Command::Secret(SecretCommand::Get {
        project_env,
        key,
        vault,
        ..
    }) = get.command
    else {
        panic!("expected secret get");
    };
    assert_eq!(project_env, "pulzar/dev");
    assert_eq!(key, None);
    assert_eq!(vault.as_deref(), Some("Personal"));

    let rm = Cli::parse_from(["umbra", "secret", "rm", "pulzar/dev", "--vault", "Personal"]);
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
    assert_eq!(key, None);
    assert_eq!(vault.as_deref(), Some("Personal"));
}
```

- [ ] **Step 2: Run test to verify it fails**

Run:

```bash
cargo test -p umbra-cli parses_secret_get_and_rm_without_key_for_interactive_selection
```

Expected: FAIL because `key` is required.

- [ ] **Step 3: Make secret keys optional in command shapes**

In `crates/umbra-cli/src/main.rs`, change:

```rust
key: String,
```

to:

```rust
key: Option<String>,
```

for `SecretCommand::Get` and `SecretCommand::Rm` only.

- [ ] **Step 4: Add secret key resolver**

In `crates/umbra-cli/src/commands.rs`, add:

```rust
fn resolve_secret_key_for_output(
    key: Option<String>,
    plaintext: &ItemPlaintextV1,
    output: OutputMode,
) -> Result<String, CliError> {
    if let Some(key) = key {
        return Ok(key);
    }

    if output.is_json() {
        return Err(CliError::Input("pass a secret key"));
    }

    crate::interactive::select_secret_key(plaintext)?
        .ok_or(CliError::Input("secret key selection cancelled"))
}
```

- [ ] **Step 5: Update `SecretCommand::Get` branch**

In the `SecretCommand::Get` branch, after loading `plaintext`, replace direct `key` usage with:

```rust
let key = resolve_secret_key_for_output(key, &item.plaintext, output)?;
if let Some(field) = item.plaintext.fields.iter().find(|field| field.name == key) {
    println!("{}", field.value);
    return Ok(());
}
```

The branch pattern must now bind `key` as `Option<String>`.

- [ ] **Step 6: Update `SecretCommand::Rm` branch**

In the `SecretCommand::Rm` branch, after finding `plaintext` and before removing, add:

```rust
let key = resolve_secret_key_for_output(key, &plaintext, output)?;
```

Then keep:

```rust
if !crate::item_plaintext::remove_plaintext_field(&mut plaintext, &key) {
    return Err(CliError::Input("secret key not found"));
}
```

- [ ] **Step 7: Update existing parser tests**

In `crates/umbra-cli/src/tests.rs`, update tests that match `SecretCommand::Get` or `SecretCommand::Rm` to compare `key.as_deref()` with `Some("...")` instead of comparing a `String`.

Example:

```rust
Command::Secret(SecretCommand::Get {
    project_env,
    key,
    ..
}) if project_env == "umbra/prod" && key.as_deref() == Some("OPENAI_API_KEY")
```

- [ ] **Step 8: Run tests and clippy**

Run:

```bash
cargo test -p umbra-cli parses_secret_get_and_rm_without_key_for_interactive_selection
cargo test -p umbra-cli parses_secret_commands
cargo test -p umbra-cli
cargo clippy -p umbra-cli --all-targets --all-features -- -D warnings
```

Expected: PASS.

- [ ] **Step 9: Commit**

```bash
git add crates/umbra-cli/src/main.rs crates/umbra-cli/src/commands.rs crates/umbra-cli/src/tests.rs
git commit -m "feat(cli): prompt for secret keys"
```

---

### Task 5: Docs For Interactive Selection

**Files:**
- Modify: `README.md`

- [ ] **Step 1: Update happy path examples**

In `README.md`, after:

```bash
umbra item get --vault Personal --title GitHub
```

add:

```bash
# omit --title/--item-id to choose from a terminal list
umbra item get --vault Personal
```

After:

```bash
umbra secret get pulzar/dev DATABASE_URL --vault Personal
```

add:

```bash
# omit the key to choose from a terminal list
umbra secret get pulzar/dev --vault Personal
```

- [ ] **Step 2: Add note about non-interactive JSON mode**

After the `--json` examples, add:

```markdown
Interactive selection only runs in human output mode. Commands run with `--json` require explicit selectors and never open prompts.
```

- [ ] **Step 3: Commit docs**

```bash
git add README.md
git commit -m "docs(cli): document interactive selection"
```

---

### Task 6: Final Verification And Push

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

- [ ] **Step 2: Inspect git status and commits**

Run:

```bash
git status --short --branch
git log --oneline --decorate -n 10
```

Expected: working tree clean, branch `main` ahead of `origin/main` by this plan's commits.

- [ ] **Step 3: Push main**

Run:

```bash
git push origin main
```

Expected: push succeeds.

---

## Self-Review

Spec coverage:

- Adds the requested TUI-like selection for the highest-friction paths: vault, item, and secret key selection.
- Keeps automation safe by making `--json` non-interactive.
- Does not add unrelated frontend/server/protocol work.

Placeholder scan:

- No placeholder sections remain.
- Each implementation step has concrete files, code, commands, and expected results.

Type consistency:

- `DecryptedListedItem` is made `pub(crate)` before `interactive.rs` uses it.
- `SecretCommand::Get` and `SecretCommand::Rm` use `Option<String>` consistently after Task 4.
- `OutputMode` is already in the codebase and is used consistently to decide whether prompts can run.
