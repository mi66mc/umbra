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
    plaintext.fields.iter().map(secret_field_choice).collect()
}

fn secret_field_choice(field: &ItemField) -> SecretFieldChoice {
    SecretFieldChoice {
        key: field.name.clone(),
        sensitive: field.sensitive,
        label: format!(
            "{}  {}",
            field.name,
            if field.sensitive {
                "[secret]"
            } else {
                "[value hidden]"
            }
        ),
    }
}

#[allow(dead_code)]
pub fn select_vault(vaults: &[CachedVault]) -> Result<Option<uuid::Uuid>, CliError> {
    let choices = vault_choices(vaults);
    select_index(
        "Vault",
        choices.iter().map(|choice| choice.label.clone()).collect(),
    )
    .map(|selected| selected.map(|index| choices[index].vault_id))
}

#[allow(dead_code)]
pub fn select_item(
    items: &[crate::commands::DecryptedListedItem],
) -> Result<Option<uuid::Uuid>, CliError> {
    let choices = item_choices(items);
    select_index(
        "Item",
        choices.iter().map(|choice| choice.label.clone()).collect(),
    )
    .map(|selected| selected.map(|index| choices[index].item_id))
}

#[allow(dead_code)]
pub fn select_secret_key(plaintext: &ItemPlaintextV1) -> Result<Option<String>, CliError> {
    let choices = secret_field_choices(plaintext);
    select_index(
        "Secret key",
        choices.iter().map(|choice| choice.label.clone()).collect(),
    )
    .map(|selected| selected.map(|index| choices[index].key.clone()))
}

pub fn select_index(prompt: &str, labels: Vec<String>) -> Result<Option<usize>, CliError> {
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
    fn item_choices_include_title_kind_and_revision() {
        let item_id = uuid::Uuid::parse_str("00000000-0000-0000-0000-000000000002").unwrap();
        let choices = item_choices(&[crate::commands::DecryptedListedItem {
            item_id,
            title: "GitHub".to_owned(),
            kind: "login".to_owned(),
            revision: 5,
            field_count: 2,
        }]);

        assert_eq!(choices.len(), 1);
        assert_eq!(choices[0].item_id, item_id);
        assert_eq!(choices[0].title, "GitHub");
        assert_eq!(choices[0].kind, "login");
        assert_eq!(choices[0].revision, 5);
        assert_eq!(choices[0].label, "GitHub  login  rev:5");
    }

    #[test]
    fn secret_field_choices_never_include_values() {
        let mut item = ItemPlaintextV1::new("pulzar/dev");
        item.fields.push(ItemField::new(
            "DATABASE_URL",
            ItemFieldKind::Secret,
            "postgres://secret",
            true,
        ));
        item.fields.push(ItemField::new(
            "FEATURE_FLAG",
            ItemFieldKind::Text,
            "enabled",
            false,
        ));

        let choices = secret_field_choices(&item);

        assert_eq!(choices.len(), 2);
        assert_eq!(choices[0].key, "DATABASE_URL");
        assert!(choices[0].sensitive);
        assert_eq!(choices[0].label, "DATABASE_URL  [secret]");
        assert_eq!(choices[1].key, "FEATURE_FLAG");
        assert!(!choices[1].sensitive);
        assert_eq!(choices[1].label, "FEATURE_FLAG  [value hidden]");
        assert!(!format!("{choices:?}").contains("postgres://secret"));
        assert!(!format!("{choices:?}").contains("enabled"));
    }

    #[test]
    fn select_index_returns_none_for_empty_labels_without_prompting() {
        assert_eq!(select_index("Empty", Vec::new()).unwrap(), None);
    }
}
