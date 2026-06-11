use serde::{Deserialize, Serialize};
use uuid::Uuid;

pub type UserId = Uuid;
pub type DeviceId = Uuid;
pub type VaultId = Uuid;
pub type ItemId = Uuid;
pub type OrgId = Uuid;
pub type RevisionId = i64;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum VaultKind {
    Personal,
    Shared,
    Project,
    Org,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum VaultRole {
    Owner,
    Admin,
    Editor,
    Viewer,
}

impl VaultRole {
    pub fn can_invite_members(self) -> bool {
        matches!(self, Self::Owner | Self::Admin)
    }

    pub fn can_write_items(self) -> bool {
        matches!(self, Self::Owner | Self::Admin | Self::Editor)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum MemberState {
    Active,
    Invited,
    Removed,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ItemKind {
    Login,
    SecureNote,
    SshKey,
    ApiKey,
    Token,
    EnvVar,
    EnvBundle,
    CreditCard,
    Custom(String),
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Vault {
    pub id: VaultId,
    pub org_id: Option<OrgId>,
    pub name: String,
    pub kind: VaultKind,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct VaultMember {
    pub vault_id: VaultId,
    pub user_id: UserId,
    pub role: VaultRole,
    pub state: MemberState,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EncryptedBlob {
    pub envelope_version: u16,
    pub envelope: serde_json::Value,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct VaultItem {
    pub id: ItemId,
    pub vault_id: VaultId,
    pub kind: ItemKind,
    pub current_revision: RevisionId,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EncryptedItem {
    pub item: VaultItem,
    pub encrypted_blob: EncryptedBlob,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SyncState {
    pub vault_id: VaultId,
    pub last_seen_vault_revision: RevisionId,
}

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum ValidationError {
    #[error("vault name cannot be empty")]
    EmptyVaultName,
    #[error("vault name cannot exceed 120 characters")]
    VaultNameTooLong,
}

pub fn validate_vault_name(name: &str) -> Result<(), ValidationError> {
    let trimmed = name.trim();
    if trimmed.is_empty() {
        return Err(ValidationError::EmptyVaultName);
    }
    if trimmed.chars().count() > 120 {
        return Err(ValidationError::VaultNameTooLong);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn validates_vault_names() {
        assert!(validate_vault_name("Personal").is_ok());
        assert_eq!(
            validate_vault_name(""),
            Err(ValidationError::EmptyVaultName)
        );
    }
}
