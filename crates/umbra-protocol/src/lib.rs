use serde::{Deserialize, Serialize};
use umbra_core::{
    DeviceId, ItemId, ItemKind, OrgId, OrgRole, RevisionId, UserId, VaultId, VaultKind, VaultRole,
};

pub const PROTOCOL_VERSION: u16 = 1;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RegisterRequest {
    pub protocol_version: u16,
    pub email: String,
    pub display_name: Option<String>,
    pub public_key: String,
    pub encrypted_private_key: serde_json::Value,
    pub initial_device: DeviceRegisterRequest,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct OpaqueRegisterStartRequest {
    pub protocol_version: u16,
    pub email: String,
    pub registration_request: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct OpaqueRegisterStartResponse {
    pub registration_id: uuid::Uuid,
    pub registration_response: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct OpaqueRegisterFinishRequest {
    pub protocol_version: u16,
    pub registration_id: uuid::Uuid,
    pub email: String,
    pub display_name: Option<String>,
    pub public_key: String,
    pub encrypted_private_key: serde_json::Value,
    pub initial_device: DeviceRegisterRequest,
    pub registration_upload: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct OpaqueLoginStartRequest {
    pub protocol_version: u16,
    pub email: String,
    pub credential_request: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct OpaqueLoginStartResponse {
    pub login_id: uuid::Uuid,
    pub credential_response: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct OpaqueLoginFinishRequest {
    pub protocol_version: u16,
    pub login_id: uuid::Uuid,
    #[serde(default)]
    pub device_id: Option<DeviceId>,
    pub credential_finalization: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct OpaqueLoginFinishResponse {
    pub user_id: UserId,
    pub session_id: uuid::Uuid,
    pub session_token: Option<String>,
    pub auth_scheme: String,
    pub encrypted_private_key: serde_json::Value,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RegisterResponse {
    pub user_id: UserId,
    pub device_id: DeviceId,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct LoginRequest {
    pub protocol_version: u16,
    pub email: String,
    pub device_id: Option<DeviceId>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct LoginResponse {
    pub user_id: UserId,
    pub encrypted_private_key: serde_json::Value,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DeviceRegisterRequest {
    pub name: String,
    pub public_key: String,
    pub fingerprint: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DeviceTrustRequest {
    pub protocol_version: u16,
    pub device_id: DeviceId,
    pub trust_proof: serde_json::Value,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CreateVaultRequest {
    pub protocol_version: u16,
    #[serde(default)]
    pub vault_id: Option<VaultId>,
    pub name: String,
    pub kind: VaultKind,
    pub initial_key_wrapping: serde_json::Value,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CreateOrgRequest {
    pub protocol_version: u16,
    pub name: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct OrgResponse {
    pub org_id: OrgId,
    pub name: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AddOrgMemberRequest {
    pub protocol_version: u16,
    pub user_id: UserId,
    pub role: OrgRole,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CreateOrgVaultRequest {
    pub protocol_version: u16,
    #[serde(default)]
    pub vault_id: Option<VaultId>,
    pub name: String,
    pub kind: VaultKind,
    pub initial_key_wrapping: serde_json::Value,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct VaultResponse {
    pub vault_id: VaultId,
    pub org_id: Option<OrgId>,
    pub name: String,
    pub kind: VaultKind,
    pub vault_revision: RevisionId,
    pub access_revision: RevisionId,
    pub current_key_generation: i64,
    pub needs_key_rotation: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AddVaultMemberRequest {
    pub protocol_version: u16,
    pub user_id: UserId,
    pub role: VaultRole,
    pub vault_key_wrapping: serde_json::Value,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RotationStatusResponse {
    pub vault_id: VaultId,
    pub current_key_generation: i64,
    pub needs_key_rotation: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RotateVaultKeyRequest {
    pub protocol_version: u16,
    pub from_generation: i64,
    pub to_generation: i64,
    pub new_wrappings: Vec<RotationVaultKeyWrapping>,
    pub reencrypted_revisions: Vec<RotationItemRevision>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RotationVaultKeyWrapping {
    pub user_id: UserId,
    pub device_id: Option<DeviceId>,
    pub wrapping_type: String,
    pub envelope: serde_json::Value,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RotationItemRevision {
    pub item_id: ItemId,
    pub expected_revision: RevisionId,
    pub envelope: serde_json::Value,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct InviteMemberRequest {
    pub protocol_version: u16,
    pub vault_id: VaultId,
    pub email: String,
    pub role: VaultRole,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AcceptInviteRequest {
    pub protocol_version: u16,
    pub invite_id: uuid::Uuid,
    pub device_id: DeviceId,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CreateItemRequest {
    pub protocol_version: u16,
    pub vault_id: VaultId,
    #[serde(default)]
    pub item_id: Option<ItemId>,
    pub kind: ItemKind,
    pub envelope: serde_json::Value,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct UpdateItemRequest {
    pub protocol_version: u16,
    pub vault_id: VaultId,
    pub item_id: ItemId,
    pub expected_revision: RevisionId,
    pub envelope: serde_json::Value,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DeleteItemRequest {
    pub protocol_version: u16,
    pub vault_id: VaultId,
    pub item_id: ItemId,
    pub expected_revision: RevisionId,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ItemRevisionResponse {
    pub item_id: ItemId,
    pub vault_id: VaultId,
    pub revision: RevisionId,
    pub vault_revision: RevisionId,
    pub key_generation: RevisionId,
    pub author_user_id: Option<UserId>,
    pub envelope: serde_json::Value,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct VaultKeyWrappingResponse {
    pub id: uuid::Uuid,
    pub vault_id: VaultId,
    pub user_id: UserId,
    pub device_id: Option<DeviceId>,
    pub wrapping_type: String,
    pub envelope: serde_json::Value,
    pub key_generation: RevisionId,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SyncStatusRequest {
    pub protocol_version: u16,
    pub vaults: Vec<VaultStatusCursor>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct VaultStatusCursor {
    pub vault_id: VaultId,
    pub known_vault_revision: RevisionId,
    pub known_access_revision: RevisionId,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SyncStatusResponse {
    pub protocol_version: u16,
    pub vaults: Vec<VaultStatus>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct VaultStatus {
    pub vault_id: VaultId,
    pub latest_vault_revision: RevisionId,
    pub latest_access_revision: RevisionId,
    pub current_key_generation: RevisionId,
    pub needs_key_rotation: bool,
    pub items_changed: bool,
    pub access_changed: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SyncRequest {
    pub protocol_version: u16,
    pub device_id: DeviceId,
    pub vaults: Vec<VaultSyncCursor>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct VaultSyncCursor {
    pub vault_id: VaultId,
    pub since_vault_revision: RevisionId,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SyncResponse {
    pub protocol_version: u16,
    pub vaults: Vec<VaultSyncChanges>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct VaultSyncChanges {
    pub vault_id: VaultId,
    pub latest_vault_revision: RevisionId,
    pub latest_access_revision: RevisionId,
    pub items: Vec<ItemRevisionResponse>,
    pub deleted_items: Vec<ItemId>,
    pub key_wrappings: Vec<VaultKeyWrappingResponse>,
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;
    use uuid::Uuid;

    #[test]
    fn item_revision_response_roundtrips() {
        let response = ItemRevisionResponse {
            item_id: Uuid::new_v4(),
            vault_id: Uuid::new_v4(),
            revision: 2,
            vault_revision: 7,
            key_generation: 1,
            author_user_id: Some(Uuid::new_v4()),
            envelope: json!({"version": 1, "ciphertext": "abc"}),
        };

        let encoded = serde_json::to_string(&response).unwrap();
        let decoded: ItemRevisionResponse = serde_json::from_str(&encoded).unwrap();

        assert_eq!(decoded, response);
    }

    #[test]
    fn sync_response_uses_typed_changes() {
        let vault_id = Uuid::new_v4();
        let item_id = Uuid::new_v4();
        let user_id = Uuid::new_v4();
        let response = SyncResponse {
            protocol_version: PROTOCOL_VERSION,
            vaults: vec![VaultSyncChanges {
                vault_id,
                latest_vault_revision: 10,
                latest_access_revision: 4,
                items: vec![ItemRevisionResponse {
                    item_id,
                    vault_id,
                    revision: 1,
                    vault_revision: 10,
                    key_generation: 1,
                    author_user_id: Some(user_id),
                    envelope: json!({"ciphertext": "encrypted"}),
                }],
                deleted_items: vec![],
                key_wrappings: vec![VaultKeyWrappingResponse {
                    id: Uuid::new_v4(),
                    vault_id,
                    user_id,
                    device_id: None,
                    wrapping_type: "user_public_key".to_owned(),
                    envelope: json!({"wrapped": true}),
                    key_generation: 1,
                }],
            }],
        };

        let encoded = serde_json::to_value(&response).unwrap();

        assert_eq!(encoded["protocol_version"], json!(1));
        assert_eq!(encoded["vaults"][0]["latest_access_revision"], json!(4));
        assert_eq!(encoded["vaults"][0]["items"][0]["revision"], json!(1));
        assert_eq!(
            encoded["vaults"][0]["key_wrappings"][0]["wrapping_type"],
            json!("user_public_key")
        );
    }

    #[test]
    fn sync_status_roundtrips() {
        let vault_id = Uuid::new_v4();
        let response = SyncStatusResponse {
            protocol_version: PROTOCOL_VERSION,
            vaults: vec![VaultStatus {
                vault_id,
                latest_vault_revision: 7,
                latest_access_revision: 3,
                current_key_generation: 2,
                needs_key_rotation: false,
                items_changed: true,
                access_changed: false,
            }],
        };

        let encoded = serde_json::to_string(&response).unwrap();
        let decoded: SyncStatusResponse = serde_json::from_str(&encoded).unwrap();

        assert_eq!(decoded, response);
    }
}
