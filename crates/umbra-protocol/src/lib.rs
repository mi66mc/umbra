use serde::{Deserialize, Serialize};
use umbra_core::{
    DeviceId, DeviceState, ItemId, ItemKind, MemberState, OrgId, OrgRole, RevisionId, UserId,
    VaultId, VaultKind, VaultRole,
};

pub const PROTOCOL_VERSION: u16 = 1;
pub const SYNC_INTEGRITY_PROTOCOL_VERSION: u16 = 2;
pub const DEVICE_SCOPED_WRAPPING_PROTOCOL_VERSION: u16 = 3;

pub const fn is_supported_protocol_version(version: u16) -> bool {
    matches!(
        version,
        PROTOCOL_VERSION
            | SYNC_INTEGRITY_PROTOCOL_VERSION
            | DEVICE_SCOPED_WRAPPING_PROTOCOL_VERSION
    )
}

pub const fn is_sync_integrity_protocol_version(version: u16) -> bool {
    version == SYNC_INTEGRITY_PROTOCOL_VERSION
}

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
    #[serde(default)]
    pub pending_device: Option<PendingDeviceRequest>,
    pub credential_finalization: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct OpaqueLoginFinishResponse {
    pub user_id: UserId,
    pub session_id: uuid::Uuid,
    pub session_token: Option<String>,
    pub auth_scheme: String,
    pub encrypted_private_key: serde_json::Value,
    #[serde(default)]
    pub pending_device: Option<PendingDeviceResponse>,
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
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub encryption_public_key: Option<String>,
    pub fingerprint: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DeviceTrustRequest {
    pub protocol_version: u16,
    pub device_id: DeviceId,
    pub trust_proof: serde_json::Value,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DeviceResponse {
    pub device_id: DeviceId,
    pub name: String,
    pub public_key: Option<String>,
    pub fingerprint: String,
    pub state: DeviceState,
    pub created_at: String,
    pub trusted_at: Option<String>,
    pub revoked_at: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PendingDeviceRequest {
    pub protocol_version: u16,
    pub name: String,
    pub public_key: String,
    pub fingerprint: String,
    pub bootstrap_public_key: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PendingDeviceResponse {
    pub device_id: DeviceId,
    pub session_id: uuid::Uuid,
    pub approval_code: String,
    pub fingerprint: String,
    pub expires_at: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PendingDeviceSummary {
    pub device_id: DeviceId,
    pub name: String,
    pub fingerprint: String,
    pub bootstrap_public_key: String,
    pub approval_expires_at: String,
    pub created_at: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ApproveDeviceRequest {
    pub protocol_version: u16,
    pub approval_code: String,
    pub bootstrap_bundle: serde_json::Value,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ApprovalLookupRequest {
    pub protocol_version: u16,
    pub approval_code: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DeviceBootstrapResponse {
    pub device_id: DeviceId,
    pub state: DeviceState,
    pub bootstrap_bundle: Option<serde_json::Value>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RecoveryChallengeStartRequest {
    pub protocol_version: u16,
    pub device_id: DeviceId,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RecoveryChallengeStartResponse {
    pub challenge_id: uuid::Uuid,
    pub encrypted_challenge: serde_json::Value,
    pub expires_at: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RecoverTrustRequest {
    pub protocol_version: u16,
    pub challenge_id: uuid::Uuid,
    pub challenge_response: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RecoverTrustResponse {
    pub device_id: DeviceId,
    pub state: DeviceState,
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
pub struct UserLookupRequest {
    pub protocol_version: u16,
    pub email: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct UserLookupResponse {
    pub user_id: UserId,
    pub email: String,
    pub public_key: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct OrgMemberResponse {
    pub org_id: OrgId,
    pub user_id: UserId,
    pub role: OrgRole,
    pub state: MemberState,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct VaultMemberResponse {
    pub vault_id: VaultId,
    pub user_id: UserId,
    pub role: VaultRole,
    pub state: MemberState,
    pub public_key: String,
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
    pub vault_key_wrapping: serde_json::Value,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AcceptInviteRequest {
    pub protocol_version: u16,
    pub invite_id: uuid::Uuid,
    pub device_id: DeviceId,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RejectInviteRequest {
    pub protocol_version: u16,
    pub invite_id: uuid::Uuid,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct InviteResponse {
    pub invite_id: uuid::Uuid,
    pub vault_id: VaultId,
    pub org_id: Option<OrgId>,
    pub email: String,
    pub role: VaultRole,
    pub state: String,
    pub invited_by: Option<UserId>,
    pub expires_at: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PendingInviteResponse {
    pub invite_id: uuid::Uuid,
    pub vault_id: VaultId,
    pub vault_name: String,
    pub org_id: Option<OrgId>,
    pub email: String,
    pub role: VaultRole,
    pub invited_by: Option<UserId>,
    pub expires_at: Option<String>,
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
pub struct ItemConflictResponse {
    pub conflict_id: uuid::Uuid,
    pub vault_id: VaultId,
    pub item_id: ItemId,
    pub base_revision: RevisionId,
    pub current_revision: RevisionId,
    pub candidate_kind: String,
    pub candidate_envelope: Option<serde_json::Value>,
    pub author_user_id: Option<UserId>,
    pub state: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ResolveItemConflictRequest {
    pub protocol_version: u16,
    pub conflict_id: uuid::Uuid,
    pub expected_current_revision: RevisionId,
    pub resolution: String,
    pub envelope: Option<serde_json::Value>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ResolveItemConflictResponse {
    pub conflict: ItemConflictResponse,
    pub revision: Option<ItemRevisionResponse>,
    pub deleted_item_id: Option<ItemId>,
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

/// Signed, ciphertext-safe evidence that binds a vault revision to its state.
/// The signature is generated and verified by clients; the server only stores
/// and transports this public metadata.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SyncCheckpoint {
    pub vault_id: VaultId,
    pub vault_revision: RevisionId,
    pub state_commitment: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub previous_checkpoint_hash: Option<String>,
    pub author_device_id: DeviceId,
    pub signature: String,
}

/// A client-authored, device-signed checkpoint. This endpoint is available
/// only to protocol-v2 clients; the server persists it as opaque metadata.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CreateSyncCheckpointRequest {
    pub protocol_version: u16,
    pub checkpoint: SyncCheckpoint,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SyncResponse {
    pub protocol_version: u16,
    pub vaults: Vec<VaultSyncChanges>,
    /// Present only in protocol-v2 responses. Kept top-level so a checkpoint
    /// history can be transported independently from ciphertext sync changes.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub checkpoints: Vec<SyncCheckpoint>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct VaultSyncChanges {
    pub vault_id: VaultId,
    pub latest_vault_revision: RevisionId,
    pub latest_access_revision: RevisionId,
    pub items: Vec<ItemRevisionResponse>,
    pub deleted_items: Vec<ItemId>,
    pub key_wrappings: Vec<VaultKeyWrappingResponse>,
    #[serde(default)]
    pub conflicts: Vec<ItemConflictResponse>,
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
    fn delete_item_request_roundtrips() {
        let vault_id = Uuid::parse_str("00000000-0000-0000-0000-000000000001").unwrap();
        let item_id = Uuid::parse_str("00000000-0000-0000-0000-000000000002").unwrap();
        let request = DeleteItemRequest {
            protocol_version: PROTOCOL_VERSION,
            vault_id,
            item_id,
            expected_revision: 7,
        };

        let encoded = serde_json::to_value(&request).unwrap();
        assert_eq!(encoded["protocol_version"], json!(1));
        assert_eq!(encoded["vault_id"], json!(vault_id.to_string()));
        assert_eq!(encoded["item_id"], json!(item_id.to_string()));
        assert_eq!(encoded["expected_revision"], json!(7));

        let decoded: DeleteItemRequest = serde_json::from_value(encoded).unwrap();
        assert_eq!(decoded, request);
    }

    #[test]
    fn sync_checkpoint_roundtrips_without_envelopes() {
        let checkpoint = SyncCheckpoint {
            vault_id: Uuid::parse_str("00000000-0000-0000-0000-000000000101").unwrap(),
            vault_revision: 7,
            state_commitment: "state-hash".to_owned(),
            previous_checkpoint_hash: Some("previous-hash".to_owned()),
            author_device_id: Uuid::parse_str("00000000-0000-0000-0000-000000000102").unwrap(),
            signature: "signature".to_owned(),
        };

        let value = serde_json::to_value(&checkpoint).unwrap();
        assert_eq!(value["vault_revision"], json!(7));
        assert!(value.get("envelope").is_none());
        assert!(value.get("plaintext").is_none());
        assert_eq!(
            serde_json::from_value::<SyncCheckpoint>(value).unwrap(),
            checkpoint
        );
    }

    #[test]
    fn v2_checkpoint_transport_is_explicit_and_v1_omits_it() {
        let vault_id = Uuid::parse_str("00000000-0000-0000-0000-000000000101").unwrap();
        let device_id = Uuid::parse_str("00000000-0000-0000-0000-000000000102").unwrap();
        let checkpoint = SyncCheckpoint {
            vault_id,
            vault_revision: 7,
            state_commitment: "state-hash".to_owned(),
            previous_checkpoint_hash: Some("previous-hash".to_owned()),
            author_device_id: device_id,
            signature: "signature".to_owned(),
        };
        let request = CreateSyncCheckpointRequest {
            protocol_version: SYNC_INTEGRITY_PROTOCOL_VERSION,
            checkpoint: checkpoint.clone(),
        };
        let v2 = SyncResponse {
            protocol_version: SYNC_INTEGRITY_PROTOCOL_VERSION,
            vaults: vec![],
            checkpoints: vec![checkpoint],
        };
        let v1 = SyncResponse {
            protocol_version: PROTOCOL_VERSION,
            vaults: vec![],
            checkpoints: vec![],
        };

        let request_json = serde_json::to_value(&request).unwrap();
        let v2_json = serde_json::to_value(&v2).unwrap();
        let v1_json = serde_json::to_value(&v1).unwrap();

        assert_eq!(
            request_json["protocol_version"],
            json!(SYNC_INTEGRITY_PROTOCOL_VERSION)
        );
        assert_eq!(
            request_json["checkpoint"]["author_device_id"],
            json!(device_id)
        );
        assert_eq!(v2_json["checkpoints"], json!([v2.checkpoints[0].clone()]));
        assert!(v1_json.get("checkpoints").is_none());
        assert!(v2_json.to_string().contains("state-hash"));
        assert!(!v2_json.to_string().contains("plaintext"));
        assert!(!v2_json.to_string().contains("envelope"));
    }

    #[test]
    fn invite_member_request_carries_encrypted_wrapping() {
        let vault_id = Uuid::parse_str("00000000-0000-0000-0000-000000000801").unwrap();
        let request = InviteMemberRequest {
            protocol_version: PROTOCOL_VERSION,
            vault_id,
            email: "ana@example.com".to_owned(),
            role: VaultRole::Editor,
            vault_key_wrapping: json!({"version": 1, "ciphertext": "wrapped-vault-key"}),
        };

        let encoded = serde_json::to_value(&request).unwrap();
        assert_eq!(encoded["protocol_version"], json!(1));
        assert_eq!(encoded["vault_id"], json!(vault_id.to_string()));
        assert_eq!(encoded["email"], json!("ana@example.com"));
        assert_eq!(encoded["role"], json!("editor"));
        assert_eq!(
            encoded["vault_key_wrapping"],
            json!({"version": 1, "ciphertext": "wrapped-vault-key"})
        );

        let decoded: InviteMemberRequest = serde_json::from_value(encoded).unwrap();
        assert_eq!(decoded, request);
    }

    #[test]
    fn invite_responses_roundtrip() {
        let invite_id = Uuid::parse_str("00000000-0000-0000-0000-000000000811").unwrap();
        let vault_id = Uuid::parse_str("00000000-0000-0000-0000-000000000812").unwrap();
        let invited_by = Uuid::parse_str("00000000-0000-0000-0000-000000000813").unwrap();
        let invite = InviteResponse {
            invite_id,
            vault_id,
            org_id: None,
            email: "ana@example.com".to_owned(),
            role: VaultRole::Viewer,
            state: "pending".to_owned(),
            invited_by: Some(invited_by),
            expires_at: Some("2026-07-12T00:00:00Z".to_owned()),
        };
        let pending = PendingInviteResponse {
            invite_id,
            vault_id,
            vault_name: "Platform".to_owned(),
            org_id: None,
            email: "ana@example.com".to_owned(),
            role: VaultRole::Viewer,
            invited_by: Some(invited_by),
            expires_at: Some("2026-07-12T00:00:00Z".to_owned()),
        };

        assert_eq!(
            serde_json::from_value::<InviteResponse>(serde_json::to_value(&invite).unwrap())
                .unwrap(),
            invite
        );
        assert_eq!(
            serde_json::from_value::<PendingInviteResponse>(
                serde_json::to_value(&pending).unwrap()
            )
            .unwrap(),
            pending
        );
    }

    #[test]
    fn pending_device_response_roundtrips() {
        let response = PendingDeviceResponse {
            device_id: Uuid::parse_str("00000000-0000-0000-0000-000000000001").unwrap(),
            session_id: Uuid::parse_str("00000000-0000-0000-0000-000000000002").unwrap(),
            approval_code: "UMBRA-7K4Q-2M9D".to_owned(),
            fingerprint: "SHA256:abc".to_owned(),
            expires_at: "2026-06-28T12:00:00Z".to_owned(),
        };

        let encoded = serde_json::to_string(&response).unwrap();
        let decoded: PendingDeviceResponse = serde_json::from_str(&encoded).unwrap();

        assert_eq!(decoded, response);
    }

    #[test]
    fn opaque_login_finish_can_request_pending_device() {
        let request = OpaqueLoginFinishRequest {
            protocol_version: PROTOCOL_VERSION,
            login_id: Uuid::parse_str("00000000-0000-0000-0000-000000000003").unwrap(),
            device_id: None,
            pending_device: Some(PendingDeviceRequest {
                protocol_version: PROTOCOL_VERSION,
                name: "new laptop".to_owned(),
                public_key: "device-public-key".to_owned(),
                fingerprint: "device-fingerprint".to_owned(),
                bootstrap_public_key: "bootstrap-public-key".to_owned(),
            }),
            credential_finalization: "final".to_owned(),
        };

        let value = serde_json::to_value(&request).unwrap();

        assert_eq!(
            value["pending_device"]["name"],
            serde_json::json!("new laptop")
        );
        assert_eq!(value["device_id"], serde_json::Value::Null);
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
                conflicts: vec![],
            }],
            checkpoints: vec![],
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
    fn conflict_response_serializes_only_the_encrypted_candidate() {
        let conflict = ItemConflictResponse {
            conflict_id: Uuid::new_v4(),
            vault_id: Uuid::new_v4(),
            item_id: Uuid::new_v4(),
            base_revision: 3,
            current_revision: 5,
            candidate_kind: "update".to_owned(),
            candidate_envelope: Some(json!({"ciphertext":"sealed"})),
            author_user_id: None,
            state: "open".to_owned(),
        };
        let encoded = serde_json::to_value(&conflict).unwrap();
        assert_eq!(encoded["candidate_envelope"]["ciphertext"], json!("sealed"));
        assert!(encoded.get("plaintext").is_none());
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

    #[test]
    fn membership_protocol_types_roundtrip() {
        use serde_json::json;

        let lookup = UserLookupResponse {
            user_id: Uuid::parse_str("00000000-0000-0000-0000-000000000001").unwrap(),
            email: "ana@example.com".to_owned(),
            public_key: "ana-public-key".to_owned(),
        };
        let encoded = serde_json::to_value(&lookup).unwrap();
        assert_eq!(encoded["email"], json!("ana@example.com"));
        assert_eq!(encoded["public_key"], json!("ana-public-key"));

        let org_member = OrgMemberResponse {
            org_id: Uuid::parse_str("00000000-0000-0000-0000-000000000002").unwrap(),
            user_id: lookup.user_id,
            role: OrgRole::Admin,
            state: MemberState::Active,
        };
        let encoded = serde_json::to_value(&org_member).unwrap();
        assert_eq!(encoded["role"], json!("admin"));
        assert_eq!(encoded["state"], json!("active"));

        let vault_member = VaultMemberResponse {
            vault_id: Uuid::parse_str("00000000-0000-0000-0000-000000000003").unwrap(),
            user_id: lookup.user_id,
            role: VaultRole::Viewer,
            state: MemberState::Active,
            public_key: "ana-public-key".to_owned(),
        };
        let encoded = serde_json::to_value(&vault_member).unwrap();
        assert_eq!(encoded["role"], json!("viewer"));
        assert_eq!(encoded["state"], json!("active"));
        assert_eq!(encoded["public_key"], json!("ana-public-key"));
    }
}
