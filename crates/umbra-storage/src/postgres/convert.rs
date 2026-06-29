use sqlx::Row;
use umbra_core::{DeviceState, ItemKind, MemberState, OrgRole, VaultKind, VaultRole};

use crate::StorageError;
use crate::models::*;

pub(crate) fn user_from_row(row: sqlx::postgres::PgRow) -> Result<UserRecord, StorageError> {
    Ok(UserRecord {
        id: row.try_get("id")?,
        email: row.try_get("email")?,
        display_name: row.try_get("display_name")?,
        public_key: row.try_get("public_key")?,
        encrypted_private_key: row.try_get("encrypted_private_key")?,
        created_at: row.try_get("created_at")?,
        updated_at: row.try_get("updated_at")?,
        disabled_at: row.try_get("disabled_at")?,
    })
}

pub(crate) fn user_auth_from_row(
    row: sqlx::postgres::PgRow,
) -> Result<UserAuthRecord, StorageError> {
    Ok(UserAuthRecord {
        user_id: row.try_get("user_id")?,
        auth_method: row.try_get("auth_method")?,
        auth_data: row.try_get("auth_data")?,
        created_at: row.try_get("created_at")?,
        updated_at: row.try_get("updated_at")?,
    })
}

pub(crate) fn device_from_row(row: sqlx::postgres::PgRow) -> Result<DeviceRecord, StorageError> {
    let state: String = row.try_get("state")?;
    Ok(DeviceRecord {
        id: row.try_get("id")?,
        user_id: row.try_get("user_id")?,
        name: row.try_get("name")?,
        public_key: row.try_get("public_key")?,
        fingerprint: row.try_get("fingerprint")?,
        state: str_to_device_state(&state)?,
        approval_code_hash: row.try_get("approval_code_hash")?,
        approval_expires_at: row.try_get("approval_expires_at")?,
        bootstrap_public_key: row.try_get("bootstrap_public_key")?,
        bootstrap_bundle: row.try_get("bootstrap_bundle")?,
        created_at: row.try_get("created_at")?,
        trusted_at: row.try_get("trusted_at")?,
        last_seen_at: row.try_get("last_seen_at")?,
        revoked_at: row.try_get("revoked_at")?,
    })
}

pub(crate) fn vault_from_row(row: sqlx::postgres::PgRow) -> Result<VaultRecord, StorageError> {
    let kind: String = row.try_get("kind")?;
    Ok(VaultRecord {
        id: row.try_get("id")?,
        org_id: row.try_get("org_id")?,
        name: row.try_get("name")?,
        kind: str_to_vault_kind(&kind)?,
        vault_revision: row.try_get("vault_revision")?,
        access_revision: row.try_get("access_revision")?,
        current_key_generation: row.try_get("current_key_generation")?,
        needs_key_rotation: row.try_get("needs_key_rotation")?,
        created_by: row.try_get("created_by")?,
        created_at: row.try_get("created_at")?,
        updated_at: row.try_get("updated_at")?,
        deleted_at: row.try_get("deleted_at")?,
        crypto_policy: row.try_get("crypto_policy")?,
    })
}

pub(crate) fn org_from_row(row: sqlx::postgres::PgRow) -> Result<OrgRecord, StorageError> {
    Ok(OrgRecord {
        id: row.try_get("id")?,
        name: row.try_get("name")?,
        created_by: row.try_get("created_by")?,
        created_at: row.try_get("created_at")?,
        updated_at: row.try_get("updated_at")?,
        deleted_at: row.try_get("deleted_at")?,
    })
}

pub(crate) fn org_member_from_row(
    row: sqlx::postgres::PgRow,
) -> Result<OrgMemberRecord, StorageError> {
    let role: String = row.try_get("role")?;
    let state: String = row.try_get("state")?;
    Ok(OrgMemberRecord {
        org_id: row.try_get("org_id")?,
        user_id: row.try_get("user_id")?,
        role: str_to_org_role(&role)?,
        state: str_to_member_state(&state)?,
        created_at: row.try_get("created_at")?,
        updated_at: row.try_get("updated_at")?,
    })
}

pub(crate) fn vault_member_from_row(
    row: sqlx::postgres::PgRow,
) -> Result<VaultMemberRecord, StorageError> {
    let role: String = row.try_get("role")?;
    let state: String = row.try_get("state")?;
    Ok(VaultMemberRecord {
        vault_id: row.try_get("vault_id")?,
        user_id: row.try_get("user_id")?,
        role: str_to_vault_role(&role)?,
        state: str_to_member_state(&state)?,
        created_at: row.try_get("created_at")?,
        updated_at: row.try_get("updated_at")?,
    })
}

pub(crate) fn vault_key_wrapping_from_row(
    row: sqlx::postgres::PgRow,
) -> Result<VaultKeyWrappingRecord, StorageError> {
    Ok(VaultKeyWrappingRecord {
        id: row.try_get("id")?,
        vault_id: row.try_get("vault_id")?,
        user_id: row.try_get("user_id")?,
        device_id: row.try_get("device_id")?,
        wrapping_type: row.try_get("wrapping_type")?,
        envelope: row.try_get("envelope")?,
        key_generation: row.try_get("key_generation")?,
        created_at: row.try_get("created_at")?,
        rotated_at: row.try_get("rotated_at")?,
        revoked_at: row.try_get("revoked_at")?,
    })
}

pub(crate) fn item_revision_from_row(
    row: sqlx::postgres::PgRow,
) -> Result<ItemRevisionRecord, StorageError> {
    Ok(ItemRevisionRecord {
        id: row.try_get("id")?,
        item_id: row.try_get("item_id")?,
        vault_id: row.try_get("vault_id")?,
        revision: row.try_get("revision")?,
        vault_revision: row.try_get("vault_revision")?,
        key_generation: row.try_get("key_generation")?,
        author_user_id: row.try_get("author_user_id")?,
        envelope: row.try_get("envelope")?,
        created_at: row.try_get("created_at")?,
    })
}

pub(crate) fn audit_log_from_row(
    row: sqlx::postgres::PgRow,
) -> Result<AuditLogRecord, StorageError> {
    Ok(AuditLogRecord {
        id: row.try_get("id")?,
        actor_user_id: row.try_get("actor_user_id")?,
        vault_id: row.try_get("vault_id")?,
        action: row.try_get("action")?,
        target_type: row.try_get("target_type")?,
        target_id: row.try_get("target_id")?,
        metadata: row.try_get("metadata")?,
        created_at: row.try_get("created_at")?,
    })
}

pub(crate) fn session_from_row(row: sqlx::postgres::PgRow) -> Result<SessionRecord, StorageError> {
    Ok(SessionRecord {
        id: row.try_get("id")?,
        user_id: row.try_get("user_id")?,
        device_id: row.try_get("device_id")?,
        token_hash: row.try_get("token_hash")?,
        auth_scheme: row.try_get("auth_scheme")?,
        created_at: row.try_get("created_at")?,
        expires_at: row.try_get("expires_at")?,
        revoked_at: row.try_get("revoked_at")?,
    })
}

pub(crate) fn recovery_challenge_from_row(
    row: sqlx::postgres::PgRow,
) -> Result<RecoveryChallengeRecord, StorageError> {
    Ok(RecoveryChallengeRecord {
        id: row.try_get("id")?,
        user_id: row.try_get("user_id")?,
        device_id: row.try_get("device_id")?,
        challenge_hash: row.try_get("challenge_hash")?,
        expires_at: row.try_get("expires_at")?,
        consumed_at: row.try_get("consumed_at")?,
        created_at: row.try_get("created_at")?,
    })
}

pub(crate) fn vault_kind_to_str(kind: VaultKind) -> &'static str {
    match kind {
        VaultKind::Personal => "personal",
        VaultKind::Shared => "shared",
        VaultKind::Project => "project",
        VaultKind::Org => "org",
    }
}

pub(crate) fn org_role_to_str(role: OrgRole) -> &'static str {
    match role {
        OrgRole::Owner => "owner",
        OrgRole::Admin => "admin",
        OrgRole::Member => "member",
    }
}

pub(crate) fn device_state_to_str(state: DeviceState) -> &'static str {
    match state {
        DeviceState::Pending => "pending",
        DeviceState::Trusted => "trusted",
        DeviceState::Revoked => "revoked",
    }
}

pub(crate) fn str_to_device_state(value: &str) -> Result<DeviceState, StorageError> {
    match value {
        "pending" => Ok(DeviceState::Pending),
        "trusted" => Ok(DeviceState::Trusted),
        "revoked" => Ok(DeviceState::Revoked),
        value => Err(StorageError::InvalidDatabaseValue {
            field: "devices.state",
            value: value.to_owned(),
        }),
    }
}

pub(crate) fn str_to_org_role(value: &str) -> Result<OrgRole, StorageError> {
    match value {
        "owner" => Ok(OrgRole::Owner),
        "admin" => Ok(OrgRole::Admin),
        "member" => Ok(OrgRole::Member),
        value => Err(StorageError::InvalidDatabaseValue {
            field: "org_members.role",
            value: value.to_owned(),
        }),
    }
}

pub(crate) fn str_to_vault_kind(value: &str) -> Result<VaultKind, StorageError> {
    match value {
        "personal" => Ok(VaultKind::Personal),
        "shared" => Ok(VaultKind::Shared),
        "project" => Ok(VaultKind::Project),
        "org" => Ok(VaultKind::Org),
        value => Err(StorageError::InvalidDatabaseValue {
            field: "vault.kind",
            value: value.to_owned(),
        }),
    }
}

pub(crate) fn vault_role_to_str(role: VaultRole) -> &'static str {
    match role {
        VaultRole::Owner => "owner",
        VaultRole::Admin => "admin",
        VaultRole::Editor => "editor",
        VaultRole::Viewer => "viewer",
    }
}

pub(crate) fn str_to_vault_role(value: &str) -> Result<VaultRole, StorageError> {
    match value {
        "owner" => Ok(VaultRole::Owner),
        "admin" => Ok(VaultRole::Admin),
        "editor" => Ok(VaultRole::Editor),
        "viewer" => Ok(VaultRole::Viewer),
        value => Err(StorageError::InvalidDatabaseValue {
            field: "vault_members.role",
            value: value.to_owned(),
        }),
    }
}

pub(crate) fn member_state_to_str(state: MemberState) -> &'static str {
    match state {
        MemberState::Active => "active",
        MemberState::Invited => "invited",
        MemberState::Removed => "removed",
    }
}

pub(crate) fn str_to_member_state(value: &str) -> Result<MemberState, StorageError> {
    match value {
        "active" => Ok(MemberState::Active),
        "invited" => Ok(MemberState::Invited),
        "removed" => Ok(MemberState::Removed),
        value => Err(StorageError::InvalidDatabaseValue {
            field: "vault_members.state",
            value: value.to_owned(),
        }),
    }
}

pub(crate) fn item_kind_to_str(kind: &ItemKind) -> &'static str {
    match kind {
        ItemKind::Login => "login",
        ItemKind::SecureNote => "secure_note",
        ItemKind::SshKey => "ssh_key",
        ItemKind::ApiKey => "api_key",
        ItemKind::Token => "token",
        ItemKind::EnvVar => "env_var",
        ItemKind::EnvBundle => "env_bundle",
        ItemKind::CreditCard => "credit_card",
        ItemKind::Custom(_) => "custom",
    }
}
