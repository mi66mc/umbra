use chrono::{DateTime, NaiveDateTime, Utc};
use sqlx::{Row, sqlite::SqliteRow};
use uuid::Uuid;

use crate::{
    AuditLogRecord, DeviceRecord, ItemRevisionRecord, OrgMemberRecord, OrgRecord,
    RecoveryChallengeRecord, SessionRecord, StorageError, UserAuthRecord, UserRecord,
    VaultKeyWrappingRecord, VaultMemberRecord, VaultRecord, VaultSyncStatusRecord,
};

pub(crate) fn parse_uuid(value: String) -> Result<Uuid, StorageError> {
    Uuid::parse_str(&value).map_err(|_| StorageError::InvalidDatabaseValue {
        field: "uuid",
        value,
    })
}

pub(crate) fn optional_uuid(value: Option<String>) -> Result<Option<Uuid>, StorageError> {
    value.map(parse_uuid).transpose()
}

pub(crate) fn parse_time(value: String) -> Result<DateTime<Utc>, StorageError> {
    if let Ok(value) = DateTime::parse_from_rfc3339(&value) {
        return Ok(value.with_timezone(&Utc));
    }

    NaiveDateTime::parse_from_str(&value, "%Y-%m-%d %H:%M:%S")
        .map(|value| value.and_utc())
        .map_err(|_| StorageError::InvalidDatabaseValue {
            field: "timestamp",
            value,
        })
}

pub(crate) fn optional_time(value: Option<String>) -> Result<Option<DateTime<Utc>>, StorageError> {
    value.map(parse_time).transpose()
}

pub(crate) fn json_value(value: String) -> Result<serde_json::Value, StorageError> {
    serde_json::from_str(&value).map_err(|_| StorageError::InvalidDatabaseValue {
        field: "json",
        value,
    })
}

pub(crate) fn user_from_row(row: SqliteRow) -> Result<UserRecord, StorageError> {
    Ok(UserRecord {
        id: parse_uuid(row.try_get("id")?)?,
        email: row.try_get("email")?,
        display_name: row.try_get("display_name")?,
        public_key: row.try_get("public_key")?,
        encrypted_private_key: json_value(row.try_get("encrypted_private_key")?)?,
        created_at: parse_time(row.try_get("created_at")?)?,
        updated_at: parse_time(row.try_get("updated_at")?)?,
        disabled_at: optional_time(row.try_get("disabled_at")?)?,
    })
}

pub(crate) fn user_auth_from_row(row: SqliteRow) -> Result<UserAuthRecord, StorageError> {
    Ok(UserAuthRecord {
        user_id: parse_uuid(row.try_get("user_id")?)?,
        auth_method: row.try_get("auth_method")?,
        auth_data: json_value(row.try_get("auth_data")?)?,
        created_at: parse_time(row.try_get("created_at")?)?,
        updated_at: parse_time(row.try_get("updated_at")?)?,
    })
}

pub(crate) fn device_from_row(row: SqliteRow) -> Result<DeviceRecord, StorageError> {
    Ok(DeviceRecord {
        id: parse_uuid(row.try_get("id")?)?,
        user_id: parse_uuid(row.try_get("user_id")?)?,
        name: row.try_get("name")?,
        public_key: row.try_get("public_key")?,
        fingerprint: row.try_get("fingerprint")?,
        state: crate::convert::str_to_device_state(row.try_get::<String, _>("state")?.as_str())?,
        approval_code_hash: row.try_get("approval_code_hash")?,
        approval_expires_at: optional_time(row.try_get("approval_expires_at")?)?,
        bootstrap_public_key: row.try_get("bootstrap_public_key")?,
        bootstrap_bundle: row
            .try_get::<Option<String>, _>("bootstrap_bundle")?
            .map(json_value)
            .transpose()?,
        created_at: parse_time(row.try_get("created_at")?)?,
        trusted_at: optional_time(row.try_get("trusted_at")?)?,
        last_seen_at: optional_time(row.try_get("last_seen_at")?)?,
        revoked_at: optional_time(row.try_get("revoked_at")?)?,
    })
}

pub(crate) fn session_from_row(row: SqliteRow) -> Result<SessionRecord, StorageError> {
    Ok(SessionRecord {
        id: parse_uuid(row.try_get("id")?)?,
        user_id: parse_uuid(row.try_get("user_id")?)?,
        device_id: optional_uuid(row.try_get("device_id")?)?,
        token_hash: row.try_get("token_hash")?,
        auth_scheme: row.try_get("auth_scheme")?,
        created_at: parse_time(row.try_get("created_at")?)?,
        expires_at: parse_time(row.try_get("expires_at")?)?,
        revoked_at: optional_time(row.try_get("revoked_at")?)?,
    })
}

pub(crate) fn recovery_challenge_from_row(
    row: SqliteRow,
) -> Result<RecoveryChallengeRecord, StorageError> {
    Ok(RecoveryChallengeRecord {
        id: parse_uuid(row.try_get("id")?)?,
        user_id: parse_uuid(row.try_get("user_id")?)?,
        device_id: parse_uuid(row.try_get("device_id")?)?,
        challenge_hash: row.try_get("challenge_hash")?,
        expires_at: parse_time(row.try_get("expires_at")?)?,
        consumed_at: optional_time(row.try_get("consumed_at")?)?,
        created_at: parse_time(row.try_get("created_at")?)?,
    })
}

pub(crate) fn org_from_row(row: SqliteRow) -> Result<OrgRecord, StorageError> {
    Ok(OrgRecord {
        id: parse_uuid(row.try_get("id")?)?,
        name: row.try_get("name")?,
        created_by: optional_uuid(row.try_get("created_by")?)?,
        created_at: parse_time(row.try_get("created_at")?)?,
        updated_at: parse_time(row.try_get("updated_at")?)?,
        deleted_at: optional_time(row.try_get("deleted_at")?)?,
    })
}

pub(crate) fn org_member_from_row(row: SqliteRow) -> Result<OrgMemberRecord, StorageError> {
    Ok(OrgMemberRecord {
        org_id: parse_uuid(row.try_get("org_id")?)?,
        user_id: parse_uuid(row.try_get("user_id")?)?,
        role: crate::convert::str_to_org_role(row.try_get::<String, _>("role")?.as_str())?,
        state: crate::convert::str_to_member_state(row.try_get::<String, _>("state")?.as_str())?,
        created_at: parse_time(row.try_get("created_at")?)?,
        updated_at: parse_time(row.try_get("updated_at")?)?,
    })
}

pub(crate) fn vault_from_row(row: SqliteRow) -> Result<VaultRecord, StorageError> {
    let needs_key_rotation: i64 = row.try_get("needs_key_rotation")?;
    Ok(VaultRecord {
        id: parse_uuid(row.try_get("id")?)?,
        org_id: optional_uuid(row.try_get("org_id")?)?,
        name: row.try_get("name")?,
        kind: crate::convert::str_to_vault_kind(row.try_get::<String, _>("kind")?.as_str())?,
        vault_revision: row.try_get("vault_revision")?,
        access_revision: row.try_get("access_revision")?,
        current_key_generation: row.try_get("current_key_generation")?,
        needs_key_rotation: needs_key_rotation != 0,
        created_by: optional_uuid(row.try_get("created_by")?)?,
        created_at: parse_time(row.try_get("created_at")?)?,
        updated_at: parse_time(row.try_get("updated_at")?)?,
        deleted_at: optional_time(row.try_get("deleted_at")?)?,
        crypto_policy: json_value(row.try_get("crypto_policy")?)?,
    })
}

pub(crate) fn vault_member_from_row(row: SqliteRow) -> Result<VaultMemberRecord, StorageError> {
    Ok(VaultMemberRecord {
        vault_id: parse_uuid(row.try_get("vault_id")?)?,
        user_id: parse_uuid(row.try_get("user_id")?)?,
        role: crate::convert::str_to_vault_role(row.try_get::<String, _>("role")?.as_str())?,
        state: crate::convert::str_to_member_state(row.try_get::<String, _>("state")?.as_str())?,
        created_at: parse_time(row.try_get("created_at")?)?,
        updated_at: parse_time(row.try_get("updated_at")?)?,
    })
}

pub(crate) fn vault_key_wrapping_from_row(
    row: SqliteRow,
) -> Result<VaultKeyWrappingRecord, StorageError> {
    Ok(VaultKeyWrappingRecord {
        id: parse_uuid(row.try_get("id")?)?,
        vault_id: parse_uuid(row.try_get("vault_id")?)?,
        user_id: parse_uuid(row.try_get("user_id")?)?,
        device_id: optional_uuid(row.try_get("device_id")?)?,
        wrapping_type: row.try_get("wrapping_type")?,
        envelope: json_value(row.try_get("envelope")?)?,
        key_generation: row.try_get("key_generation")?,
        created_at: parse_time(row.try_get("created_at")?)?,
        rotated_at: optional_time(row.try_get("rotated_at")?)?,
        revoked_at: optional_time(row.try_get("revoked_at")?)?,
    })
}

pub(crate) fn item_revision_from_row(row: SqliteRow) -> Result<ItemRevisionRecord, StorageError> {
    Ok(ItemRevisionRecord {
        id: parse_uuid(row.try_get("id")?)?,
        item_id: parse_uuid(row.try_get("item_id")?)?,
        vault_id: parse_uuid(row.try_get("vault_id")?)?,
        revision: row.try_get("revision")?,
        vault_revision: row.try_get("vault_revision")?,
        key_generation: row.try_get("key_generation")?,
        author_user_id: optional_uuid(row.try_get("author_user_id")?)?,
        envelope: json_value(row.try_get("envelope")?)?,
        created_at: parse_time(row.try_get("created_at")?)?,
    })
}

pub(crate) fn audit_log_from_row(row: SqliteRow) -> Result<AuditLogRecord, StorageError> {
    Ok(AuditLogRecord {
        id: parse_uuid(row.try_get("id")?)?,
        actor_user_id: optional_uuid(row.try_get("actor_user_id")?)?,
        vault_id: optional_uuid(row.try_get("vault_id")?)?,
        action: row.try_get("action")?,
        target_type: row.try_get("target_type")?,
        target_id: optional_uuid(row.try_get("target_id")?)?,
        metadata: json_value(row.try_get("metadata")?)?,
        created_at: parse_time(row.try_get("created_at")?)?,
    })
}

pub(crate) fn vault_sync_status_from_row(
    row: SqliteRow,
) -> Result<VaultSyncStatusRecord, StorageError> {
    let needs_key_rotation: i64 = row.try_get("needs_key_rotation")?;
    Ok(VaultSyncStatusRecord {
        vault_id: parse_uuid(row.try_get("vault_id")?)?,
        latest_vault_revision: row.try_get("latest_vault_revision")?,
        latest_access_revision: row.try_get("latest_access_revision")?,
        current_key_generation: row.try_get("current_key_generation")?,
        needs_key_rotation: needs_key_rotation != 0,
    })
}
