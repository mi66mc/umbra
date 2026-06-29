use chrono::{DateTime, NaiveDateTime, Utc};
use sqlx::{Row, sqlite::SqliteRow};
use uuid::Uuid;

use crate::{
    DeviceRecord, RecoveryChallengeRecord, SessionRecord, StorageError, UserAuthRecord, UserRecord,
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
