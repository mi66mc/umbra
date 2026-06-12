use umbra_core::*;
use uuid::Uuid;

use crate::convert::*;
use crate::error::{ensure_rows_affected, map_sqlx_error};
use crate::models::*;
use crate::{Storage, StorageError};

impl Storage {
    pub async fn create_device(&self, input: CreateDevice) -> Result<DeviceRecord, StorageError> {
        let id = input.id.unwrap_or_else(Uuid::new_v4);
        let row = sqlx::query(
            r#"
            INSERT INTO devices (id, user_id, name, public_key, fingerprint, trusted)
            VALUES ($1, $2, $3, $4, $5, $6)
            RETURNING id, user_id, name, public_key, fingerprint, trusted, created_at, last_seen_at, revoked_at
            "#,
        )
        .bind(id)
        .bind(input.user_id)
        .bind(input.name)
        .bind(input.public_key)
        .bind(input.fingerprint)
        .bind(input.trusted)
        .fetch_one(&self.pool)
        .await
        .map_err(map_sqlx_error)?;

        device_from_row(row)
    }

    pub async fn list_devices_for_user(
        &self,
        user_id: UserId,
    ) -> Result<Vec<DeviceRecord>, StorageError> {
        let rows = sqlx::query(
            r#"
            SELECT id, user_id, name, public_key, fingerprint, trusted, created_at, last_seen_at, revoked_at
            FROM devices
            WHERE user_id = $1
            ORDER BY created_at ASC
            "#,
        )
        .bind(user_id)
        .fetch_all(&self.pool)
        .await?;

        rows.into_iter().map(device_from_row).collect()
    }

    pub async fn revoke_device(&self, device_id: DeviceId) -> Result<(), StorageError> {
        let result = sqlx::query("UPDATE devices SET revoked_at = now() WHERE id = $1")
            .bind(device_id)
            .execute(&self.pool)
            .await?;

        ensure_rows_affected(result.rows_affected())
    }
}
