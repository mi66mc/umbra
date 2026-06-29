use umbra_core::{DeviceId, DeviceState, UserId};
use uuid::Uuid;

use crate::convert::device_state_to_str;
use crate::error::{ensure_rows_affected, map_sqlx_error};
use crate::sqlite::SqliteStorage;
use crate::sqlite::convert::{device_from_row, recovery_challenge_from_row};
use crate::{
    ApprovePendingDevice, CreateDevice, CreateRecoveryChallenge, DeviceRecord,
    RecoveryChallengeRecord, StorageError,
};

const DEVICE_COLUMNS: &str = "id, user_id, name, public_key, fingerprint, state, approval_code_hash, approval_expires_at, bootstrap_public_key, bootstrap_bundle, created_at, trusted_at, last_seen_at, revoked_at";

impl SqliteStorage {
    pub async fn create_device(&self, input: CreateDevice) -> Result<DeviceRecord, StorageError> {
        let id = input.id.unwrap_or_else(Uuid::new_v4);
        let state = device_state_to_str(input.state);
        let row = sqlx::query(&format!(
            r#"
            INSERT INTO devices (
                id, user_id, name, public_key, fingerprint, trusted, state,
                approval_code_hash, approval_expires_at, bootstrap_public_key, trusted_at
            )
            VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10,
                    CASE WHEN ?7 = 'trusted' THEN strftime('%Y-%m-%dT%H:%M:%fZ', 'now') ELSE NULL END)
            RETURNING {DEVICE_COLUMNS}
            "#
        ))
        .bind(id.to_string())
        .bind(input.user_id.to_string())
        .bind(input.name)
        .bind(input.public_key)
        .bind(input.fingerprint)
        .bind(matches!(input.state, DeviceState::Trusted) as i64)
        .bind(state)
        .bind(input.approval_code_hash)
        .bind(input.approval_expires_at.map(|value| value.to_rfc3339()))
        .bind(input.bootstrap_public_key)
        .fetch_one(&self.pool)
        .await
        .map_err(map_sqlx_error)?;

        device_from_row(row)
    }

    pub async fn list_devices_for_user(
        &self,
        user_id: UserId,
    ) -> Result<Vec<DeviceRecord>, StorageError> {
        let rows = sqlx::query(&format!(
            r#"
            SELECT {DEVICE_COLUMNS}
            FROM devices
            WHERE user_id = ?1
            ORDER BY created_at ASC
            "#
        ))
        .bind(user_id.to_string())
        .fetch_all(&self.pool)
        .await?;

        rows.into_iter().map(device_from_row).collect()
    }

    pub async fn find_device_by_id(
        &self,
        device_id: DeviceId,
    ) -> Result<DeviceRecord, StorageError> {
        let row = sqlx::query(&format!(
            r#"
            SELECT {DEVICE_COLUMNS}
            FROM devices
            WHERE id = ?1
            "#
        ))
        .bind(device_id.to_string())
        .fetch_optional(&self.pool)
        .await?
        .ok_or(StorageError::NotFound)?;

        device_from_row(row)
    }

    pub async fn list_pending_devices_for_user(
        &self,
        user_id: UserId,
    ) -> Result<Vec<DeviceRecord>, StorageError> {
        let rows = sqlx::query(&format!(
            r#"
            SELECT {DEVICE_COLUMNS}
            FROM devices
            WHERE user_id = ?1 AND state = 'pending' AND revoked_at IS NULL
            ORDER BY created_at ASC
            "#
        ))
        .bind(user_id.to_string())
        .fetch_all(&self.pool)
        .await?;

        rows.into_iter().map(device_from_row).collect()
    }

    pub async fn find_pending_device_by_approval_hash(
        &self,
        user_id: UserId,
        approval_code_hash: &str,
    ) -> Result<DeviceRecord, StorageError> {
        let row = sqlx::query(&format!(
            r#"
            SELECT {DEVICE_COLUMNS}
            FROM devices
            WHERE user_id = ?1
              AND approval_code_hash = ?2
              AND state = 'pending'
              AND revoked_at IS NULL
              AND approval_expires_at > strftime('%Y-%m-%dT%H:%M:%fZ', 'now')
            "#
        ))
        .bind(user_id.to_string())
        .bind(approval_code_hash)
        .fetch_optional(&self.pool)
        .await?
        .ok_or(StorageError::NotFound)?;

        device_from_row(row)
    }

    pub async fn approve_pending_device(
        &self,
        input: ApprovePendingDevice,
    ) -> Result<DeviceRecord, StorageError> {
        let row = sqlx::query(&format!(
            r#"
            UPDATE devices
            SET state = 'trusted',
                trusted = 1,
                trusted_at = strftime('%Y-%m-%dT%H:%M:%fZ', 'now'),
                bootstrap_bundle = ?2,
                approval_code_hash = NULL,
                approval_expires_at = NULL
            WHERE id = ?1
              AND state = 'pending'
              AND revoked_at IS NULL
              AND approval_expires_at > strftime('%Y-%m-%dT%H:%M:%fZ', 'now')
            RETURNING {DEVICE_COLUMNS}
            "#
        ))
        .bind(input.device_id.to_string())
        .bind(input.bootstrap_bundle.to_string())
        .fetch_optional(&self.pool)
        .await?
        .ok_or(StorageError::NotFound)?;

        device_from_row(row)
    }

    pub async fn mark_device_trusted(
        &self,
        device_id: DeviceId,
    ) -> Result<DeviceRecord, StorageError> {
        let row = sqlx::query(&format!(
            r#"
            UPDATE devices
            SET state = 'trusted',
                trusted = 1,
                trusted_at = strftime('%Y-%m-%dT%H:%M:%fZ', 'now'),
                approval_code_hash = NULL,
                approval_expires_at = NULL
            WHERE id = ?1 AND state = 'pending' AND revoked_at IS NULL
            RETURNING {DEVICE_COLUMNS}
            "#
        ))
        .bind(device_id.to_string())
        .fetch_optional(&self.pool)
        .await?
        .ok_or(StorageError::NotFound)?;

        device_from_row(row)
    }

    pub async fn revoke_device(&self, device_id: DeviceId) -> Result<(), StorageError> {
        let result = sqlx::query(
            r#"
            UPDATE devices
            SET state = 'revoked',
                trusted = 0,
                revoked_at = strftime('%Y-%m-%dT%H:%M:%fZ', 'now')
            WHERE id = ?1
            "#,
        )
        .bind(device_id.to_string())
        .execute(&self.pool)
        .await?;

        ensure_rows_affected(result.rows_affected())
    }

    pub async fn create_recovery_challenge(
        &self,
        input: CreateRecoveryChallenge,
    ) -> Result<RecoveryChallengeRecord, StorageError> {
        let id = input.id.unwrap_or_else(Uuid::new_v4);
        let row = sqlx::query(
            r#"
            INSERT INTO device_recovery_challenges (id, user_id, device_id, challenge_hash, expires_at)
            VALUES (?1, ?2, ?3, ?4, ?5)
            RETURNING id, user_id, device_id, challenge_hash, expires_at, consumed_at, created_at
            "#,
        )
        .bind(id.to_string())
        .bind(input.user_id.to_string())
        .bind(input.device_id.to_string())
        .bind(input.challenge_hash)
        .bind(input.expires_at.to_rfc3339())
        .fetch_one(&self.pool)
        .await
        .map_err(map_sqlx_error)?;

        recovery_challenge_from_row(row)
    }

    pub async fn consume_recovery_challenge(
        &self,
        challenge_id: Uuid,
        user_id: UserId,
        device_id: DeviceId,
        challenge_hash: &str,
    ) -> Result<RecoveryChallengeRecord, StorageError> {
        let row = sqlx::query(
            r#"
            UPDATE device_recovery_challenges
            SET consumed_at = strftime('%Y-%m-%dT%H:%M:%fZ', 'now')
            WHERE id = ?1
              AND user_id = ?2
              AND device_id = ?3
              AND challenge_hash = ?4
              AND consumed_at IS NULL
              AND expires_at > strftime('%Y-%m-%dT%H:%M:%fZ', 'now')
            RETURNING id, user_id, device_id, challenge_hash, expires_at, consumed_at, created_at
            "#,
        )
        .bind(challenge_id.to_string())
        .bind(user_id.to_string())
        .bind(device_id.to_string())
        .bind(challenge_hash)
        .fetch_optional(&self.pool)
        .await?
        .ok_or(StorageError::NotFound)?;

        recovery_challenge_from_row(row)
    }
}
