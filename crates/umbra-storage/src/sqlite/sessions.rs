use uuid::Uuid;

use crate::error::map_sqlx_error;
use crate::sqlite::SqliteStorage;
use crate::sqlite::convert::session_from_row;
use crate::{CreateSession, SessionRecord, StorageError};

impl SqliteStorage {
    pub async fn create_session(
        &self,
        input: CreateSession,
    ) -> Result<SessionRecord, StorageError> {
        let id = input.id.unwrap_or_else(Uuid::new_v4);
        let row = sqlx::query(
            r#"
            INSERT INTO sessions (id, user_id, device_id, token_hash, auth_scheme, expires_at)
            VALUES (?1, ?2, ?3, ?4, ?5, ?6)
            RETURNING id, user_id, device_id, token_hash, auth_scheme, created_at, expires_at, revoked_at
            "#,
        )
        .bind(id.to_string())
        .bind(input.user_id.to_string())
        .bind(input.device_id.map(|value| value.to_string()))
        .bind(input.token_hash)
        .bind(input.auth_scheme)
        .bind(input.expires_at.to_rfc3339())
        .fetch_one(&self.pool)
        .await
        .map_err(map_sqlx_error)?;

        session_from_row(row)
    }

    pub async fn find_active_session_by_hash(
        &self,
        token_hash: &str,
    ) -> Result<SessionRecord, StorageError> {
        let row = sqlx::query(
            r#"
            SELECT id, user_id, device_id, token_hash, auth_scheme, created_at, expires_at, revoked_at
            FROM sessions
            WHERE token_hash = ?1
              AND revoked_at IS NULL
              AND expires_at > strftime('%Y-%m-%dT%H:%M:%fZ', 'now')
            "#,
        )
        .bind(token_hash)
        .fetch_optional(&self.pool)
        .await?
        .ok_or(StorageError::NotFound)?;

        session_from_row(row)
    }

    pub async fn find_active_session_by_id(
        &self,
        session_id: Uuid,
    ) -> Result<SessionRecord, StorageError> {
        let row = sqlx::query(
            r#"
            SELECT id, user_id, device_id, token_hash, auth_scheme, created_at, expires_at, revoked_at
            FROM sessions
            WHERE id = ?1
              AND revoked_at IS NULL
              AND expires_at > strftime('%Y-%m-%dT%H:%M:%fZ', 'now')
            "#,
        )
        .bind(session_id.to_string())
        .fetch_optional(&self.pool)
        .await?
        .ok_or(StorageError::NotFound)?;

        session_from_row(row)
    }

    pub async fn remember_session_nonce(
        &self,
        session_id: Uuid,
        nonce: &str,
    ) -> Result<(), StorageError> {
        sqlx::query(
            r#"
            INSERT INTO session_nonces (session_id, nonce)
            VALUES (?1, ?2)
            "#,
        )
        .bind(session_id.to_string())
        .bind(nonce)
        .execute(&self.pool)
        .await
        .map_err(map_sqlx_error)?;

        Ok(())
    }

    pub async fn revoke_sessions_for_device(&self, device_id: Uuid) -> Result<u64, StorageError> {
        let result = sqlx::query(
            r#"
            UPDATE sessions
            SET revoked_at = strftime('%Y-%m-%dT%H:%M:%fZ', 'now')
            WHERE device_id = ?1 AND revoked_at IS NULL
            "#,
        )
        .bind(device_id.to_string())
        .execute(&self.pool)
        .await?;

        Ok(result.rows_affected())
    }
}
