use uuid::Uuid;

use crate::convert::*;
use crate::error::map_sqlx_error;
use crate::models::*;
use crate::{Storage, StorageError};

impl Storage {
    pub async fn create_session(
        &self,
        input: CreateSession,
    ) -> Result<SessionRecord, StorageError> {
        let id = input.id.unwrap_or_else(Uuid::new_v4);
        let row = sqlx::query(
            r#"
            INSERT INTO sessions (id, user_id, device_id, token_hash, auth_scheme, expires_at)
            VALUES ($1, $2, $3, $4, $5, $6)
            RETURNING id, user_id, device_id, token_hash, auth_scheme, created_at, expires_at, revoked_at
            "#,
        )
        .bind(id)
        .bind(input.user_id)
        .bind(input.device_id)
        .bind(input.token_hash)
        .bind(input.auth_scheme)
        .bind(input.expires_at)
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
            WHERE token_hash = $1 AND revoked_at IS NULL AND expires_at > now()
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
            WHERE id = $1 AND revoked_at IS NULL AND expires_at > now()
            "#,
        )
        .bind(session_id)
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
            VALUES ($1, $2)
            "#,
        )
        .bind(session_id)
        .bind(nonce)
        .execute(&self.pool)
        .await
        .map_err(map_sqlx_error)?;

        Ok(())
    }
}
