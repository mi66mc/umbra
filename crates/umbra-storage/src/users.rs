use umbra_core::*;
use uuid::Uuid;

use crate::convert::*;
use crate::error::map_sqlx_error;
use crate::models::*;
use crate::{Storage, StorageError};

impl Storage {
    pub async fn create_user(&self, input: CreateUser) -> Result<UserRecord, StorageError> {
        let id = input.id.unwrap_or_else(Uuid::new_v4);
        let row = sqlx::query(
            r#"
            INSERT INTO users (id, email, display_name, public_key, encrypted_private_key)
            VALUES ($1, $2, $3, $4, $5)
            RETURNING id, email, display_name, public_key, encrypted_private_key, created_at, updated_at, disabled_at
            "#,
        )
        .bind(id)
        .bind(input.email)
        .bind(input.display_name)
        .bind(input.public_key)
        .bind(input.encrypted_private_key)
        .fetch_one(&self.pool)
        .await
        .map_err(map_sqlx_error)?;

        user_from_row(row)
    }

    pub async fn find_user_by_email(&self, email: &str) -> Result<UserRecord, StorageError> {
        let row = sqlx::query(
            r#"
            SELECT id, email, display_name, public_key, encrypted_private_key, created_at, updated_at, disabled_at
            FROM users
            WHERE email = $1
            "#,
        )
        .bind(email)
        .fetch_optional(&self.pool)
        .await?
        .ok_or(StorageError::NotFound)?;

        user_from_row(row)
    }

    pub async fn find_user_by_id(&self, user_id: UserId) -> Result<UserRecord, StorageError> {
        let row = sqlx::query(
            r#"
            SELECT id, email, display_name, public_key, encrypted_private_key, created_at, updated_at, disabled_at
            FROM users
            WHERE id = $1
            "#,
        )
        .bind(user_id)
        .fetch_optional(&self.pool)
        .await?
        .ok_or(StorageError::NotFound)?;

        user_from_row(row)
    }

    pub async fn upsert_user_auth(
        &self,
        input: UpsertUserAuth,
    ) -> Result<UserAuthRecord, StorageError> {
        let row = sqlx::query(
            r#"
            INSERT INTO user_auth (user_id, auth_method, auth_data)
            VALUES ($1, $2, $3)
            ON CONFLICT (user_id)
            DO UPDATE SET auth_method = EXCLUDED.auth_method, auth_data = EXCLUDED.auth_data, updated_at = now()
            RETURNING user_id, auth_method, auth_data, created_at, updated_at
            "#,
        )
        .bind(input.user_id)
        .bind(input.auth_method)
        .bind(input.auth_data)
        .fetch_one(&self.pool)
        .await
        .map_err(map_sqlx_error)?;

        user_auth_from_row(row)
    }

    pub async fn find_user_auth(&self, user_id: UserId) -> Result<UserAuthRecord, StorageError> {
        let row = sqlx::query(
            r#"
            SELECT user_id, auth_method, auth_data, created_at, updated_at
            FROM user_auth
            WHERE user_id = $1
            "#,
        )
        .bind(user_id)
        .fetch_optional(&self.pool)
        .await?
        .ok_or(StorageError::NotFound)?;

        user_auth_from_row(row)
    }
}
