use uuid::Uuid;

use crate::convert::*;
use crate::error::map_sqlx_error;
use crate::models::*;
use crate::{Storage, StorageError};

impl Storage {
    pub async fn append_audit_log(
        &self,
        input: AppendAuditLog,
    ) -> Result<AuditLogRecord, StorageError> {
        let id = input.id.unwrap_or_else(Uuid::new_v4);
        let row = sqlx::query(
            r#"
            INSERT INTO audit_logs (id, actor_user_id, vault_id, action, target_type, target_id, metadata)
            VALUES ($1, $2, $3, $4, $5, $6, $7)
            RETURNING id, actor_user_id, vault_id, action, target_type, target_id, metadata, created_at
            "#,
        )
        .bind(id)
        .bind(input.actor_user_id)
        .bind(input.vault_id)
        .bind(input.action)
        .bind(input.target_type)
        .bind(input.target_id)
        .bind(input.metadata)
        .fetch_one(&self.pool)
        .await
        .map_err(map_sqlx_error)?;

        audit_log_from_row(row)
    }
}
