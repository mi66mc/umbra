use uuid::Uuid;

use crate::sqlite::SqliteStorage;
use crate::sqlite::convert::audit_log_from_row;
use crate::{AppendAuditLog, AuditLogRecord, StorageError, error::map_sqlx_error};

impl SqliteStorage {
    pub async fn append_audit_log(
        &self,
        input: AppendAuditLog,
    ) -> Result<AuditLogRecord, StorageError> {
        let id = input.id.unwrap_or_else(Uuid::new_v4);
        let row = sqlx::query(
            r#"
            INSERT INTO audit_logs (id, actor_user_id, vault_id, action, target_type, target_id, metadata)
            VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)
            RETURNING id, actor_user_id, vault_id, action, target_type, target_id, metadata, created_at
            "#,
        )
        .bind(id.to_string())
        .bind(input.actor_user_id.map(|value| value.to_string()))
        .bind(input.vault_id.map(|value| value.to_string()))
        .bind(input.action)
        .bind(input.target_type)
        .bind(input.target_id.map(|value| value.to_string()))
        .bind(input.metadata.to_string())
        .fetch_one(&self.pool)
        .await
        .map_err(map_sqlx_error)?;

        audit_log_from_row(row)
    }
}
