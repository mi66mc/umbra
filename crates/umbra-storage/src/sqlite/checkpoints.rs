use sqlx::Row;
use umbra_core::VaultId;

use crate::sqlite::SqliteStorage;
use crate::sqlite::convert::{parse_time, parse_uuid};
use crate::{CheckpointConflict, CreateSyncCheckpoint, StorageError, StoredSyncCheckpoint};

const CHECKPOINT_COLUMNS: &str = "vault_id, vault_revision, state_commitment, checkpoint_hash, previous_checkpoint_hash, author_device_id, signature, created_at";
const APPEND_RETRY_LIMIT: usize = 8;

impl SqliteStorage {
    pub async fn append_sync_checkpoint(
        &self,
        input: CreateSyncCheckpoint,
    ) -> Result<StoredSyncCheckpoint, StorageError> {
        for attempt in 0..APPEND_RETRY_LIMIT {
            match self.append_sync_checkpoint_once(input.clone()).await {
                Err(StorageError::Database(error))
                    if is_sqlite_lock_error(&error) && attempt + 1 < APPEND_RETRY_LIMIT =>
                {
                    tokio::task::yield_now().await;
                }
                result => return result,
            }
        }

        unreachable!("the retry loop returns on its final attempt")
    }

    async fn append_sync_checkpoint_once(
        &self,
        input: CreateSyncCheckpoint,
    ) -> Result<StoredSyncCheckpoint, StorageError> {
        let mut tx = self.pool.begin().await?;
        let inserted = sqlx::query(
            "INSERT OR IGNORE INTO sync_checkpoints (checkpoint_hash, vault_id, vault_revision, state_commitment, previous_checkpoint_hash, author_device_id, signature) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)",
        )
        .bind(input.checkpoint_hash.clone())
        .bind(input.vault_id.to_string())
        .bind(input.vault_revision)
        .bind(input.state_commitment)
        .bind(input.previous_checkpoint_hash)
        .bind(input.author_device_id.to_string())
        .bind(input.signature)
        .execute(&mut *tx)
        .await?;

        let row = sqlx::query(&format!(
            "SELECT {CHECKPOINT_COLUMNS} FROM sync_checkpoints WHERE vault_id = ?1 AND vault_revision = ?2"
        ))
        .bind(input.vault_id.to_string())
        .bind(input.vault_revision)
        .fetch_optional(&mut *tx)
        .await?
        .ok_or(StorageError::Conflict)?;
        let checkpoint = sync_checkpoint_from_row(row)?;
        if inserted.rows_affected() == 0 && checkpoint.checkpoint_hash != input.checkpoint_hash {
            return Err(StorageError::CheckpointConflict(CheckpointConflict {
                vault_id: input.vault_id,
                vault_revision: input.vault_revision,
                existing_checkpoint_hash: checkpoint.checkpoint_hash,
                checkpoint_hash: input.checkpoint_hash,
            }));
        }
        tx.commit().await?;

        Ok(checkpoint)
    }

    pub async fn list_sync_checkpoints_since(
        &self,
        vault_id: VaultId,
        since_vault_revision: i64,
    ) -> Result<Vec<StoredSyncCheckpoint>, StorageError> {
        let rows = sqlx::query(&format!(
            "SELECT {CHECKPOINT_COLUMNS} FROM sync_checkpoints WHERE vault_id = ?1 AND vault_revision > ?2 ORDER BY vault_revision ASC, created_at ASC"
        ))
        .bind(vault_id.to_string())
        .bind(since_vault_revision)
        .fetch_all(&self.pool)
        .await?;

        rows.into_iter().map(sync_checkpoint_from_row).collect()
    }

    pub async fn find_sync_checkpoint(
        &self,
        vault_id: VaultId,
        vault_revision: i64,
    ) -> Result<Option<StoredSyncCheckpoint>, StorageError> {
        sqlx::query(&format!(
            "SELECT {CHECKPOINT_COLUMNS} FROM sync_checkpoints WHERE vault_id = ?1 AND vault_revision = ?2"
        ))
        .bind(vault_id.to_string())
        .bind(vault_revision)
        .fetch_optional(&self.pool)
        .await?
        .map(sync_checkpoint_from_row)
        .transpose()
    }
}

fn is_sqlite_lock_error(error: &sqlx::Error) -> bool {
    matches!(
        error,
        sqlx::Error::Database(database_error)
            if matches!(database_error.code().as_deref(), Some("5") | Some("6"))
    )
}

fn sync_checkpoint_from_row(
    row: sqlx::sqlite::SqliteRow,
) -> Result<StoredSyncCheckpoint, StorageError> {
    Ok(StoredSyncCheckpoint {
        vault_id: parse_uuid(row.try_get("vault_id")?)?,
        vault_revision: row.try_get("vault_revision")?,
        state_commitment: row.try_get("state_commitment")?,
        checkpoint_hash: row.try_get("checkpoint_hash")?,
        previous_checkpoint_hash: row.try_get("previous_checkpoint_hash")?,
        author_device_id: parse_uuid(row.try_get("author_device_id")?)?,
        signature: row.try_get("signature")?,
        created_at: parse_time(row.try_get("created_at")?)?,
    })
}
