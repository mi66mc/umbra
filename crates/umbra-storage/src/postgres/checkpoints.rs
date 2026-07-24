use sqlx::Row;
use umbra_core::VaultId;

use crate::{
    CheckpointConflict, CreateSyncCheckpoint, PostgresStorage, StorageError, StoredSyncCheckpoint,
};

const CHECKPOINT_COLUMNS: &str = "vault_id, vault_revision, state_commitment, checkpoint_hash, previous_checkpoint_hash, author_device_id, signature, created_at";

impl PostgresStorage {
    pub async fn append_sync_checkpoint(
        &self,
        input: CreateSyncCheckpoint,
    ) -> Result<StoredSyncCheckpoint, StorageError> {
        let mut tx = self.pool.begin().await?;

        sqlx::query("SELECT pg_advisory_xact_lock(hashtext($1::text))")
            .bind(input.vault_id)
            .execute(&mut *tx)
            .await?;

        let existing = sqlx::query(&format!(
            "SELECT {CHECKPOINT_COLUMNS} FROM sync_checkpoints WHERE vault_id = $1 AND vault_revision = $2"
        ))
        .bind(input.vault_id)
        .bind(input.vault_revision)
        .fetch_optional(&mut *tx)
        .await?;
        if let Some(row) = existing {
            let checkpoint = sync_checkpoint_from_row(row)?;
            if checkpoint.checkpoint_hash == input.checkpoint_hash {
                tx.commit().await?;
                return Ok(checkpoint);
            }
            return Err(StorageError::CheckpointConflict(CheckpointConflict {
                vault_id: input.vault_id,
                vault_revision: input.vault_revision,
                existing_checkpoint_hash: checkpoint.checkpoint_hash,
                checkpoint_hash: input.checkpoint_hash,
            }));
        }

        let row = sqlx::query(&format!(
            "INSERT INTO sync_checkpoints (checkpoint_hash, vault_id, vault_revision, state_commitment, previous_checkpoint_hash, author_device_id, signature) VALUES ($1, $2, $3, $4, $5, $6, $7) RETURNING {CHECKPOINT_COLUMNS}"
        ))
        .bind(input.checkpoint_hash)
        .bind(input.vault_id)
        .bind(input.vault_revision)
        .bind(input.state_commitment)
        .bind(input.previous_checkpoint_hash)
        .bind(input.author_device_id)
        .bind(input.signature)
        .fetch_one(&mut *tx)
        .await?;
        tx.commit().await?;

        sync_checkpoint_from_row(row)
    }

    pub async fn list_sync_checkpoints_since(
        &self,
        vault_id: VaultId,
        since_vault_revision: i64,
    ) -> Result<Vec<StoredSyncCheckpoint>, StorageError> {
        let rows = sqlx::query(&format!(
            "SELECT {CHECKPOINT_COLUMNS} FROM sync_checkpoints WHERE vault_id = $1 AND vault_revision > $2 ORDER BY vault_revision ASC, created_at ASC"
        ))
        .bind(vault_id)
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
            "SELECT {CHECKPOINT_COLUMNS} FROM sync_checkpoints WHERE vault_id = $1 AND vault_revision = $2"
        ))
        .bind(vault_id)
        .bind(vault_revision)
        .fetch_optional(&self.pool)
        .await?
        .map(sync_checkpoint_from_row)
        .transpose()
    }
}

fn sync_checkpoint_from_row(
    row: sqlx::postgres::PgRow,
) -> Result<StoredSyncCheckpoint, StorageError> {
    Ok(StoredSyncCheckpoint {
        vault_id: row.try_get("vault_id")?,
        vault_revision: row.try_get("vault_revision")?,
        state_commitment: row.try_get("state_commitment")?,
        checkpoint_hash: row.try_get("checkpoint_hash")?,
        previous_checkpoint_hash: row.try_get("previous_checkpoint_hash")?,
        author_device_id: row.try_get("author_device_id")?,
        signature: row.try_get("signature")?,
        created_at: row.try_get("created_at")?,
    })
}
