use sqlx::Row;
use uuid::Uuid;

use crate::postgres::convert::item_revision_from_row;
use crate::{
    CreateItemConflict, DeletedItemRecord, ItemConflictRecord, PostgresStorage,
    ResolveItemConflict, ResolvedItemConflictRecord, StorageError,
};

impl PostgresStorage {
    pub async fn create_item_conflict(
        &self,
        input: CreateItemConflict,
    ) -> Result<ItemConflictRecord, StorageError> {
        let id = input.id.unwrap_or_else(Uuid::new_v4);
        let current_revision: i64 = sqlx::query_scalar(
            "SELECT current_revision FROM items WHERE id = $1 AND vault_id = $2 AND deleted_at IS NULL",
        ).bind(input.item_id).bind(input.vault_id).fetch_optional(&self.pool).await?.ok_or(StorageError::NotFound)?;
        let row = sqlx::query(
            "INSERT INTO item_conflicts (id, vault_id, item_id, base_revision, current_revision, candidate_kind, candidate_envelope, author_user_id) VALUES ($1,$2,$3,$4,$5,$6,$7,$8) RETURNING id,vault_id,item_id,base_revision,current_revision,candidate_kind,candidate_envelope,author_user_id,state,resolved_revision,created_at",
        ).bind(id).bind(input.vault_id).bind(input.item_id).bind(input.base_revision).bind(current_revision).bind(input.candidate_kind).bind(input.candidate_envelope).bind(input.author_user_id).fetch_one(&self.pool).await?;
        item_conflict_from_row(row)
    }

    pub async fn list_open_item_conflicts(
        &self,
        vault_id: Uuid,
    ) -> Result<Vec<ItemConflictRecord>, StorageError> {
        let rows = sqlx::query("SELECT id,vault_id,item_id,base_revision,current_revision,candidate_kind,candidate_envelope,author_user_id,state,resolved_revision,created_at FROM item_conflicts WHERE vault_id = $1 AND state = 'open' ORDER BY created_at ASC").bind(vault_id).fetch_all(&self.pool).await?;
        rows.into_iter().map(item_conflict_from_row).collect()
    }

    pub async fn find_item_conflict(
        &self,
        vault_id: Uuid,
        conflict_id: Uuid,
    ) -> Result<ItemConflictRecord, StorageError> {
        let row = sqlx::query("SELECT id,vault_id,item_id,base_revision,current_revision,candidate_kind,candidate_envelope,author_user_id,state,resolved_revision,created_at FROM item_conflicts WHERE vault_id = $1 AND id = $2")
            .bind(vault_id).bind(conflict_id).fetch_optional(&self.pool).await?.ok_or(StorageError::NotFound)?;
        item_conflict_from_row(row)
    }

    pub async fn resolve_item_conflict(
        &self,
        input: ResolveItemConflict,
    ) -> Result<ResolvedItemConflictRecord, StorageError> {
        let mut tx = self.pool.begin().await?;
        let row = sqlx::query("SELECT id,vault_id,item_id,base_revision,current_revision,candidate_kind,candidate_envelope,author_user_id,state,resolved_revision,created_at FROM item_conflicts WHERE vault_id = $1 AND id = $2 FOR UPDATE")
            .bind(input.vault_id).bind(input.conflict_id).fetch_optional(&mut *tx).await?.ok_or(StorageError::NotFound)?;
        let conflict = item_conflict_from_row(row)?;
        if conflict.state != "open" {
            return Err(StorageError::Conflict);
        }
        let current_revision: i64 = sqlx::query_scalar("SELECT current_revision FROM items WHERE id = $1 AND vault_id = $2 AND deleted_at IS NULL FOR UPDATE")
            .bind(conflict.item_id).bind(conflict.vault_id).fetch_optional(&mut *tx).await?.ok_or(StorageError::NotFound)?;
        if current_revision != input.expected_current_revision {
            return Err(StorageError::Conflict);
        }

        let mut revision = None;
        let mut deleted = None;
        if input.resolution == "local" || input.resolution == "merge" {
            if input.resolution == "local" && conflict.candidate_kind == "delete" {
                let vault_revision: i64 = sqlx::query_scalar("UPDATE vaults SET vault_revision = vault_revision + 1, updated_at = now() WHERE id = $1 RETURNING vault_revision").bind(conflict.vault_id).fetch_one(&mut *tx).await?;
                sqlx::query("UPDATE items SET deleted_at = now(), deleted_vault_revision = $3, updated_at = now() WHERE id = $1 AND vault_id = $2 AND deleted_at IS NULL").bind(conflict.item_id).bind(conflict.vault_id).bind(vault_revision).execute(&mut *tx).await?;
                deleted = Some(DeletedItemRecord {
                    item_id: conflict.item_id,
                    vault_id: conflict.vault_id,
                    deleted_vault_revision: vault_revision,
                });
            } else {
                let envelope = input.envelope.ok_or(StorageError::Conflict)?;
                let vault_revision: i64 = sqlx::query_scalar("UPDATE vaults SET vault_revision = vault_revision + 1, updated_at = now() WHERE id = $1 RETURNING vault_revision").bind(conflict.vault_id).fetch_one(&mut *tx).await?;
                let next_revision = current_revision + 1;
                sqlx::query("UPDATE items SET current_revision = $1, updated_at = now() WHERE id = $2 AND vault_id = $3 AND deleted_at IS NULL").bind(next_revision).bind(conflict.item_id).bind(conflict.vault_id).execute(&mut *tx).await?;
                let row = sqlx::query("INSERT INTO item_revisions (id,item_id,vault_id,revision,vault_revision,author_user_id,envelope,key_generation) VALUES ($1,$2,$3,$4,$5,$6,$7,(SELECT current_key_generation FROM vaults WHERE id = $3)) RETURNING id,item_id,vault_id,revision,vault_revision,key_generation,author_user_id,envelope,created_at")
                    .bind(Uuid::new_v4()).bind(conflict.item_id).bind(conflict.vault_id).bind(next_revision).bind(vault_revision).bind(input.author_user_id).bind(envelope).fetch_one(&mut *tx).await?;
                revision = Some(item_revision_from_row(row)?);
            }
        } else {
            sqlx::query("UPDATE vaults SET vault_revision = vault_revision + 1, updated_at = now() WHERE id = $1")
                .bind(conflict.vault_id).execute(&mut *tx).await?;
        }
        let resolved_revision = revision.as_ref().map(|record| record.revision);
        sqlx::query("UPDATE item_conflicts SET state = CASE WHEN id = $1 THEN 'resolved' ELSE 'discarded' END, resolved_revision = $2, resolved_at = now() WHERE vault_id = $3 AND item_id = $4 AND state = 'open'")
            .bind(conflict.id).bind(resolved_revision).bind(conflict.vault_id).bind(conflict.item_id).execute(&mut *tx).await?;
        let row = sqlx::query("SELECT id,vault_id,item_id,base_revision,current_revision,candidate_kind,candidate_envelope,author_user_id,state,resolved_revision,created_at FROM item_conflicts WHERE id = $1")
            .bind(conflict.id).fetch_one(&mut *tx).await?;
        tx.commit().await?;
        Ok(ResolvedItemConflictRecord {
            conflict: item_conflict_from_row(row)?,
            revision,
            deleted,
        })
    }
}

fn item_conflict_from_row(row: sqlx::postgres::PgRow) -> Result<ItemConflictRecord, StorageError> {
    Ok(ItemConflictRecord {
        id: row.try_get("id")?,
        vault_id: row.try_get("vault_id")?,
        item_id: row.try_get("item_id")?,
        base_revision: row.try_get("base_revision")?,
        current_revision: row.try_get("current_revision")?,
        candidate_kind: row.try_get("candidate_kind")?,
        candidate_envelope: row.try_get("candidate_envelope")?,
        author_user_id: row.try_get("author_user_id")?,
        state: row.try_get("state")?,
        resolved_revision: row.try_get("resolved_revision")?,
        created_at: row.try_get("created_at")?,
    })
}
