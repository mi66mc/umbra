use umbra_core::{RevisionId, VaultId};
use uuid::Uuid;

use sqlx::Row;

use crate::convert::item_kind_to_str;
use crate::error::map_sqlx_error;
use crate::sqlite::SqliteStorage;
use crate::sqlite::convert::item_revision_from_row;
use crate::{
    CreateEncryptedItem, CreateItemRevision, DeleteItem, DeletedItemRecord, ItemRevisionRecord,
    StorageError,
};

impl SqliteStorage {
    pub async fn create_encrypted_item(
        &self,
        input: CreateEncryptedItem,
    ) -> Result<ItemRevisionRecord, StorageError> {
        let item_id = input.item_id.unwrap_or_else(Uuid::new_v4);
        let revision_id = input.revision_id.unwrap_or_else(Uuid::new_v4);

        let mut tx = self.pool.begin().await?;
        let vault_revision: i64 = sqlx::query_scalar(
            "UPDATE vaults SET vault_revision = vault_revision + 1, updated_at = strftime('%Y-%m-%dT%H:%M:%fZ', 'now') WHERE id = ?1 RETURNING vault_revision",
        )
        .bind(input.vault_id.to_string())
        .fetch_optional(&mut *tx)
        .await?
        .ok_or(StorageError::NotFound)?;

        sqlx::query(
            "INSERT INTO items (id, vault_id, kind, current_revision, created_by) VALUES (?1, ?2, ?3, 1, ?4)",
        )
        .bind(item_id.to_string())
        .bind(input.vault_id.to_string())
        .bind(item_kind_to_str(&input.kind))
        .bind(input.author_user_id.map(|value| value.to_string()))
        .execute(&mut *tx)
        .await
        .map_err(map_sqlx_error)?;

        let row = sqlx::query(
            r#"
            INSERT INTO item_revisions (id, item_id, vault_id, revision, vault_revision, author_user_id, envelope, key_generation)
            VALUES (?1, ?2, ?3, 1, ?4, ?5, ?6, (SELECT current_key_generation FROM vaults WHERE id = ?3))
            RETURNING id, item_id, vault_id, revision, vault_revision, key_generation, author_user_id, envelope, created_at
            "#,
        )
        .bind(revision_id.to_string())
        .bind(item_id.to_string())
        .bind(input.vault_id.to_string())
        .bind(vault_revision)
        .bind(input.author_user_id.map(|value| value.to_string()))
        .bind(input.envelope.to_string())
        .fetch_one(&mut *tx)
        .await
        .map_err(map_sqlx_error)?;

        tx.commit().await?;
        item_revision_from_row(row)
    }

    pub async fn create_item_revision(
        &self,
        input: CreateItemRevision,
    ) -> Result<ItemRevisionRecord, StorageError> {
        let revision_id = input.revision_id.unwrap_or_else(Uuid::new_v4);
        let mut tx = self.pool.begin().await?;

        let current_revision: i64 = sqlx::query_scalar(
            "SELECT current_revision FROM items WHERE id = ?1 AND vault_id = ?2 AND deleted_at IS NULL",
        )
        .bind(input.item_id.to_string())
        .bind(input.vault_id.to_string())
        .fetch_optional(&mut *tx)
        .await?
        .ok_or(StorageError::NotFound)?;

        if current_revision != input.expected_revision {
            return Err(StorageError::Conflict);
        }
        let unresolved: bool = sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM item_conflicts WHERE vault_id = ?1 AND item_id = ?2 AND state = 'open')")
            .bind(input.vault_id.to_string()).bind(input.item_id.to_string()).fetch_one(&mut *tx).await?;
        if unresolved {
            return Err(StorageError::Conflict);
        }

        let next_revision = current_revision + 1;
        let vault_revision: i64 = sqlx::query_scalar(
            "UPDATE vaults SET vault_revision = vault_revision + 1, updated_at = strftime('%Y-%m-%dT%H:%M:%fZ', 'now') WHERE id = ?1 RETURNING vault_revision",
        )
        .bind(input.vault_id.to_string())
        .fetch_one(&mut *tx)
        .await?;

        sqlx::query(
            "UPDATE items SET current_revision = ?1, updated_at = strftime('%Y-%m-%dT%H:%M:%fZ', 'now') WHERE id = ?2 AND vault_id = ?3 AND deleted_at IS NULL",
        )
        .bind(next_revision)
        .bind(input.item_id.to_string())
        .bind(input.vault_id.to_string())
        .execute(&mut *tx)
        .await?;

        let row = sqlx::query(
            r#"
            INSERT INTO item_revisions (id, item_id, vault_id, revision, vault_revision, author_user_id, envelope, key_generation)
            VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, (SELECT current_key_generation FROM vaults WHERE id = ?3))
            RETURNING id, item_id, vault_id, revision, vault_revision, key_generation, author_user_id, envelope, created_at
            "#,
        )
        .bind(revision_id.to_string())
        .bind(input.item_id.to_string())
        .bind(input.vault_id.to_string())
        .bind(next_revision)
        .bind(vault_revision)
        .bind(input.author_user_id.map(|value| value.to_string()))
        .bind(input.envelope.to_string())
        .fetch_one(&mut *tx)
        .await
        .map_err(map_sqlx_error)?;

        tx.commit().await?;
        item_revision_from_row(row)
    }

    pub async fn delete_item(&self, input: DeleteItem) -> Result<DeletedItemRecord, StorageError> {
        let mut tx = self.pool.begin().await?;

        let current_revision: i64 = sqlx::query_scalar(
            "SELECT current_revision FROM items WHERE id = ?1 AND vault_id = ?2 AND deleted_at IS NULL",
        )
        .bind(input.item_id.to_string())
        .bind(input.vault_id.to_string())
        .fetch_optional(&mut *tx)
        .await?
        .ok_or(StorageError::NotFound)?;

        if current_revision != input.expected_revision {
            return Err(StorageError::Conflict);
        }
        let unresolved: bool = sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM item_conflicts WHERE vault_id = ?1 AND item_id = ?2 AND state = 'open')")
            .bind(input.vault_id.to_string()).bind(input.item_id.to_string()).fetch_one(&mut *tx).await?;
        if unresolved {
            return Err(StorageError::Conflict);
        }

        let vault_revision: i64 = sqlx::query_scalar(
            "UPDATE vaults SET vault_revision = vault_revision + 1, updated_at = strftime('%Y-%m-%dT%H:%M:%fZ', 'now') WHERE id = ?1 RETURNING vault_revision",
        )
        .bind(input.vault_id.to_string())
        .fetch_one(&mut *tx)
        .await?;

        let affected = sqlx::query(
            "UPDATE items SET deleted_at = strftime('%Y-%m-%dT%H:%M:%fZ', 'now'), deleted_vault_revision = ?3, updated_at = strftime('%Y-%m-%dT%H:%M:%fZ', 'now') WHERE id = ?1 AND vault_id = ?2 AND deleted_at IS NULL",
        )
        .bind(input.item_id.to_string())
        .bind(input.vault_id.to_string())
        .bind(vault_revision)
        .execute(&mut *tx)
        .await?
        .rows_affected();

        if affected != 1 {
            return Err(StorageError::NotFound);
        }

        tx.commit().await?;
        Ok(DeletedItemRecord {
            item_id: input.item_id,
            vault_id: input.vault_id,
            deleted_vault_revision: vault_revision,
        })
    }

    pub async fn list_deleted_item_ids_since(
        &self,
        vault_id: VaultId,
        since_vault_revision: RevisionId,
    ) -> Result<Vec<DeletedItemRecord>, StorageError> {
        let rows = sqlx::query(
            r#"
            SELECT id, vault_id, deleted_vault_revision
            FROM items
            WHERE vault_id = ?1
              AND deleted_vault_revision IS NOT NULL
              AND deleted_vault_revision > ?2
            ORDER BY deleted_vault_revision ASC, id ASC
            "#,
        )
        .bind(vault_id.to_string())
        .bind(since_vault_revision)
        .fetch_all(&self.pool)
        .await?;

        rows.into_iter()
            .map(|row| {
                Ok(DeletedItemRecord {
                    item_id: crate::sqlite::convert::parse_uuid(row.try_get::<String, _>("id")?)?,
                    vault_id: crate::sqlite::convert::parse_uuid(
                        row.try_get::<String, _>("vault_id")?,
                    )?,
                    deleted_vault_revision: row.try_get("deleted_vault_revision")?,
                })
            })
            .collect()
    }

    pub async fn list_item_revisions_since(
        &self,
        vault_id: VaultId,
        since_vault_revision: RevisionId,
    ) -> Result<Vec<ItemRevisionRecord>, StorageError> {
        let rows = sqlx::query(
            r#"
            SELECT ir.id, ir.item_id, ir.vault_id, ir.revision, ir.vault_revision, ir.key_generation, ir.author_user_id, ir.envelope, ir.created_at
            FROM item_revisions ir
            INNER JOIN items i ON i.id = ir.item_id AND i.vault_id = ir.vault_id
            WHERE ir.vault_id = ?1
              AND ir.vault_revision > ?2
              AND i.deleted_at IS NULL
            ORDER BY ir.vault_revision ASC
            "#,
        )
        .bind(vault_id.to_string())
        .bind(since_vault_revision)
        .fetch_all(&self.pool)
        .await?;

        rows.into_iter().map(item_revision_from_row).collect()
    }
}
