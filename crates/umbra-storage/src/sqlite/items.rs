use umbra_core::{RevisionId, VaultId};
use uuid::Uuid;

use crate::convert::item_kind_to_str;
use crate::error::map_sqlx_error;
use crate::sqlite::SqliteStorage;
use crate::sqlite::convert::item_revision_from_row;
use crate::{CreateEncryptedItem, CreateItemRevision, ItemRevisionRecord, StorageError};

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
            "SELECT current_revision FROM items WHERE id = ?1 AND vault_id = ?2",
        )
        .bind(input.item_id.to_string())
        .bind(input.vault_id.to_string())
        .fetch_optional(&mut *tx)
        .await?
        .ok_or(StorageError::NotFound)?;

        if current_revision != input.expected_revision {
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
            "UPDATE items SET current_revision = ?1, updated_at = strftime('%Y-%m-%dT%H:%M:%fZ', 'now') WHERE id = ?2",
        )
        .bind(next_revision)
        .bind(input.item_id.to_string())
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

    pub async fn list_item_revisions_since(
        &self,
        vault_id: VaultId,
        since_vault_revision: RevisionId,
    ) -> Result<Vec<ItemRevisionRecord>, StorageError> {
        let rows = sqlx::query(
            r#"
            SELECT id, item_id, vault_id, revision, vault_revision, key_generation, author_user_id, envelope, created_at
            FROM item_revisions
            WHERE vault_id = ?1 AND vault_revision > ?2
            ORDER BY vault_revision ASC
            "#,
        )
        .bind(vault_id.to_string())
        .bind(since_vault_revision)
        .fetch_all(&self.pool)
        .await?;

        rows.into_iter().map(item_revision_from_row).collect()
    }
}
