use sqlx::Row;
use umbra_core::{UserId, VaultId};
use uuid::Uuid;

use crate::convert::{member_state_to_str, vault_kind_to_str, vault_role_to_str};
use crate::error::{ensure_rows_affected, map_sqlx_error};
use crate::sqlite::SqliteStorage;
use crate::sqlite::convert::{
    vault_from_row, vault_key_wrapping_from_row, vault_member_from_row, vault_sync_status_from_row,
};
use crate::{
    CreateVault, CreateVaultKeyWrapping, FinishVaultKeyRotation, RotationStatusRecord,
    StorageError, UpsertVaultMember, VaultKeyWrappingRecord, VaultMemberRecord, VaultRecord,
    VaultSyncStatusRecord,
};

const VAULT_COLUMNS: &str = "id, org_id, name, kind, vault_revision, access_revision, current_key_generation, needs_key_rotation, created_by, created_at, updated_at, deleted_at, crypto_policy";
const WRAPPING_COLUMNS: &str = "id, vault_id, user_id, device_id, wrapping_type, envelope, key_generation, created_at, rotated_at, revoked_at";

impl SqliteStorage {
    pub async fn create_vault(&self, input: CreateVault) -> Result<VaultRecord, StorageError> {
        let id = input.id.unwrap_or_else(Uuid::new_v4);
        let row = sqlx::query(&format!(
            r#"
            INSERT INTO vaults (id, org_id, name, kind, created_by, crypto_policy)
            VALUES (?1, ?2, ?3, ?4, ?5, ?6)
            RETURNING {VAULT_COLUMNS}
            "#
        ))
        .bind(id.to_string())
        .bind(input.org_id.map(|value| value.to_string()))
        .bind(input.name)
        .bind(vault_kind_to_str(input.kind))
        .bind(input.created_by.map(|value| value.to_string()))
        .bind(input.crypto_policy.to_string())
        .fetch_one(&self.pool)
        .await
        .map_err(map_sqlx_error)?;

        vault_from_row(row)
    }

    pub async fn find_vault_by_id(&self, vault_id: VaultId) -> Result<VaultRecord, StorageError> {
        let row = sqlx::query(&format!("SELECT {VAULT_COLUMNS} FROM vaults WHERE id = ?1"))
            .bind(vault_id.to_string())
            .fetch_optional(&self.pool)
            .await?
            .ok_or(StorageError::NotFound)?;

        vault_from_row(row)
    }

    pub async fn list_vaults_for_user(
        &self,
        user_id: UserId,
    ) -> Result<Vec<VaultRecord>, StorageError> {
        let rows = sqlx::query(&format!(
            r#"
            SELECT v.{}
            FROM vaults v
            JOIN vault_members vm ON vm.vault_id = v.id
            WHERE vm.user_id = ?1 AND vm.state = 'active' AND v.deleted_at IS NULL
            ORDER BY v.created_at ASC
            "#,
            VAULT_COLUMNS.replace(", ", ", v.")
        ))
        .bind(user_id.to_string())
        .fetch_all(&self.pool)
        .await?;

        rows.into_iter().map(vault_from_row).collect()
    }

    pub async fn upsert_vault_member(
        &self,
        input: UpsertVaultMember,
    ) -> Result<VaultMemberRecord, StorageError> {
        let mut tx = self.pool.begin().await?;
        let row = sqlx::query(
            r#"
            INSERT INTO vault_members (vault_id, user_id, role, state)
            VALUES (?1, ?2, ?3, ?4)
            ON CONFLICT(vault_id, user_id) DO UPDATE SET
                role = excluded.role,
                state = excluded.state,
                updated_at = strftime('%Y-%m-%dT%H:%M:%fZ', 'now')
            RETURNING vault_id, user_id, role, state, created_at, updated_at
            "#,
        )
        .bind(input.vault_id.to_string())
        .bind(input.user_id.to_string())
        .bind(vault_role_to_str(input.role))
        .bind(member_state_to_str(input.state))
        .fetch_one(&mut *tx)
        .await
        .map_err(map_sqlx_error)?;

        let result = sqlx::query(
            "UPDATE vaults SET access_revision = access_revision + 1, updated_at = strftime('%Y-%m-%dT%H:%M:%fZ', 'now') WHERE id = ?1",
        )
        .bind(input.vault_id.to_string())
        .execute(&mut *tx)
        .await?;
        ensure_rows_affected(result.rows_affected())?;

        tx.commit().await?;
        vault_member_from_row(row)
    }

    pub async fn list_vault_members(
        &self,
        vault_id: VaultId,
    ) -> Result<Vec<VaultMemberRecord>, StorageError> {
        let rows = sqlx::query(
            "SELECT vault_id, user_id, role, state, created_at, updated_at FROM vault_members WHERE vault_id = ?1 ORDER BY created_at ASC",
        )
        .bind(vault_id.to_string())
        .fetch_all(&self.pool)
        .await?;

        rows.into_iter().map(vault_member_from_row).collect()
    }

    pub async fn has_active_vault_membership(
        &self,
        vault_id: VaultId,
        user_id: UserId,
    ) -> Result<bool, StorageError> {
        let exists: i64 = sqlx::query_scalar(
            "SELECT COUNT(*) FROM vault_members WHERE vault_id = ?1 AND user_id = ?2 AND state = 'active'",
        )
        .bind(vault_id.to_string())
        .bind(user_id.to_string())
        .fetch_one(&self.pool)
        .await?;

        Ok(exists > 0)
    }

    pub async fn create_vault_key_wrapping(
        &self,
        input: CreateVaultKeyWrapping,
    ) -> Result<VaultKeyWrappingRecord, StorageError> {
        let id = input.id.unwrap_or_else(Uuid::new_v4);
        let mut tx = self.pool.begin().await?;

        let result = sqlx::query(
            "UPDATE vaults SET access_revision = access_revision + 1, updated_at = strftime('%Y-%m-%dT%H:%M:%fZ', 'now') WHERE id = ?1",
        )
        .bind(input.vault_id.to_string())
        .execute(&mut *tx)
        .await?;
        ensure_rows_affected(result.rows_affected())?;

        let row = sqlx::query(&format!(
            r#"
            INSERT INTO vault_key_wrappings (id, vault_id, user_id, device_id, wrapping_type, envelope, key_generation)
            VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)
            RETURNING {WRAPPING_COLUMNS}
            "#
        ))
        .bind(id.to_string())
        .bind(input.vault_id.to_string())
        .bind(input.user_id.to_string())
        .bind(input.device_id.map(|value| value.to_string()))
        .bind(input.wrapping_type)
        .bind(input.envelope.to_string())
        .bind(input.key_generation)
        .fetch_one(&mut *tx)
        .await
        .map_err(map_sqlx_error)?;

        tx.commit().await?;
        vault_key_wrapping_from_row(row)
    }

    pub async fn list_key_wrappings_for_user_vault(
        &self,
        user_id: UserId,
        vault_id: VaultId,
    ) -> Result<Vec<VaultKeyWrappingRecord>, StorageError> {
        let rows = sqlx::query(&format!(
            "SELECT {WRAPPING_COLUMNS} FROM vault_key_wrappings WHERE user_id = ?1 AND vault_id = ?2 AND revoked_at IS NULL ORDER BY created_at ASC"
        ))
        .bind(user_id.to_string())
        .bind(vault_id.to_string())
        .fetch_all(&self.pool)
        .await?;

        rows.into_iter().map(vault_key_wrapping_from_row).collect()
    }

    pub async fn remove_vault_member(
        &self,
        vault_id: VaultId,
        user_id: UserId,
    ) -> Result<(), StorageError> {
        let mut tx = self.pool.begin().await?;

        let member_result = sqlx::query(
            "UPDATE vault_members SET state = 'removed', updated_at = strftime('%Y-%m-%dT%H:%M:%fZ', 'now') WHERE vault_id = ?1 AND user_id = ?2",
        )
        .bind(vault_id.to_string())
        .bind(user_id.to_string())
        .execute(&mut *tx)
        .await?;
        ensure_rows_affected(member_result.rows_affected())?;

        sqlx::query(
            "UPDATE vault_key_wrappings SET revoked_at = strftime('%Y-%m-%dT%H:%M:%fZ', 'now') WHERE vault_id = ?1 AND user_id = ?2 AND revoked_at IS NULL",
        )
        .bind(vault_id.to_string())
        .bind(user_id.to_string())
        .execute(&mut *tx)
        .await?;

        sqlx::query(
            "UPDATE vaults SET access_revision = access_revision + 1, needs_key_rotation = 1, updated_at = strftime('%Y-%m-%dT%H:%M:%fZ', 'now') WHERE id = ?1",
        )
        .bind(vault_id.to_string())
        .execute(&mut *tx)
        .await?;

        tx.commit().await?;
        Ok(())
    }

    pub async fn revoke_key_wrapping(&self, wrapping_id: Uuid) -> Result<(), StorageError> {
        let mut tx = self.pool.begin().await?;
        let vault_id: String = sqlx::query_scalar(
            "UPDATE vault_key_wrappings SET revoked_at = strftime('%Y-%m-%dT%H:%M:%fZ', 'now') WHERE id = ?1 RETURNING vault_id",
        )
        .bind(wrapping_id.to_string())
        .fetch_optional(&mut *tx)
        .await?
        .ok_or(StorageError::NotFound)?;

        let result = sqlx::query(
            "UPDATE vaults SET access_revision = access_revision + 1, updated_at = strftime('%Y-%m-%dT%H:%M:%fZ', 'now') WHERE id = ?1",
        )
        .bind(vault_id)
        .execute(&mut *tx)
        .await?;
        ensure_rows_affected(result.rows_affected())?;

        tx.commit().await?;
        Ok(())
    }

    pub async fn rotation_status(
        &self,
        vault_id: VaultId,
    ) -> Result<RotationStatusRecord, StorageError> {
        let row = sqlx::query(
            "SELECT id, current_key_generation, needs_key_rotation FROM vaults WHERE id = ?1",
        )
        .bind(vault_id.to_string())
        .fetch_optional(&self.pool)
        .await?
        .ok_or(StorageError::NotFound)?;

        let needs_key_rotation: i64 = row.try_get("needs_key_rotation")?;
        Ok(RotationStatusRecord {
            vault_id: crate::sqlite::convert::parse_uuid(row.try_get("id")?)?,
            current_key_generation: row.try_get("current_key_generation")?,
            needs_key_rotation: needs_key_rotation != 0,
        })
    }

    pub async fn vault_sync_status(
        &self,
        vault_id: VaultId,
        user_id: UserId,
    ) -> Result<VaultSyncStatusRecord, StorageError> {
        let row = sqlx::query(
            r#"
            SELECT
                v.id AS vault_id,
                v.vault_revision AS latest_vault_revision,
                v.access_revision AS latest_access_revision,
                v.current_key_generation,
                v.needs_key_rotation
            FROM vaults v
            JOIN vault_members vm ON vm.vault_id = v.id
            WHERE v.id = ?1
              AND vm.user_id = ?2
              AND vm.state = 'active'
              AND v.deleted_at IS NULL
            "#,
        )
        .bind(vault_id.to_string())
        .bind(user_id.to_string())
        .fetch_optional(&self.pool)
        .await?
        .ok_or(StorageError::NotFound)?;

        vault_sync_status_from_row(row)
    }

    pub async fn finish_vault_key_rotation(
        &self,
        input: FinishVaultKeyRotation,
    ) -> Result<RotationStatusRecord, StorageError> {
        if input.to_generation != input.from_generation + 1 {
            return Err(StorageError::Conflict);
        }

        let mut tx = self.pool.begin().await?;
        let current_generation: i64 =
            sqlx::query_scalar("SELECT current_key_generation FROM vaults WHERE id = ?1")
                .bind(input.vault_id.to_string())
                .fetch_optional(&mut *tx)
                .await?
                .ok_or(StorageError::NotFound)?;

        if current_generation != input.from_generation {
            return Err(StorageError::Conflict);
        }

        sqlx::query(
            "UPDATE vault_key_wrappings SET revoked_at = strftime('%Y-%m-%dT%H:%M:%fZ', 'now'), rotated_at = strftime('%Y-%m-%dT%H:%M:%fZ', 'now') WHERE vault_id = ?1 AND revoked_at IS NULL",
        )
        .bind(input.vault_id.to_string())
        .execute(&mut *tx)
        .await?;

        for wrapping in input.new_wrappings {
            sqlx::query(
                "INSERT INTO vault_key_wrappings (id, vault_id, user_id, device_id, wrapping_type, envelope, key_generation) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)",
            )
            .bind(wrapping.id.unwrap_or_else(Uuid::new_v4).to_string())
            .bind(input.vault_id.to_string())
            .bind(wrapping.user_id.to_string())
            .bind(wrapping.device_id.map(|value| value.to_string()))
            .bind(wrapping.wrapping_type)
            .bind(wrapping.envelope.to_string())
            .bind(input.to_generation)
            .execute(&mut *tx)
            .await
            .map_err(map_sqlx_error)?;
        }

        for revision in input.reencrypted_revisions {
            let current_revision: i64 = sqlx::query_scalar(
                "SELECT current_revision FROM items WHERE id = ?1 AND vault_id = ?2",
            )
            .bind(revision.item_id.to_string())
            .bind(input.vault_id.to_string())
            .fetch_optional(&mut *tx)
            .await?
            .ok_or(StorageError::NotFound)?;

            if current_revision != revision.expected_revision {
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
            .bind(revision.item_id.to_string())
            .execute(&mut *tx)
            .await?;

            sqlx::query(
                "INSERT INTO item_revisions (id, item_id, vault_id, revision, vault_revision, author_user_id, envelope, key_generation) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)",
            )
            .bind(revision.revision_id.unwrap_or_else(Uuid::new_v4).to_string())
            .bind(revision.item_id.to_string())
            .bind(input.vault_id.to_string())
            .bind(next_revision)
            .bind(vault_revision)
            .bind(input.author_user_id.map(|value| value.to_string()))
            .bind(revision.envelope.to_string())
            .bind(input.to_generation)
            .execute(&mut *tx)
            .await
            .map_err(map_sqlx_error)?;
        }

        let row = sqlx::query(
            r#"
            UPDATE vaults
            SET current_key_generation = ?2,
                access_revision = access_revision + 1,
                needs_key_rotation = 0,
                updated_at = strftime('%Y-%m-%dT%H:%M:%fZ', 'now')
            WHERE id = ?1
            RETURNING id, current_key_generation, needs_key_rotation
            "#,
        )
        .bind(input.vault_id.to_string())
        .bind(input.to_generation)
        .fetch_one(&mut *tx)
        .await?;

        tx.commit().await?;
        let needs_key_rotation: i64 = row.try_get("needs_key_rotation")?;
        Ok(RotationStatusRecord {
            vault_id: crate::sqlite::convert::parse_uuid(row.try_get("id")?)?,
            current_key_generation: row.try_get("current_key_generation")?,
            needs_key_rotation: needs_key_rotation != 0,
        })
    }
}
