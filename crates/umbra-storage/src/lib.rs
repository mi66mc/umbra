use chrono::{DateTime, Utc};
use serde_json::Value;
use sqlx::{PgPool, Row, postgres::PgPoolOptions};
use umbra_core::{
    DeviceId, ItemId, ItemKind, MemberState, OrgId, OrgRole, RevisionId, UserId, VaultId,
    VaultKind, VaultRole,
};
use uuid::Uuid;

#[derive(Clone)]
pub struct Storage {
    pool: PgPool,
}

impl Storage {
    pub async fn connect(database_url: &str) -> Result<Self, StorageError> {
        let pool = PgPoolOptions::new()
            .max_connections(10)
            .connect(database_url)
            .await?;

        Ok(Self { pool })
    }

    pub fn from_pool(pool: PgPool) -> Self {
        Self { pool }
    }

    pub fn pool(&self) -> &PgPool {
        &self.pool
    }

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

    pub async fn create_device(&self, input: CreateDevice) -> Result<DeviceRecord, StorageError> {
        let id = input.id.unwrap_or_else(Uuid::new_v4);
        let row = sqlx::query(
            r#"
            INSERT INTO devices (id, user_id, name, public_key, fingerprint, trusted)
            VALUES ($1, $2, $3, $4, $5, $6)
            RETURNING id, user_id, name, public_key, fingerprint, trusted, created_at, last_seen_at, revoked_at
            "#,
        )
        .bind(id)
        .bind(input.user_id)
        .bind(input.name)
        .bind(input.public_key)
        .bind(input.fingerprint)
        .bind(input.trusted)
        .fetch_one(&self.pool)
        .await
        .map_err(map_sqlx_error)?;

        device_from_row(row)
    }

    pub async fn list_devices_for_user(
        &self,
        user_id: UserId,
    ) -> Result<Vec<DeviceRecord>, StorageError> {
        let rows = sqlx::query(
            r#"
            SELECT id, user_id, name, public_key, fingerprint, trusted, created_at, last_seen_at, revoked_at
            FROM devices
            WHERE user_id = $1
            ORDER BY created_at ASC
            "#,
        )
        .bind(user_id)
        .fetch_all(&self.pool)
        .await?;

        rows.into_iter().map(device_from_row).collect()
    }

    pub async fn revoke_device(&self, device_id: DeviceId) -> Result<(), StorageError> {
        let result = sqlx::query("UPDATE devices SET revoked_at = now() WHERE id = $1")
            .bind(device_id)
            .execute(&self.pool)
            .await?;

        ensure_rows_affected(result.rows_affected())
    }

    pub async fn create_vault(&self, input: CreateVault) -> Result<VaultRecord, StorageError> {
        let id = input.id.unwrap_or_else(Uuid::new_v4);
        let row = sqlx::query(
            r#"
            INSERT INTO vaults (id, org_id, name, kind, created_by, crypto_policy)
            VALUES ($1, $2, $3, $4, $5, $6)
            RETURNING id, org_id, name, kind, vault_revision, current_key_generation, needs_key_rotation, created_by, created_at, updated_at, deleted_at, crypto_policy
            "#,
        )
        .bind(id)
        .bind(input.org_id)
        .bind(input.name)
        .bind(vault_kind_to_str(input.kind))
        .bind(input.created_by)
        .bind(input.crypto_policy)
        .fetch_one(&self.pool)
        .await
        .map_err(map_sqlx_error)?;

        vault_from_row(row)
    }

    pub async fn find_vault_by_id(&self, vault_id: VaultId) -> Result<VaultRecord, StorageError> {
        let row = sqlx::query(
            r#"
            SELECT id, org_id, name, kind, vault_revision, current_key_generation, needs_key_rotation, created_by, created_at, updated_at, deleted_at, crypto_policy
            FROM vaults
            WHERE id = $1
            "#,
        )
        .bind(vault_id)
        .fetch_optional(&self.pool)
        .await?
        .ok_or(StorageError::NotFound)?;

        vault_from_row(row)
    }

    pub async fn list_vaults_for_user(
        &self,
        user_id: UserId,
    ) -> Result<Vec<VaultRecord>, StorageError> {
        let rows = sqlx::query(
            r#"
            SELECT v.id, v.org_id, v.name, v.kind, v.vault_revision, v.current_key_generation, v.needs_key_rotation, v.created_by, v.created_at, v.updated_at, v.deleted_at, v.crypto_policy
            FROM vaults v
            JOIN vault_members vm ON vm.vault_id = v.id
            WHERE vm.user_id = $1 AND vm.state = 'active' AND v.deleted_at IS NULL
            ORDER BY v.created_at ASC
            "#,
        )
        .bind(user_id)
        .fetch_all(&self.pool)
        .await?;

        rows.into_iter().map(vault_from_row).collect()
    }

    pub async fn create_org(&self, input: CreateOrg) -> Result<OrgRecord, StorageError> {
        let id = input.id.unwrap_or_else(Uuid::new_v4);
        let row = sqlx::query(
            r#"
            INSERT INTO orgs (id, name, created_by)
            VALUES ($1, $2, $3)
            RETURNING id, name, created_by, created_at, updated_at, deleted_at
            "#,
        )
        .bind(id)
        .bind(input.name)
        .bind(input.created_by)
        .fetch_one(&self.pool)
        .await
        .map_err(map_sqlx_error)?;

        org_from_row(row)
    }

    pub async fn find_org_by_id(&self, org_id: OrgId) -> Result<OrgRecord, StorageError> {
        let row = sqlx::query(
            r#"
            SELECT id, name, created_by, created_at, updated_at, deleted_at
            FROM orgs
            WHERE id = $1
            "#,
        )
        .bind(org_id)
        .fetch_optional(&self.pool)
        .await?
        .ok_or(StorageError::NotFound)?;

        org_from_row(row)
    }

    pub async fn list_orgs_for_user(
        &self,
        user_id: UserId,
    ) -> Result<Vec<OrgRecord>, StorageError> {
        let rows = sqlx::query(
            r#"
            SELECT o.id, o.name, o.created_by, o.created_at, o.updated_at, o.deleted_at
            FROM orgs o
            JOIN org_members om ON om.org_id = o.id
            WHERE om.user_id = $1 AND om.state = 'active' AND o.deleted_at IS NULL
            ORDER BY o.created_at ASC
            "#,
        )
        .bind(user_id)
        .fetch_all(&self.pool)
        .await?;

        rows.into_iter().map(org_from_row).collect()
    }

    pub async fn upsert_org_member(
        &self,
        input: UpsertOrgMember,
    ) -> Result<OrgMemberRecord, StorageError> {
        let row = sqlx::query(
            r#"
            INSERT INTO org_members (org_id, user_id, role, state)
            VALUES ($1, $2, $3, $4)
            ON CONFLICT (org_id, user_id)
            DO UPDATE SET role = EXCLUDED.role, state = EXCLUDED.state, updated_at = now()
            RETURNING org_id, user_id, role, state, created_at, updated_at
            "#,
        )
        .bind(input.org_id)
        .bind(input.user_id)
        .bind(org_role_to_str(input.role))
        .bind(member_state_to_str(input.state))
        .fetch_one(&self.pool)
        .await
        .map_err(map_sqlx_error)?;

        org_member_from_row(row)
    }

    pub async fn list_org_members(
        &self,
        org_id: OrgId,
    ) -> Result<Vec<OrgMemberRecord>, StorageError> {
        let rows = sqlx::query(
            r#"
            SELECT org_id, user_id, role, state, created_at, updated_at
            FROM org_members
            WHERE org_id = $1
            ORDER BY created_at ASC
            "#,
        )
        .bind(org_id)
        .fetch_all(&self.pool)
        .await?;

        rows.into_iter().map(org_member_from_row).collect()
    }

    pub async fn find_org_member(
        &self,
        org_id: OrgId,
        user_id: UserId,
    ) -> Result<OrgMemberRecord, StorageError> {
        let row = sqlx::query(
            r#"
            SELECT org_id, user_id, role, state, created_at, updated_at
            FROM org_members
            WHERE org_id = $1 AND user_id = $2
            "#,
        )
        .bind(org_id)
        .bind(user_id)
        .fetch_optional(&self.pool)
        .await?
        .ok_or(StorageError::NotFound)?;

        org_member_from_row(row)
    }

    pub async fn upsert_vault_member(
        &self,
        input: UpsertVaultMember,
    ) -> Result<VaultMemberRecord, StorageError> {
        let row = sqlx::query(
            r#"
            INSERT INTO vault_members (vault_id, user_id, role, state)
            VALUES ($1, $2, $3, $4)
            ON CONFLICT (vault_id, user_id)
            DO UPDATE SET role = EXCLUDED.role, state = EXCLUDED.state, updated_at = now()
            RETURNING vault_id, user_id, role, state, created_at, updated_at
            "#,
        )
        .bind(input.vault_id)
        .bind(input.user_id)
        .bind(vault_role_to_str(input.role))
        .bind(member_state_to_str(input.state))
        .fetch_one(&self.pool)
        .await
        .map_err(map_sqlx_error)?;

        vault_member_from_row(row)
    }

    pub async fn list_vault_members(
        &self,
        vault_id: VaultId,
    ) -> Result<Vec<VaultMemberRecord>, StorageError> {
        let rows = sqlx::query(
            r#"
            SELECT vault_id, user_id, role, state, created_at, updated_at
            FROM vault_members
            WHERE vault_id = $1
            ORDER BY created_at ASC
            "#,
        )
        .bind(vault_id)
        .fetch_all(&self.pool)
        .await?;

        rows.into_iter().map(vault_member_from_row).collect()
    }

    pub async fn has_active_vault_membership(
        &self,
        vault_id: VaultId,
        user_id: UserId,
    ) -> Result<bool, StorageError> {
        let exists: bool = sqlx::query_scalar(
            r#"
            SELECT EXISTS (
                SELECT 1
                FROM vault_members
                WHERE vault_id = $1 AND user_id = $2 AND state = 'active'
            )
            "#,
        )
        .bind(vault_id)
        .bind(user_id)
        .fetch_one(&self.pool)
        .await?;

        Ok(exists)
    }

    pub async fn create_vault_key_wrapping(
        &self,
        input: CreateVaultKeyWrapping,
    ) -> Result<VaultKeyWrappingRecord, StorageError> {
        let id = input.id.unwrap_or_else(Uuid::new_v4);
        let row = sqlx::query(
            r#"
            INSERT INTO vault_key_wrappings (id, vault_id, user_id, device_id, wrapping_type, envelope, key_generation)
            VALUES ($1, $2, $3, $4, $5, $6, $7)
            RETURNING id, vault_id, user_id, device_id, wrapping_type, envelope, key_generation, created_at, rotated_at, revoked_at
            "#,
        )
        .bind(id)
        .bind(input.vault_id)
        .bind(input.user_id)
        .bind(input.device_id)
        .bind(input.wrapping_type)
        .bind(input.envelope)
        .bind(input.key_generation)
        .fetch_one(&self.pool)
        .await
        .map_err(map_sqlx_error)?;

        vault_key_wrapping_from_row(row)
    }

    pub async fn list_key_wrappings_for_user_vault(
        &self,
        user_id: UserId,
        vault_id: VaultId,
    ) -> Result<Vec<VaultKeyWrappingRecord>, StorageError> {
        let rows = sqlx::query(
            r#"
            SELECT id, vault_id, user_id, device_id, wrapping_type, envelope, key_generation, created_at, rotated_at, revoked_at
            FROM vault_key_wrappings
            WHERE user_id = $1 AND vault_id = $2 AND revoked_at IS NULL
            ORDER BY created_at ASC
            "#,
        )
        .bind(user_id)
        .bind(vault_id)
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
            r#"
            UPDATE vault_members
            SET state = 'removed', updated_at = now()
            WHERE vault_id = $1 AND user_id = $2
            "#,
        )
        .bind(vault_id)
        .bind(user_id)
        .execute(&mut *tx)
        .await?;

        if member_result.rows_affected() == 0 {
            return Err(StorageError::NotFound);
        }

        sqlx::query(
            r#"
            UPDATE vault_key_wrappings
            SET revoked_at = now()
            WHERE vault_id = $1 AND user_id = $2 AND revoked_at IS NULL
            "#,
        )
        .bind(vault_id)
        .bind(user_id)
        .execute(&mut *tx)
        .await?;

        sqlx::query(
            "UPDATE vaults SET needs_key_rotation = true, updated_at = now() WHERE id = $1",
        )
        .bind(vault_id)
        .execute(&mut *tx)
        .await?;

        tx.commit().await?;
        Ok(())
    }

    pub async fn revoke_key_wrapping(&self, wrapping_id: Uuid) -> Result<(), StorageError> {
        let result = sqlx::query("UPDATE vault_key_wrappings SET revoked_at = now() WHERE id = $1")
            .bind(wrapping_id)
            .execute(&self.pool)
            .await?;

        ensure_rows_affected(result.rows_affected())
    }

    pub async fn create_encrypted_item(
        &self,
        input: CreateEncryptedItem,
    ) -> Result<ItemRevisionRecord, StorageError> {
        let item_id = input.item_id.unwrap_or_else(Uuid::new_v4);
        let revision_id = input.revision_id.unwrap_or_else(Uuid::new_v4);

        let mut tx = self.pool.begin().await?;
        let vault_revision: i64 = sqlx::query_scalar(
            r#"
            UPDATE vaults
            SET vault_revision = vault_revision + 1, updated_at = now()
            WHERE id = $1
            RETURNING vault_revision
            "#,
        )
        .bind(input.vault_id)
        .fetch_optional(&mut *tx)
        .await?
        .ok_or(StorageError::NotFound)?;

        sqlx::query(
            r#"
            INSERT INTO items (id, vault_id, kind, current_revision, created_by)
            VALUES ($1, $2, $3, 1, $4)
            "#,
        )
        .bind(item_id)
        .bind(input.vault_id)
        .bind(item_kind_to_str(&input.kind))
        .bind(input.author_user_id)
        .execute(&mut *tx)
        .await
        .map_err(map_sqlx_error)?;

        let row = sqlx::query(
            r#"
            INSERT INTO item_revisions (id, item_id, vault_id, revision, vault_revision, author_user_id, envelope, key_generation)
            VALUES ($1, $2, $3, 1, $4, $5, $6, (SELECT current_key_generation FROM vaults WHERE id = $3))
            RETURNING id, item_id, vault_id, revision, vault_revision, key_generation, author_user_id, envelope, created_at
            "#,
        )
        .bind(revision_id)
        .bind(item_id)
        .bind(input.vault_id)
        .bind(vault_revision)
        .bind(input.author_user_id)
        .bind(input.envelope)
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
            "SELECT current_revision FROM items WHERE id = $1 AND vault_id = $2",
        )
        .bind(input.item_id)
        .bind(input.vault_id)
        .fetch_optional(&mut *tx)
        .await?
        .ok_or(StorageError::NotFound)?;

        if current_revision != input.expected_revision {
            return Err(StorageError::Conflict);
        }

        let next_revision = current_revision + 1;
        let vault_revision: i64 = sqlx::query_scalar(
            r#"
            UPDATE vaults
            SET vault_revision = vault_revision + 1, updated_at = now()
            WHERE id = $1
            RETURNING vault_revision
            "#,
        )
        .bind(input.vault_id)
        .fetch_one(&mut *tx)
        .await?;

        sqlx::query(
            r#"
            UPDATE items
            SET current_revision = $1, updated_at = now()
            WHERE id = $2
            "#,
        )
        .bind(next_revision)
        .bind(input.item_id)
        .execute(&mut *tx)
        .await?;

        let row = sqlx::query(
            r#"
            INSERT INTO item_revisions (id, item_id, vault_id, revision, vault_revision, author_user_id, envelope, key_generation)
            VALUES ($1, $2, $3, $4, $5, $6, $7, (SELECT current_key_generation FROM vaults WHERE id = $3))
            RETURNING id, item_id, vault_id, revision, vault_revision, key_generation, author_user_id, envelope, created_at
            "#,
        )
        .bind(revision_id)
        .bind(input.item_id)
        .bind(input.vault_id)
        .bind(next_revision)
        .bind(vault_revision)
        .bind(input.author_user_id)
        .bind(input.envelope)
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
            WHERE vault_id = $1 AND vault_revision > $2
            ORDER BY vault_revision ASC
            "#,
        )
        .bind(vault_id)
        .bind(since_vault_revision)
        .fetch_all(&self.pool)
        .await?;

        rows.into_iter().map(item_revision_from_row).collect()
    }

    pub async fn rotation_status(
        &self,
        vault_id: VaultId,
    ) -> Result<RotationStatusRecord, StorageError> {
        let row = sqlx::query(
            r#"
            SELECT id, current_key_generation, needs_key_rotation
            FROM vaults
            WHERE id = $1
            "#,
        )
        .bind(vault_id)
        .fetch_optional(&self.pool)
        .await?
        .ok_or(StorageError::NotFound)?;

        Ok(RotationStatusRecord {
            vault_id: row.try_get("id")?,
            current_key_generation: row.try_get("current_key_generation")?,
            needs_key_rotation: row.try_get("needs_key_rotation")?,
        })
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
            sqlx::query_scalar("SELECT current_key_generation FROM vaults WHERE id = $1")
                .bind(input.vault_id)
                .fetch_optional(&mut *tx)
                .await?
                .ok_or(StorageError::NotFound)?;

        if current_generation != input.from_generation {
            return Err(StorageError::Conflict);
        }

        sqlx::query(
            r#"
            UPDATE vault_key_wrappings
            SET revoked_at = now(), rotated_at = now()
            WHERE vault_id = $1 AND revoked_at IS NULL
            "#,
        )
        .bind(input.vault_id)
        .execute(&mut *tx)
        .await?;

        for wrapping in input.new_wrappings {
            sqlx::query(
                r#"
                INSERT INTO vault_key_wrappings (id, vault_id, user_id, device_id, wrapping_type, envelope, key_generation)
                VALUES ($1, $2, $3, $4, $5, $6, $7)
                "#,
            )
            .bind(wrapping.id.unwrap_or_else(Uuid::new_v4))
            .bind(input.vault_id)
            .bind(wrapping.user_id)
            .bind(wrapping.device_id)
            .bind(wrapping.wrapping_type)
            .bind(wrapping.envelope)
            .bind(input.to_generation)
            .execute(&mut *tx)
            .await
            .map_err(map_sqlx_error)?;
        }

        for revision in input.reencrypted_revisions {
            let current_revision: i64 = sqlx::query_scalar(
                "SELECT current_revision FROM items WHERE id = $1 AND vault_id = $2",
            )
            .bind(revision.item_id)
            .bind(input.vault_id)
            .fetch_optional(&mut *tx)
            .await?
            .ok_or(StorageError::NotFound)?;

            if current_revision != revision.expected_revision {
                return Err(StorageError::Conflict);
            }

            let next_revision = current_revision + 1;
            let vault_revision: i64 = sqlx::query_scalar(
                r#"
                UPDATE vaults
                SET vault_revision = vault_revision + 1, updated_at = now()
                WHERE id = $1
                RETURNING vault_revision
                "#,
            )
            .bind(input.vault_id)
            .fetch_one(&mut *tx)
            .await?;

            sqlx::query("UPDATE items SET current_revision = $1, updated_at = now() WHERE id = $2")
                .bind(next_revision)
                .bind(revision.item_id)
                .execute(&mut *tx)
                .await?;

            sqlx::query(
                r#"
                INSERT INTO item_revisions (id, item_id, vault_id, revision, vault_revision, author_user_id, envelope, key_generation)
                VALUES ($1, $2, $3, $4, $5, $6, $7, $8)
                "#,
            )
            .bind(revision.revision_id.unwrap_or_else(Uuid::new_v4))
            .bind(revision.item_id)
            .bind(input.vault_id)
            .bind(next_revision)
            .bind(vault_revision)
            .bind(input.author_user_id)
            .bind(revision.envelope)
            .bind(input.to_generation)
            .execute(&mut *tx)
            .await
            .map_err(map_sqlx_error)?;
        }

        let row = sqlx::query(
            r#"
            UPDATE vaults
            SET current_key_generation = $2, needs_key_rotation = false, updated_at = now()
            WHERE id = $1
            RETURNING id, current_key_generation, needs_key_rotation
            "#,
        )
        .bind(input.vault_id)
        .bind(input.to_generation)
        .fetch_one(&mut *tx)
        .await?;

        tx.commit().await?;
        Ok(RotationStatusRecord {
            vault_id: row.try_get("id")?,
            current_key_generation: row.try_get("current_key_generation")?,
            needs_key_rotation: row.try_get("needs_key_rotation")?,
        })
    }

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

    pub async fn create_session(
        &self,
        input: CreateSession,
    ) -> Result<SessionRecord, StorageError> {
        let id = input.id.unwrap_or_else(Uuid::new_v4);
        let row = sqlx::query(
            r#"
            INSERT INTO sessions (id, user_id, device_id, token_hash, expires_at)
            VALUES ($1, $2, $3, $4, $5)
            RETURNING id, user_id, device_id, token_hash, created_at, expires_at, revoked_at
            "#,
        )
        .bind(id)
        .bind(input.user_id)
        .bind(input.device_id)
        .bind(input.token_hash)
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
            SELECT id, user_id, device_id, token_hash, created_at, expires_at, revoked_at
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
}

#[derive(Debug, Clone)]
pub struct CreateUser {
    pub id: Option<UserId>,
    pub email: String,
    pub display_name: Option<String>,
    pub public_key: String,
    pub encrypted_private_key: Value,
}

#[derive(Debug, Clone)]
pub struct UserRecord {
    pub id: UserId,
    pub email: String,
    pub display_name: Option<String>,
    pub public_key: String,
    pub encrypted_private_key: Value,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
    pub disabled_at: Option<DateTime<Utc>>,
}

#[derive(Debug, Clone)]
pub struct UpsertUserAuth {
    pub user_id: UserId,
    pub auth_method: String,
    pub auth_data: Value,
}

#[derive(Debug, Clone)]
pub struct UserAuthRecord {
    pub user_id: UserId,
    pub auth_method: String,
    pub auth_data: Value,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

#[derive(Debug, Clone)]
pub struct CreateDevice {
    pub id: Option<DeviceId>,
    pub user_id: UserId,
    pub name: String,
    pub public_key: Option<String>,
    pub fingerprint: String,
    pub trusted: bool,
}

#[derive(Debug, Clone)]
pub struct DeviceRecord {
    pub id: DeviceId,
    pub user_id: UserId,
    pub name: String,
    pub public_key: Option<String>,
    pub fingerprint: String,
    pub trusted: bool,
    pub created_at: DateTime<Utc>,
    pub last_seen_at: Option<DateTime<Utc>>,
    pub revoked_at: Option<DateTime<Utc>>,
}

#[derive(Debug, Clone)]
pub struct CreateVault {
    pub id: Option<VaultId>,
    pub org_id: Option<OrgId>,
    pub name: String,
    pub kind: VaultKind,
    pub created_by: Option<UserId>,
    pub crypto_policy: Value,
}

#[derive(Debug, Clone)]
pub struct VaultRecord {
    pub id: VaultId,
    pub org_id: Option<OrgId>,
    pub name: String,
    pub kind: VaultKind,
    pub vault_revision: RevisionId,
    pub current_key_generation: RevisionId,
    pub needs_key_rotation: bool,
    pub created_by: Option<UserId>,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
    pub deleted_at: Option<DateTime<Utc>>,
    pub crypto_policy: Value,
}

#[derive(Debug, Clone)]
pub struct CreateOrg {
    pub id: Option<OrgId>,
    pub name: String,
    pub created_by: Option<UserId>,
}

#[derive(Debug, Clone)]
pub struct OrgRecord {
    pub id: OrgId,
    pub name: String,
    pub created_by: Option<UserId>,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
    pub deleted_at: Option<DateTime<Utc>>,
}

#[derive(Debug, Clone)]
pub struct UpsertOrgMember {
    pub org_id: OrgId,
    pub user_id: UserId,
    pub role: OrgRole,
    pub state: MemberState,
}

#[derive(Debug, Clone)]
pub struct OrgMemberRecord {
    pub org_id: OrgId,
    pub user_id: UserId,
    pub role: OrgRole,
    pub state: MemberState,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

#[derive(Debug, Clone)]
pub struct UpsertVaultMember {
    pub vault_id: VaultId,
    pub user_id: UserId,
    pub role: VaultRole,
    pub state: MemberState,
}

#[derive(Debug, Clone)]
pub struct VaultMemberRecord {
    pub vault_id: VaultId,
    pub user_id: UserId,
    pub role: VaultRole,
    pub state: MemberState,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

#[derive(Debug, Clone)]
pub struct CreateVaultKeyWrapping {
    pub id: Option<Uuid>,
    pub vault_id: VaultId,
    pub user_id: UserId,
    pub device_id: Option<DeviceId>,
    pub wrapping_type: String,
    pub envelope: Value,
    pub key_generation: RevisionId,
}

#[derive(Debug, Clone)]
pub struct VaultKeyWrappingRecord {
    pub id: Uuid,
    pub vault_id: VaultId,
    pub user_id: UserId,
    pub device_id: Option<DeviceId>,
    pub wrapping_type: String,
    pub envelope: Value,
    pub key_generation: RevisionId,
    pub created_at: DateTime<Utc>,
    pub rotated_at: Option<DateTime<Utc>>,
    pub revoked_at: Option<DateTime<Utc>>,
}

#[derive(Debug, Clone)]
pub struct CreateEncryptedItem {
    pub item_id: Option<ItemId>,
    pub revision_id: Option<Uuid>,
    pub vault_id: VaultId,
    pub kind: ItemKind,
    pub author_user_id: Option<UserId>,
    pub envelope: Value,
}

#[derive(Debug, Clone)]
pub struct CreateItemRevision {
    pub revision_id: Option<Uuid>,
    pub item_id: ItemId,
    pub vault_id: VaultId,
    pub expected_revision: RevisionId,
    pub author_user_id: Option<UserId>,
    pub envelope: Value,
}

#[derive(Debug, Clone)]
pub struct ItemRevisionRecord {
    pub id: Uuid,
    pub item_id: ItemId,
    pub vault_id: VaultId,
    pub revision: RevisionId,
    pub vault_revision: RevisionId,
    pub key_generation: RevisionId,
    pub author_user_id: Option<UserId>,
    pub envelope: Value,
    pub created_at: DateTime<Utc>,
}

#[derive(Debug, Clone)]
pub struct RotationStatusRecord {
    pub vault_id: VaultId,
    pub current_key_generation: RevisionId,
    pub needs_key_rotation: bool,
}

#[derive(Debug, Clone)]
pub struct FinishVaultKeyRotation {
    pub vault_id: VaultId,
    pub author_user_id: Option<UserId>,
    pub from_generation: RevisionId,
    pub to_generation: RevisionId,
    pub new_wrappings: Vec<CreateVaultKeyWrapping>,
    pub reencrypted_revisions: Vec<RotationItemRevisionInput>,
}

#[derive(Debug, Clone)]
pub struct RotationItemRevisionInput {
    pub revision_id: Option<Uuid>,
    pub item_id: ItemId,
    pub expected_revision: RevisionId,
    pub envelope: Value,
}

#[derive(Debug, Clone)]
pub struct AppendAuditLog {
    pub id: Option<Uuid>,
    pub actor_user_id: Option<UserId>,
    pub vault_id: Option<VaultId>,
    pub action: String,
    pub target_type: Option<String>,
    pub target_id: Option<Uuid>,
    pub metadata: Value,
}

#[derive(Debug, Clone)]
pub struct AuditLogRecord {
    pub id: Uuid,
    pub actor_user_id: Option<UserId>,
    pub vault_id: Option<VaultId>,
    pub action: String,
    pub target_type: Option<String>,
    pub target_id: Option<Uuid>,
    pub metadata: Value,
    pub created_at: DateTime<Utc>,
}

#[derive(Debug, Clone)]
pub struct CreateSession {
    pub id: Option<Uuid>,
    pub user_id: UserId,
    pub device_id: Option<DeviceId>,
    pub token_hash: String,
    pub expires_at: DateTime<Utc>,
}

#[derive(Debug, Clone)]
pub struct SessionRecord {
    pub id: Uuid,
    pub user_id: UserId,
    pub device_id: Option<DeviceId>,
    pub token_hash: String,
    pub created_at: DateTime<Utc>,
    pub expires_at: DateTime<Utc>,
    pub revoked_at: Option<DateTime<Utc>>,
}

#[derive(Debug, thiserror::Error)]
pub enum StorageError {
    #[error("database error: {0}")]
    Database(#[from] sqlx::Error),
    #[error("record not found")]
    NotFound,
    #[error("record conflict")]
    Conflict,
    #[error("forbidden")]
    Forbidden,
    #[error("invalid database value for {field}: {value}")]
    InvalidDatabaseValue { field: &'static str, value: String },
}

fn map_sqlx_error(error: sqlx::Error) -> StorageError {
    if let sqlx::Error::Database(db_error) = &error
        && db_error.is_unique_violation()
    {
        return StorageError::Conflict;
    }
    StorageError::Database(error)
}

fn ensure_rows_affected(rows: u64) -> Result<(), StorageError> {
    if rows == 0 {
        Err(StorageError::NotFound)
    } else {
        Ok(())
    }
}

fn user_from_row(row: sqlx::postgres::PgRow) -> Result<UserRecord, StorageError> {
    Ok(UserRecord {
        id: row.try_get("id")?,
        email: row.try_get("email")?,
        display_name: row.try_get("display_name")?,
        public_key: row.try_get("public_key")?,
        encrypted_private_key: row.try_get("encrypted_private_key")?,
        created_at: row.try_get("created_at")?,
        updated_at: row.try_get("updated_at")?,
        disabled_at: row.try_get("disabled_at")?,
    })
}

fn user_auth_from_row(row: sqlx::postgres::PgRow) -> Result<UserAuthRecord, StorageError> {
    Ok(UserAuthRecord {
        user_id: row.try_get("user_id")?,
        auth_method: row.try_get("auth_method")?,
        auth_data: row.try_get("auth_data")?,
        created_at: row.try_get("created_at")?,
        updated_at: row.try_get("updated_at")?,
    })
}

fn device_from_row(row: sqlx::postgres::PgRow) -> Result<DeviceRecord, StorageError> {
    Ok(DeviceRecord {
        id: row.try_get("id")?,
        user_id: row.try_get("user_id")?,
        name: row.try_get("name")?,
        public_key: row.try_get("public_key")?,
        fingerprint: row.try_get("fingerprint")?,
        trusted: row.try_get("trusted")?,
        created_at: row.try_get("created_at")?,
        last_seen_at: row.try_get("last_seen_at")?,
        revoked_at: row.try_get("revoked_at")?,
    })
}

fn vault_from_row(row: sqlx::postgres::PgRow) -> Result<VaultRecord, StorageError> {
    let kind: String = row.try_get("kind")?;
    Ok(VaultRecord {
        id: row.try_get("id")?,
        org_id: row.try_get("org_id")?,
        name: row.try_get("name")?,
        kind: str_to_vault_kind(&kind)?,
        vault_revision: row.try_get("vault_revision")?,
        current_key_generation: row.try_get("current_key_generation")?,
        needs_key_rotation: row.try_get("needs_key_rotation")?,
        created_by: row.try_get("created_by")?,
        created_at: row.try_get("created_at")?,
        updated_at: row.try_get("updated_at")?,
        deleted_at: row.try_get("deleted_at")?,
        crypto_policy: row.try_get("crypto_policy")?,
    })
}

fn org_from_row(row: sqlx::postgres::PgRow) -> Result<OrgRecord, StorageError> {
    Ok(OrgRecord {
        id: row.try_get("id")?,
        name: row.try_get("name")?,
        created_by: row.try_get("created_by")?,
        created_at: row.try_get("created_at")?,
        updated_at: row.try_get("updated_at")?,
        deleted_at: row.try_get("deleted_at")?,
    })
}

fn org_member_from_row(row: sqlx::postgres::PgRow) -> Result<OrgMemberRecord, StorageError> {
    let role: String = row.try_get("role")?;
    let state: String = row.try_get("state")?;
    Ok(OrgMemberRecord {
        org_id: row.try_get("org_id")?,
        user_id: row.try_get("user_id")?,
        role: str_to_org_role(&role)?,
        state: str_to_member_state(&state)?,
        created_at: row.try_get("created_at")?,
        updated_at: row.try_get("updated_at")?,
    })
}

fn vault_member_from_row(row: sqlx::postgres::PgRow) -> Result<VaultMemberRecord, StorageError> {
    let role: String = row.try_get("role")?;
    let state: String = row.try_get("state")?;
    Ok(VaultMemberRecord {
        vault_id: row.try_get("vault_id")?,
        user_id: row.try_get("user_id")?,
        role: str_to_vault_role(&role)?,
        state: str_to_member_state(&state)?,
        created_at: row.try_get("created_at")?,
        updated_at: row.try_get("updated_at")?,
    })
}

fn vault_key_wrapping_from_row(
    row: sqlx::postgres::PgRow,
) -> Result<VaultKeyWrappingRecord, StorageError> {
    Ok(VaultKeyWrappingRecord {
        id: row.try_get("id")?,
        vault_id: row.try_get("vault_id")?,
        user_id: row.try_get("user_id")?,
        device_id: row.try_get("device_id")?,
        wrapping_type: row.try_get("wrapping_type")?,
        envelope: row.try_get("envelope")?,
        key_generation: row.try_get("key_generation")?,
        created_at: row.try_get("created_at")?,
        rotated_at: row.try_get("rotated_at")?,
        revoked_at: row.try_get("revoked_at")?,
    })
}

fn item_revision_from_row(row: sqlx::postgres::PgRow) -> Result<ItemRevisionRecord, StorageError> {
    Ok(ItemRevisionRecord {
        id: row.try_get("id")?,
        item_id: row.try_get("item_id")?,
        vault_id: row.try_get("vault_id")?,
        revision: row.try_get("revision")?,
        vault_revision: row.try_get("vault_revision")?,
        key_generation: row.try_get("key_generation")?,
        author_user_id: row.try_get("author_user_id")?,
        envelope: row.try_get("envelope")?,
        created_at: row.try_get("created_at")?,
    })
}

fn audit_log_from_row(row: sqlx::postgres::PgRow) -> Result<AuditLogRecord, StorageError> {
    Ok(AuditLogRecord {
        id: row.try_get("id")?,
        actor_user_id: row.try_get("actor_user_id")?,
        vault_id: row.try_get("vault_id")?,
        action: row.try_get("action")?,
        target_type: row.try_get("target_type")?,
        target_id: row.try_get("target_id")?,
        metadata: row.try_get("metadata")?,
        created_at: row.try_get("created_at")?,
    })
}

fn session_from_row(row: sqlx::postgres::PgRow) -> Result<SessionRecord, StorageError> {
    Ok(SessionRecord {
        id: row.try_get("id")?,
        user_id: row.try_get("user_id")?,
        device_id: row.try_get("device_id")?,
        token_hash: row.try_get("token_hash")?,
        created_at: row.try_get("created_at")?,
        expires_at: row.try_get("expires_at")?,
        revoked_at: row.try_get("revoked_at")?,
    })
}

fn vault_kind_to_str(kind: VaultKind) -> &'static str {
    match kind {
        VaultKind::Personal => "personal",
        VaultKind::Shared => "shared",
        VaultKind::Project => "project",
        VaultKind::Org => "org",
    }
}

fn org_role_to_str(role: OrgRole) -> &'static str {
    match role {
        OrgRole::Owner => "owner",
        OrgRole::Admin => "admin",
        OrgRole::Member => "member",
    }
}

fn str_to_org_role(value: &str) -> Result<OrgRole, StorageError> {
    match value {
        "owner" => Ok(OrgRole::Owner),
        "admin" => Ok(OrgRole::Admin),
        "member" => Ok(OrgRole::Member),
        value => Err(StorageError::InvalidDatabaseValue {
            field: "org_members.role",
            value: value.to_owned(),
        }),
    }
}

fn str_to_vault_kind(value: &str) -> Result<VaultKind, StorageError> {
    match value {
        "personal" => Ok(VaultKind::Personal),
        "shared" => Ok(VaultKind::Shared),
        "project" => Ok(VaultKind::Project),
        "org" => Ok(VaultKind::Org),
        value => Err(StorageError::InvalidDatabaseValue {
            field: "vault.kind",
            value: value.to_owned(),
        }),
    }
}

fn vault_role_to_str(role: VaultRole) -> &'static str {
    match role {
        VaultRole::Owner => "owner",
        VaultRole::Admin => "admin",
        VaultRole::Editor => "editor",
        VaultRole::Viewer => "viewer",
    }
}

fn str_to_vault_role(value: &str) -> Result<VaultRole, StorageError> {
    match value {
        "owner" => Ok(VaultRole::Owner),
        "admin" => Ok(VaultRole::Admin),
        "editor" => Ok(VaultRole::Editor),
        "viewer" => Ok(VaultRole::Viewer),
        value => Err(StorageError::InvalidDatabaseValue {
            field: "vault_members.role",
            value: value.to_owned(),
        }),
    }
}

fn member_state_to_str(state: MemberState) -> &'static str {
    match state {
        MemberState::Active => "active",
        MemberState::Invited => "invited",
        MemberState::Removed => "removed",
    }
}

fn str_to_member_state(value: &str) -> Result<MemberState, StorageError> {
    match value {
        "active" => Ok(MemberState::Active),
        "invited" => Ok(MemberState::Invited),
        "removed" => Ok(MemberState::Removed),
        value => Err(StorageError::InvalidDatabaseValue {
            field: "vault_members.state",
            value: value.to_owned(),
        }),
    }
}

fn item_kind_to_str(kind: &ItemKind) -> &'static str {
    match kind {
        ItemKind::Login => "login",
        ItemKind::SecureNote => "secure_note",
        ItemKind::SshKey => "ssh_key",
        ItemKind::ApiKey => "api_key",
        ItemKind::Token => "token",
        ItemKind::EnvVar => "env_var",
        ItemKind::EnvBundle => "env_bundle",
        ItemKind::CreditCard => "credit_card",
        ItemKind::Custom(_) => "custom",
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn enum_string_conversions_roundtrip() {
        assert_eq!(
            str_to_vault_kind(vault_kind_to_str(VaultKind::Shared)).unwrap(),
            VaultKind::Shared
        );
        assert_eq!(
            str_to_vault_role(vault_role_to_str(VaultRole::Editor)).unwrap(),
            VaultRole::Editor
        );
        assert_eq!(
            str_to_member_state(member_state_to_str(MemberState::Active)).unwrap(),
            MemberState::Active
        );
        assert_eq!(item_kind_to_str(&ItemKind::ApiKey), "api_key");
    }

    #[tokio::test]
    async fn postgres_smoke_migration_test_is_optional() {
        let Ok(database_url) = std::env::var("UMBRA_TEST_DATABASE_URL") else {
            return;
        };

        let storage = Storage::connect(&database_url).await.unwrap();
        umbra_migrations::run(storage.pool()).await.unwrap();

        let exists: bool = sqlx::query_scalar("SELECT to_regclass('public.users') IS NOT NULL")
            .fetch_one(storage.pool())
            .await
            .unwrap();

        assert!(exists);
    }
}
