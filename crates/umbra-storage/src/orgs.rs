use umbra_core::*;
use uuid::Uuid;

use crate::convert::*;
use crate::error::map_sqlx_error;
use crate::models::*;
use crate::{Storage, StorageError};

impl Storage {
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
}
