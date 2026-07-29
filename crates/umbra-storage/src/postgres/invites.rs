use chrono::{DateTime, Utc};
use sqlx::Row;
use uuid::Uuid;

use crate::convert::{str_to_vault_role, vault_member_from_row, vault_role_to_str};
use crate::error::map_sqlx_error;
use crate::models::*;
use crate::{PostgresStorage, StorageError};

impl PostgresStorage {
    pub async fn create_vault_invite(
        &self,
        input: CreateVaultInvite,
    ) -> Result<VaultInviteRecord, StorageError> {
        let id = input.id.unwrap_or_else(Uuid::new_v4);
        let row = sqlx::query(
            r#"
            INSERT INTO invites (
                id, vault_id, org_id, email, role, state, invited_by,
                vault_key_wrapping, expires_at
            )
            VALUES ($1, $2, $3, lower($4), $5, 'pending', $6, $7, $8)
            RETURNING id, vault_id, org_id, email, role, state, invited_by,
                      accepted_user_id, vault_key_wrapping, created_at, accepted_at, expires_at
            "#,
        )
        .bind(id)
        .bind(input.vault_id)
        .bind(input.org_id)
        .bind(input.email)
        .bind(vault_role_to_str(input.role))
        .bind(input.invited_by)
        .bind(input.vault_key_wrapping)
        .bind(input.expires_at)
        .fetch_one(&self.pool)
        .await
        .map_err(map_sqlx_error)?;

        vault_invite_from_row(row)
    }

    pub async fn list_pending_vault_invites_for_email(
        &self,
        email: &str,
    ) -> Result<Vec<PendingVaultInviteRecord>, StorageError> {
        let rows = sqlx::query(
            r#"
            SELECT i.id, i.vault_id, v.name AS vault_name, i.org_id, i.email, i.role,
                   i.invited_by, i.vault_key_wrapping, i.expires_at
            FROM invites i
            INNER JOIN vaults v ON v.id = i.vault_id AND v.deleted_at IS NULL
            WHERE i.email = lower($1)
              AND i.state = 'pending'
              AND (i.expires_at IS NULL OR i.expires_at > now())
            ORDER BY i.created_at ASC
            "#,
        )
        .bind(email)
        .fetch_all(&self.pool)
        .await?;

        rows.into_iter()
            .map(pending_vault_invite_from_row)
            .collect()
    }

    pub async fn accept_vault_invite(
        &self,
        input: AcceptVaultInvite,
    ) -> Result<VaultMemberRecord, StorageError> {
        let mut tx = self.pool.begin().await?;

        let invite_row = sqlx::query(
            r#"
            UPDATE invites i
            SET state = 'accepted',
                accepted_user_id = $2,
                accepted_at = now()
            FROM users u
            WHERE i.id = $1
              AND u.id = $2
              AND lower(u.email) = i.email
              AND i.state = 'pending'
              AND (i.expires_at IS NULL OR i.expires_at > now())
            RETURNING i.id, i.vault_id, i.org_id, i.email, i.role, i.state, i.invited_by,
                      i.accepted_user_id, i.vault_key_wrapping, i.created_at, i.accepted_at, i.expires_at
            "#,
        )
        .bind(input.invite_id)
        .bind(input.user_id)
        .fetch_optional(&mut *tx)
        .await?
        .ok_or(StorageError::NotFound)?;
        let invite = vault_invite_from_row(invite_row)?;
        let (wrapping_type, envelope, key_generation, device_id) =
            invite_device_wrapping(&invite.vault_key_wrapping, input.device_id)?;

        let member_row = sqlx::query(
            r#"
            INSERT INTO vault_members (vault_id, user_id, role, state)
            VALUES ($1, $2, $3, 'active')
            ON CONFLICT (vault_id, user_id) DO UPDATE SET
                role = excluded.role,
                state = 'active',
                updated_at = now()
            RETURNING vault_id, user_id, role, state, created_at, updated_at
            "#,
        )
        .bind(invite.vault_id)
        .bind(input.user_id)
        .bind(vault_role_to_str(invite.role))
        .fetch_one(&mut *tx)
        .await?;

        sqlx::query(
            r#"
            INSERT INTO vault_key_wrappings (
                id, vault_id, user_id, device_id, wrapping_type, envelope, key_generation
            )
            VALUES (
                $1, $2, $3, $4, $5, $6, $7
            )
            "#,
        )
        .bind(Uuid::new_v4())
        .bind(invite.vault_id)
        .bind(input.user_id)
        .bind(device_id)
        .bind(wrapping_type)
        .bind(envelope)
        .bind(key_generation)
        .execute(&mut *tx)
        .await?;

        sqlx::query(
            "UPDATE vaults SET access_revision = access_revision + 1, updated_at = now() WHERE id = $1",
        )
        .bind(invite.vault_id)
        .execute(&mut *tx)
        .await?;

        tx.commit().await?;
        vault_member_from_row(member_row)
    }

    pub async fn reject_vault_invite(
        &self,
        invite_id: Uuid,
        user_id: Uuid,
    ) -> Result<VaultInviteRecord, StorageError> {
        let row = sqlx::query(
            r#"
            UPDATE invites i
            SET state = 'rejected'
            FROM users u
            WHERE i.id = $1
              AND u.id = $2
              AND lower(u.email) = i.email
              AND i.state = 'pending'
            RETURNING i.id, i.vault_id, i.org_id, i.email, i.role, i.state, i.invited_by,
                      i.accepted_user_id, i.vault_key_wrapping, i.created_at, i.accepted_at, i.expires_at
            "#,
        )
        .bind(invite_id)
        .bind(user_id)
        .fetch_optional(&self.pool)
        .await?
        .ok_or(StorageError::NotFound)?;

        vault_invite_from_row(row)
    }
}

fn invite_device_wrapping(
    value: &serde_json::Value,
    device_id: Option<Uuid>,
) -> Result<(String, serde_json::Value, i64, Option<Uuid>), StorageError> {
    let Some(entries) = value.get("device_wrappings").and_then(|v| v.as_array()) else {
        // User-scoped invite envelopes cannot be safely assigned to a single
        // trusted device. Leave the legacy invite pending for explicit
        // re-issuance instead of silently recreating a user-key wrapping.
        return Err(StorageError::NotFound);
    };
    let device_id = device_id.ok_or(StorageError::NotFound)?;
    let expected = device_id.to_string();
    let entry = entries
        .iter()
        .find(|entry| entry.get("device_id").and_then(|id| id.as_str()) == Some(expected.as_str()))
        .ok_or(StorageError::NotFound)?;
    Ok((
        entry
            .get("wrapping_type")
            .and_then(|v| v.as_str())
            .ok_or(StorageError::NotFound)?
            .to_owned(),
        entry
            .get("envelope")
            .cloned()
            .ok_or(StorageError::NotFound)?,
        entry
            .get("key_generation")
            .and_then(|v| v.as_i64())
            .ok_or(StorageError::NotFound)?,
        Some(device_id),
    ))
}

fn vault_invite_from_row(row: sqlx::postgres::PgRow) -> Result<VaultInviteRecord, StorageError> {
    let role: String = row.try_get("role")?;
    Ok(VaultInviteRecord {
        id: row.try_get("id")?,
        vault_id: row.try_get("vault_id")?,
        org_id: row.try_get("org_id")?,
        email: row.try_get("email")?,
        role: str_to_vault_role(&role)?,
        state: row.try_get("state")?,
        invited_by: row.try_get("invited_by")?,
        accepted_user_id: row.try_get("accepted_user_id")?,
        vault_key_wrapping: row.try_get("vault_key_wrapping")?,
        created_at: row.try_get("created_at")?,
        accepted_at: row.try_get("accepted_at")?,
        expires_at: row.try_get::<Option<DateTime<Utc>>, _>("expires_at")?,
    })
}

fn pending_vault_invite_from_row(
    row: sqlx::postgres::PgRow,
) -> Result<PendingVaultInviteRecord, StorageError> {
    let role: String = row.try_get("role")?;
    Ok(PendingVaultInviteRecord {
        id: row.try_get("id")?,
        vault_id: row.try_get("vault_id")?,
        vault_name: row.try_get("vault_name")?,
        org_id: row.try_get("org_id")?,
        email: row.try_get("email")?,
        role: str_to_vault_role(&role)?,
        invited_by: row.try_get("invited_by")?,
        vault_key_wrapping: row.try_get("vault_key_wrapping")?,
        expires_at: row.try_get("expires_at")?,
    })
}
