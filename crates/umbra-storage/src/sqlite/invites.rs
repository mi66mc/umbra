use chrono::Utc;
use sqlx::Row;
use uuid::Uuid;

use crate::convert::{str_to_vault_role, vault_role_to_str};
use crate::error::map_sqlx_error;
use crate::models::*;
use crate::sqlite::SqliteStorage;
use crate::sqlite::convert::{optional_time, parse_time, parse_uuid, vault_member_from_row};
use crate::{StorageError, VaultMemberRecord};

impl SqliteStorage {
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
            VALUES (?1, ?2, ?3, lower(?4), ?5, 'pending', ?6, ?7, ?8)
            RETURNING id, vault_id, org_id, email, role, state, invited_by,
                      accepted_user_id, vault_key_wrapping, created_at, accepted_at, expires_at
            "#,
        )
        .bind(id.to_string())
        .bind(input.vault_id.to_string())
        .bind(input.org_id.map(|id| id.to_string()))
        .bind(input.email)
        .bind(vault_role_to_str(input.role))
        .bind(input.invited_by.map(|id| id.to_string()))
        .bind(input.vault_key_wrapping.to_string())
        .bind(input.expires_at.map(|time| time.to_rfc3339()))
        .fetch_one(&self.pool)
        .await
        .map_err(map_sqlx_error)?;

        vault_invite_from_row(row)
    }

    pub async fn list_pending_vault_invites_for_email(
        &self,
        email: &str,
    ) -> Result<Vec<PendingVaultInviteRecord>, StorageError> {
        let now = Utc::now().to_rfc3339();
        let rows = sqlx::query(
            r#"
            SELECT i.id, i.vault_id, v.name AS vault_name, i.org_id, i.email, i.role,
                   i.invited_by, i.vault_key_wrapping, i.expires_at
            FROM invites i
            INNER JOIN vaults v ON v.id = i.vault_id AND v.deleted_at IS NULL
            WHERE i.email = lower(?1)
              AND i.state = 'pending'
              AND (i.expires_at IS NULL OR i.expires_at > ?2)
            ORDER BY i.created_at ASC
            "#,
        )
        .bind(email)
        .bind(now)
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
        let now = Utc::now().to_rfc3339();

        let invite_row = sqlx::query(
            r#"
            UPDATE invites
            SET state = 'accepted',
                accepted_user_id = ?2,
                accepted_at = ?3
            WHERE id = ?1
              AND state = 'pending'
              AND email = (SELECT lower(email) FROM users WHERE id = ?2)
              AND (expires_at IS NULL OR expires_at > ?3)
            RETURNING id, vault_id, org_id, email, role, state, invited_by,
                      accepted_user_id, vault_key_wrapping, created_at, accepted_at, expires_at
            "#,
        )
        .bind(input.invite_id.to_string())
        .bind(input.user_id.to_string())
        .bind(&now)
        .fetch_optional(&mut *tx)
        .await?
        .ok_or(StorageError::NotFound)?;
        let invite = vault_invite_from_row(invite_row)?;
        let (wrapping_type, envelope, key_generation, device_id) =
            invite_device_wrapping(&invite.vault_key_wrapping, input.device_id)?;

        let member_row = sqlx::query(
            r#"
            INSERT INTO vault_members (vault_id, user_id, role, state)
            VALUES (?1, ?2, ?3, 'active')
            ON CONFLICT (vault_id, user_id) DO UPDATE SET
                role = excluded.role,
                state = 'active',
                updated_at = ?4
            RETURNING vault_id, user_id, role, state, created_at, updated_at
            "#,
        )
        .bind(invite.vault_id.to_string())
        .bind(input.user_id.to_string())
        .bind(vault_role_to_str(invite.role))
        .bind(&now)
        .fetch_one(&mut *tx)
        .await?;

        sqlx::query(
            r#"
            INSERT INTO vault_key_wrappings (
                id, vault_id, user_id, device_id, wrapping_type, envelope, key_generation
            )
            VALUES (
                ?1, ?2, ?3, ?4, ?5, ?6, ?7
            )
            "#,
        )
        .bind(Uuid::new_v4().to_string())
        .bind(invite.vault_id.to_string())
        .bind(input.user_id.to_string())
        .bind(device_id.map(|id| id.to_string()))
        .bind(wrapping_type)
        .bind(envelope.to_string())
        .bind(key_generation)
        .execute(&mut *tx)
        .await?;

        sqlx::query(
            "UPDATE vaults SET access_revision = access_revision + 1, updated_at = ?2 WHERE id = ?1",
        )
        .bind(invite.vault_id.to_string())
        .bind(&now)
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
            UPDATE invites
            SET state = 'rejected'
            WHERE id = ?1
              AND state = 'pending'
              AND email = (SELECT lower(email) FROM users WHERE id = ?2)
            RETURNING id, vault_id, org_id, email, role, state, invited_by,
                      accepted_user_id, vault_key_wrapping, created_at, accepted_at, expires_at
            "#,
        )
        .bind(invite_id.to_string())
        .bind(user_id.to_string())
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
        return Ok(("user_public_key".to_owned(), value.clone(), 1, device_id));
    };
    let device_id = device_id.ok_or(StorageError::NotFound)?;
    let entry = entries
        .iter()
        .find(|entry| {
            entry.get("device_id").and_then(|id| id.as_str()) == Some(&device_id.to_string())
        })
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

fn vault_invite_from_row(row: sqlx::sqlite::SqliteRow) -> Result<VaultInviteRecord, StorageError> {
    let role: String = row.try_get("role")?;
    let wrapping: String = row.try_get("vault_key_wrapping")?;
    Ok(VaultInviteRecord {
        id: parse_uuid(row.try_get::<String, _>("id")?)?,
        vault_id: parse_uuid(row.try_get::<String, _>("vault_id")?)?,
        org_id: row
            .try_get::<Option<String>, _>("org_id")?
            .map(parse_uuid)
            .transpose()?,
        email: row.try_get("email")?,
        role: str_to_vault_role(&role)?,
        state: row.try_get("state")?,
        invited_by: row
            .try_get::<Option<String>, _>("invited_by")?
            .map(parse_uuid)
            .transpose()?,
        accepted_user_id: row
            .try_get::<Option<String>, _>("accepted_user_id")?
            .map(parse_uuid)
            .transpose()?,
        vault_key_wrapping: invite_wrapping_json(&wrapping)?,
        created_at: parse_time(row.try_get::<String, _>("created_at")?)?,
        accepted_at: optional_time(row.try_get("accepted_at")?)?,
        expires_at: optional_time(row.try_get("expires_at")?)?,
    })
}

fn pending_vault_invite_from_row(
    row: sqlx::sqlite::SqliteRow,
) -> Result<PendingVaultInviteRecord, StorageError> {
    let role: String = row.try_get("role")?;
    let wrapping: String = row.try_get("vault_key_wrapping")?;
    Ok(PendingVaultInviteRecord {
        id: parse_uuid(row.try_get::<String, _>("id")?)?,
        vault_id: parse_uuid(row.try_get::<String, _>("vault_id")?)?,
        vault_name: row.try_get("vault_name")?,
        org_id: row
            .try_get::<Option<String>, _>("org_id")?
            .map(parse_uuid)
            .transpose()?,
        email: row.try_get("email")?,
        role: str_to_vault_role(&role)?,
        invited_by: row
            .try_get::<Option<String>, _>("invited_by")?
            .map(parse_uuid)
            .transpose()?,
        vault_key_wrapping: invite_wrapping_json(&wrapping)?,
        expires_at: optional_time(row.try_get("expires_at")?)?,
    })
}

fn invite_wrapping_json(value: &str) -> Result<serde_json::Value, StorageError> {
    serde_json::from_str(value).map_err(|_| StorageError::InvalidDatabaseValue {
        field: "invites.vault_key_wrapping",
        value: value.to_owned(),
    })
}
