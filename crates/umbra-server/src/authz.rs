use axum::http::HeaderMap;
use umbra_core::{MemberState, UserId, VaultRole};
use uuid::Uuid;

use crate::error::ServerError;
use crate::state::AppState;
use crate::util::token_hash;

pub(crate) async fn authenticate(
    state: &AppState,
    headers: &HeaderMap,
) -> Result<UserId, ServerError> {
    let token = headers
        .get("authorization")
        .and_then(|value| value.to_str().ok())
        .and_then(|value| value.strip_prefix("Bearer "))
        .ok_or(ServerError::Unauthorized)?;
    let session = state
        .storage
        .find_active_session_by_hash(&token_hash(token))
        .await?;
    Ok(session.user_id)
}

pub(crate) async fn ensure_org_manager(
    state: &AppState,
    org_id: Uuid,
    user_id: Uuid,
) -> Result<(), ServerError> {
    let member = state.storage.find_org_member(org_id, user_id).await?;
    if member.state == MemberState::Active && member.role.can_manage_members() {
        Ok(())
    } else {
        Err(ServerError::Forbidden)
    }
}

pub(crate) async fn ensure_org_vault_creator(
    state: &AppState,
    org_id: Uuid,
    user_id: Uuid,
) -> Result<(), ServerError> {
    let member = state.storage.find_org_member(org_id, user_id).await?;
    if member.state == MemberState::Active && member.role.can_create_vaults() {
        Ok(())
    } else {
        Err(ServerError::Forbidden)
    }
}

pub(crate) async fn ensure_vault_member(
    state: &AppState,
    vault_id: Uuid,
    user_id: Uuid,
) -> Result<(), ServerError> {
    if state
        .storage
        .has_active_vault_membership(vault_id, user_id)
        .await?
    {
        Ok(())
    } else {
        Err(ServerError::Forbidden)
    }
}

pub(crate) async fn ensure_vault_admin(
    state: &AppState,
    vault_id: Uuid,
    user_id: Uuid,
) -> Result<(), ServerError> {
    let members = state.storage.list_vault_members(vault_id).await?;
    let Some(member) = members
        .into_iter()
        .find(|member| member.user_id == user_id && member.state == MemberState::Active)
    else {
        return Err(ServerError::Forbidden);
    };
    if matches!(member.role, VaultRole::Owner | VaultRole::Admin) {
        Ok(())
    } else {
        Err(ServerError::Forbidden)
    }
}

pub(crate) async fn ensure_vault_writer(
    state: &AppState,
    vault_id: Uuid,
    user_id: Uuid,
) -> Result<(), ServerError> {
    let members = state.storage.list_vault_members(vault_id).await?;
    let Some(member) = members
        .into_iter()
        .find(|member| member.user_id == user_id && member.state == MemberState::Active)
    else {
        return Err(ServerError::Forbidden);
    };

    if member.role.can_write_items() {
        Ok(())
    } else {
        Err(ServerError::Forbidden)
    }
}
