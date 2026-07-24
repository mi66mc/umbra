use std::{
    collections::HashMap,
    net::{IpAddr, SocketAddr},
    time::{Duration, Instant},
};

use axum::{
    extract::{ConnectInfo, Request, State},
    http::{HeaderMap, StatusCode},
    middleware::Next,
    response::{IntoResponse, Response},
};
use tokio::sync::Mutex;

use crate::{config::RateLimitSettings, state::AppState};

#[derive(Debug, Clone, Copy)]
pub(crate) enum LimitClass {
    Registration,
    Auth,
    Authenticated,
    Write,
}

#[derive(Default)]
pub(crate) struct RateLimiter {
    entries: Mutex<HashMap<String, Window>>,
}
struct Window {
    started: Instant,
    used: u32,
}

impl RateLimiter {
    pub(crate) async fn check(
        &self,
        key: String,
        class: LimitClass,
        settings: &RateLimitSettings,
    ) -> Result<(), u64> {
        let (limit, period) = match class {
            LimitClass::Registration => (settings.registration_per_hour, Duration::from_secs(3600)),
            LimitClass::Auth => (settings.auth_per_minute, Duration::from_secs(60)),
            LimitClass::Authenticated => {
                (settings.authenticated_per_minute, Duration::from_secs(60))
            }
            LimitClass::Write => (settings.write_per_minute, Duration::from_secs(60)),
        };
        let now = Instant::now();
        let mut entries = self.entries.lock().await;
        entries.retain(|_, value| now.duration_since(value.started) < Duration::from_secs(3600));
        let entry = entries.entry(format!("{key}:{class:?}")).or_insert(Window {
            started: now,
            used: 0,
        });
        if now.duration_since(entry.started) >= period {
            entry.started = now;
            entry.used = 0;
        }
        if entry.used >= limit {
            return Err((period.saturating_sub(now.duration_since(entry.started)))
                .as_secs()
                .max(1));
        }
        entry.used += 1;
        Ok(())
    }
}

pub(crate) async fn public_rate_limit(
    State(state): State<AppState>,
    request: Request,
    next: Next,
) -> Response {
    let class = match request.uri().path() {
        "/api/v1/auth/register/start" | "/api/v1/auth/register/finish" => {
            Some(LimitClass::Registration)
        }
        "/api/v1/auth/login/start" | "/api/v1/auth/login/finish" => Some(LimitClass::Auth),
        _ => None,
    };
    if let Some(class) = class
        && let Err(retry_after) = state
            .rate_limiter
            .check(
                client_key(request.extensions(), request.headers(), &state),
                class,
                &state.config.rate_limit,
            )
            .await
    {
        tracing::warn!(decision = "rate_limited", class = ?class, "request rejected");
        return too_many_requests(retry_after);
    }
    next.run(request).await
}

pub(crate) async fn check_authenticated(
    state: &AppState,
    device_id: Option<uuid::Uuid>,
    method: &axum::http::Method,
) -> Result<(), Response> {
    let class = if matches!(*method, axum::http::Method::GET | axum::http::Method::HEAD) {
        LimitClass::Authenticated
    } else {
        LimitClass::Write
    };
    let key = device_id
        .map(|id| format!("device:{id}"))
        .unwrap_or_else(|| "device:legacy".to_owned());
    state
        .rate_limiter
        .check(key, class, &state.config.rate_limit)
        .await
        .map_err(too_many_requests)
}

fn client_key(
    extensions: &axum::http::Extensions,
    headers: &HeaderMap,
    state: &AppState,
) -> String {
    let direct = extensions
        .get::<ConnectInfo<SocketAddr>>()
        .map(|value| value.0.ip());
    let trusted = direct.is_some_and(|ip| state.server_trusted_proxy(ip));
    if trusted
        && let Some(ip) = headers
            .get("x-forwarded-for")
            .and_then(|value| value.to_str().ok())
            .and_then(|value| value.split(',').next())
            .and_then(|value| value.trim().parse::<IpAddr>().ok())
    {
        return format!("ip:{ip}");
    }
    direct
        .map(|ip| format!("ip:{ip}"))
        .unwrap_or_else(|| "ip:unknown".to_owned())
}

fn too_many_requests(retry_after: u64) -> Response {
    (
        StatusCode::TOO_MANY_REQUESTS,
        [("retry-after", retry_after.to_string())],
        "rate limit exceeded",
    )
        .into_response()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn limits_are_scoped_to_their_client_key() {
        let limiter = RateLimiter::default();
        let settings = RateLimitSettings {
            registration_per_hour: 1,
            auth_per_minute: 1,
            authenticated_per_minute: 1,
            write_per_minute: 1,
        };
        assert!(
            limiter
                .check("ip:one".to_owned(), LimitClass::Auth, &settings)
                .await
                .is_ok()
        );
        assert!(
            limiter
                .check("ip:one".to_owned(), LimitClass::Auth, &settings)
                .await
                .is_err()
        );
        assert!(
            limiter
                .check("ip:two".to_owned(), LimitClass::Auth, &settings)
                .await
                .is_ok()
        );
    }
}
