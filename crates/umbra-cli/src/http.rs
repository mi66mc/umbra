use serde::{Serialize, de::DeserializeOwned};

use crate::config::CliConfig;
use crate::error::CliError;

#[derive(Clone)]
pub struct UmbraHttpClient {
    base_url: String,
    token: Option<String>,
    inner: reqwest::Client,
}

impl UmbraHttpClient {
    pub fn new(config: &CliConfig) -> Self {
        Self {
            base_url: config.server_url.trim_end_matches('/').to_owned(),
            token: config.session_token.clone(),
            inner: reqwest::Client::new(),
        }
    }

    pub async fn get<R>(&self, path: &str) -> Result<R, CliError>
    where
        R: DeserializeOwned,
    {
        let request = self.inner.get(format!("{}{}", self.base_url, path));
        self.send(request).await
    }

    pub async fn post<T, R>(&self, path: &str, body: &T) -> Result<R, CliError>
    where
        T: Serialize + ?Sized,
        R: DeserializeOwned,
    {
        let request = self
            .inner
            .post(format!("{}{}", self.base_url, path))
            .json(body);
        self.send(request).await
    }

    pub async fn put<T, R>(&self, path: &str, body: &T) -> Result<R, CliError>
    where
        T: Serialize + ?Sized,
        R: DeserializeOwned,
    {
        let request = self
            .inner
            .put(format!("{}{}", self.base_url, path))
            .json(body);
        self.send(request).await
    }

    async fn send<R>(&self, request: reqwest::RequestBuilder) -> Result<R, CliError>
    where
        R: DeserializeOwned,
    {
        let request = if let Some(token) = &self.token {
            request.bearer_auth(token)
        } else {
            request
        };

        let response = request.send().await?;
        let status = response.status();
        let body = response.text().await?;
        if !status.is_success() {
            return Err(CliError::ServerStatus { status, body });
        }

        Ok(serde_json::from_str(&body)?)
    }
}
