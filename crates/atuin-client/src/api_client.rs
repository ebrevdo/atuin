use std::collections::HashMap;
use std::env;
use std::time::Duration;

use eyre::{Result, bail, eyre};
use reqwest::{
    Method, RequestBuilder, Response, StatusCode, Url,
    header::{AUTHORIZATION, HeaderValue, USER_AGENT},
};
use thiserror::Error;

use atuin_common::{
    api::{ATUIN_CARGO_VERSION, ATUIN_HEADER_VERSION, ATUIN_VERSION},
    record::{EncryptedData, HostId, Record, RecordIdx},
};
use atuin_common::{
    api::{
        AddHistoryRequest, AuthProvidersResponse, ChangePasswordRequest, CountResponse,
        DeleteHistoryRequest, ErrorResponse, LoginRequest, LoginResponse, MeResponse,
        RegisterResponse, SendVerificationResponse, StatusResponse, SyncHistoryResponse,
        VerificationTokenRequest, VerificationTokenResponse,
    },
    record::RecordStatus,
};

use semver::Version;
use time::OffsetDateTime;
use time::format_description::well_known::Rfc3339;

use crate::{history::History, sync::hash_str, utils::get_host_user};

static APP_USER_AGENT: &str = concat!("atuin/", env!("CARGO_PKG_VERSION"),);

pub struct Client<'a> {
    sync_addr: &'a str,
    client: reqwest::Client,
    auth_header: HeaderValue,
    version_header: HeaderValue,
}

fn make_url(address: &str, path: &str) -> Result<Url> {
    // `join()` expects a trailing `/` in order to join paths
    // e.g. it treats `http://host:port/subdir` as a file called `subdir`
    let mut base = address.trim().to_string();
    if !base.ends_with('/') {
        base.push('/');
    }

    // passing a path with a leading `/` will cause `join()` to replace the entire URL path
    let path = path.strip_prefix('/').unwrap_or(path);

    let base = Url::parse(&base).map_err(|_| eyre!("invalid address"))?;
    let url = base.join(path).map_err(|_| eyre!("invalid address"))?;

    Ok(url)
}

pub async fn register(
    address: &str,
    username: &str,
    email: &str,
    password: &str,
) -> Result<RegisterResponse> {
    let mut map = HashMap::new();
    map.insert("username", username);
    map.insert("email", email);
    map.insert("password", password);

    let url = make_url(address, &format!("/user/{username}"))?;
    let resp = reqwest::get(url).await?;

    if resp.status().is_success() {
        bail!("username already in use");
    }

    let url = make_url(address, "/register")?;
    let client = reqwest::Client::new();
    let resp = client
        .post(url)
        .header(USER_AGENT, APP_USER_AGENT)
        .header(ATUIN_HEADER_VERSION, ATUIN_CARGO_VERSION)
        .json(&map)
        .send()
        .await?;
    let resp = handle_resp_error(resp).await?;

    if !ensure_version(&resp)? {
        bail!("could not register user due to version mismatch");
    }

    let session = resp.json::<RegisterResponse>().await?;
    Ok(session)
}

pub async fn login(address: &str, req: LoginRequest) -> Result<LoginResponse> {
    let url = make_url(address, "/login")?;
    let client = reqwest::Client::new();

    let resp = client
        .post(url)
        .header(USER_AGENT, APP_USER_AGENT)
        .json(&req)
        .send()
        .await?;
    let resp = handle_resp_error(resp).await?;

    if !ensure_version(&resp)? {
        bail!("Could not login due to version mismatch");
    }

    let session = resp.json::<LoginResponse>().await?;
    Ok(session)
}

pub async fn auth_providers(address: &str) -> Result<Option<AuthProvidersResponse>> {
    let url = make_url(address, "/auth/providers")?;
    let client = reqwest::Client::new();

    let resp = client
        .get(url)
        .header(USER_AGENT, APP_USER_AGENT)
        .header(ATUIN_HEADER_VERSION, ATUIN_CARGO_VERSION)
        .send()
        .await?;
    if resp.status() == StatusCode::NOT_FOUND {
        return Ok(None);
    }

    let resp = handle_resp_error(resp).await?;

    if !ensure_version(&resp)? {
        bail!("could not fetch auth providers due to version mismatch");
    }

    Ok(Some(resp.json::<AuthProvidersResponse>().await?))
}

#[cfg(feature = "check-update")]
pub async fn latest_version() -> Result<Version> {
    use atuin_common::api::IndexResponse;

    let url = "https://api.atuin.sh";
    let client = reqwest::Client::new();

    let resp = client
        .get(url)
        .header(USER_AGENT, APP_USER_AGENT)
        .send()
        .await?;
    let resp = handle_resp_error(resp).await?;

    let index = resp.json::<IndexResponse>().await?;
    let version = Version::parse(index.version.as_str())?;

    Ok(version)
}

pub fn ensure_version(response: &Response) -> Result<bool> {
    let version = response.headers().get(ATUIN_HEADER_VERSION);

    let version = if let Some(version) = version {
        match version.to_str() {
            Ok(v) => Version::parse(v),
            Err(e) => bail!("failed to parse server version: {:?}", e),
        }
    } else {
        bail!("Server not reporting its version: it is either too old or unhealthy");
    }?;

    // If the client is newer than the server
    if version.major < ATUIN_VERSION.major {
        println!(
            "Atuin version mismatch! In order to successfully sync, the server needs to run a newer version of Atuin"
        );
        println!("Client: {ATUIN_CARGO_VERSION}");
        println!("Server: {version}");

        return Ok(false);
    }

    Ok(true)
}

#[derive(Debug, Error, PartialEq, Eq)]
enum ApiClientError {
    #[error("Service unavailable: check https://status.atuin.sh (or get in touch with your host)")]
    ServiceUnavailable,
    #[error("Rate limited; please wait before doing that again")]
    RateLimited,
    #[error("authentication failed: {0}")]
    Unauthorized(String),
    #[error("permission denied: {0}")]
    Forbidden(String),
    #[error("Invalid request to the service: {status} - {message}.")]
    InvalidRequest { status: StatusCode, message: String },
    #[error(
        "There was an error with the atuin sync service, server error {status}: {message}. If the problem persists, contact the host"
    )]
    ServerError { status: StatusCode, message: String },
    #[error("Unexpected response from the atuin sync service ({status}): {message}")]
    Unexpected { status: StatusCode, message: String },
}

async fn handle_resp_error(resp: Response) -> Result<Response, ApiClientError> {
    let status = resp.status();

    if status == StatusCode::SERVICE_UNAVAILABLE {
        return Err(ApiClientError::ServiceUnavailable);
    }

    if status == StatusCode::TOO_MANY_REQUESTS {
        return Err(ApiClientError::RateLimited);
    }

    if status.is_success() {
        return Ok(resp);
    }

    let reason = match resp.json::<ErrorResponse>().await {
        Ok(error) => Some(error.reason.into_owned()),
        Err(err) => {
            debug!("failed to parse error response body: {err:?}");
            None
        }
    };

    Err(map_status_to_error(status, reason))
}

fn map_status_to_error(status: StatusCode, reason: Option<String>) -> ApiClientError {
    let message = reason
        .and_then(normalize_reason)
        .unwrap_or_else(|| default_error_message(status));

    match status {
        StatusCode::UNAUTHORIZED => ApiClientError::Unauthorized(message),
        StatusCode::FORBIDDEN => ApiClientError::Forbidden(message),
        _ if status.is_client_error() => ApiClientError::InvalidRequest { status, message },
        _ if status.is_server_error() => ApiClientError::ServerError { status, message },
        _ => ApiClientError::Unexpected { status, message },
    }
}

fn normalize_reason(reason: String) -> Option<String> {
    let trimmed = reason.trim().to_string();
    if trimmed.is_empty() {
        None
    } else {
        Some(trimmed)
    }
}

fn default_error_message(status: StatusCode) -> String {
    match status {
        StatusCode::UNAUTHORIZED => {
            "session invalid or expired; run 'atuin login' and try again".to_string()
        }
        StatusCode::FORBIDDEN => "this account is not permitted to perform that action".to_string(),
        _ if status.is_client_error() => {
            format!("the server rejected the request (status {status})")
        }
        _ if status.is_server_error() => {
            format!("the server failed to process the request (status {status})")
        }
        _ => format!("received unexpected status {status} from the server"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn unauthorized_prefers_server_reason() {
        let error = map_status_to_error(StatusCode::UNAUTHORIZED, Some("session expired".into()));
        assert_eq!(
            error,
            ApiClientError::Unauthorized("session expired".into())
        );
    }

    #[test]
    fn forbidden_falls_back_to_default_message() {
        let error = map_status_to_error(StatusCode::FORBIDDEN, None);
        assert!(
            matches!(error, ApiClientError::Forbidden(message) if message.contains("not permitted"))
        );
    }

    #[test]
    fn client_error_maps_status_and_reason() {
        let error = map_status_to_error(StatusCode::BAD_REQUEST, Some("invalid".into()));
        match error {
            ApiClientError::InvalidRequest { status, message } => {
                assert_eq!(status, StatusCode::BAD_REQUEST);
                assert_eq!(message, "invalid");
            }
            other => panic!("unexpected error variant: {other:?}"),
        }
    }
}

impl<'a> Client<'a> {
    pub fn new(
        sync_addr: &'a str,
        session_token: &str,
        connect_timeout: u64,
        timeout: u64,
    ) -> Result<Self> {
        let auth_header = HeaderValue::from_str(&format!("Token {session_token}"))?;
        let version_header = HeaderValue::from_static(ATUIN_CARGO_VERSION);

        Ok(Client {
            sync_addr,
            client: reqwest::Client::builder()
                .user_agent(APP_USER_AGENT)
                .connect_timeout(Duration::new(connect_timeout, 0))
                .timeout(Duration::new(timeout, 0))
                .build()?,
            auth_header,
            version_header,
        })
    }

    fn url(&self, path: &str) -> Result<Url> {
        make_url(self.sync_addr, path)
    }

    fn authed(&self, builder: RequestBuilder) -> RequestBuilder {
        builder
            .header(AUTHORIZATION, self.auth_header.clone())
            .header(ATUIN_HEADER_VERSION, self.version_header.clone())
    }

    fn request(&self, method: Method, path: &str) -> Result<RequestBuilder> {
        let url = self.url(path)?;
        Ok(self.authed(self.client.request(method, url)))
    }

    pub async fn count(&self) -> Result<i64> {
        let resp = self.request(Method::GET, "/sync/count")?.send().await?;
        let resp = handle_resp_error(resp).await?;

        if !ensure_version(&resp)? {
            bail!("could not sync due to version mismatch");
        }

        if resp.status() != StatusCode::OK {
            bail!("failed to get count (are you logged in?)");
        }

        let count = resp.json::<CountResponse>().await?;

        Ok(count.count)
    }

    pub async fn status(&self) -> Result<StatusResponse> {
        let resp = self.request(Method::GET, "/sync/status")?.send().await?;
        let resp = handle_resp_error(resp).await?;

        if !ensure_version(&resp)? {
            bail!("could not sync due to version mismatch");
        }

        let status = resp.json::<StatusResponse>().await?;

        Ok(status)
    }

    pub async fn me(&self) -> Result<MeResponse> {
        let resp = self.request(Method::GET, "/api/v0/me")?.send().await?;
        let resp = handle_resp_error(resp).await?;

        let status = resp.json::<MeResponse>().await?;

        Ok(status)
    }

    pub async fn get_history(
        &self,
        sync_ts: OffsetDateTime,
        history_ts: OffsetDateTime,
        host: Option<String>,
    ) -> Result<SyncHistoryResponse> {
        let host = host.unwrap_or_else(|| hash_str(&get_host_user()));

        let resp = self
            .request(
                Method::GET,
                &format!(
                    "/sync/history?sync_ts={}&history_ts={}&host={}",
                    urlencoding::encode(sync_ts.format(&Rfc3339)?.as_str()),
                    urlencoding::encode(history_ts.format(&Rfc3339)?.as_str()),
                    host,
                ),
            )?
            .send()
            .await?;
        let resp = handle_resp_error(resp).await?;

        let history = resp.json::<SyncHistoryResponse>().await?;
        Ok(history)
    }

    pub async fn post_history(&self, history: &[AddHistoryRequest]) -> Result<()> {
        let resp = self
            .request(Method::POST, "/history")?
            .json(history)
            .send()
            .await?;
        handle_resp_error(resp).await?;

        Ok(())
    }

    pub async fn delete_history(&self, h: History) -> Result<()> {
        let resp = self
            .request(Method::DELETE, "/history")?
            .json(&DeleteHistoryRequest {
                client_id: h.id.to_string(),
            })
            .send()
            .await?;

        handle_resp_error(resp).await?;

        Ok(())
    }

    pub async fn delete_store(&self) -> Result<()> {
        let resp = self
            .request(Method::DELETE, "/api/v0/store")?
            .send()
            .await?;

        handle_resp_error(resp).await?;

        Ok(())
    }

    pub async fn post_records(&self, records: &[Record<EncryptedData>]) -> Result<()> {
        let url = self.url("/api/v0/record")?;
        debug!("uploading {} records to {url}", records.len());

        let resp = self
            .authed(self.client.post(url))
            .json(records)
            .send()
            .await?;
        handle_resp_error(resp).await?;

        Ok(())
    }

    pub async fn next_records(
        &self,
        host: HostId,
        tag: String,
        start: RecordIdx,
        count: u64,
    ) -> Result<Vec<Record<EncryptedData>>> {
        debug!("fetching record/s from host {}/{}/{}", host.0, tag, start);

        let resp = self
            .request(
                Method::GET,
                &format!(
                    "/api/v0/record/next?host={}&tag={}&count={}&start={}",
                    host.0, tag, count, start
                ),
            )?
            .send()
            .await?;
        let resp = handle_resp_error(resp).await?;

        let records = resp.json::<Vec<Record<EncryptedData>>>().await?;

        Ok(records)
    }

    pub async fn record_status(&self) -> Result<RecordStatus> {
        let resp = self.request(Method::GET, "/api/v0/record")?.send().await?;
        let resp = handle_resp_error(resp).await?;

        if !ensure_version(&resp)? {
            bail!("could not sync records due to version mismatch");
        }

        let index = resp.json().await?;

        debug!("got remote index {index:?}");

        Ok(index)
    }

    pub async fn delete(&self) -> Result<()> {
        let resp = self.request(Method::DELETE, "/account")?.send().await?;
        handle_resp_error(resp).await?;

        Ok(())
    }

    pub async fn change_password(
        &self,
        current_password: String,
        new_password: String,
    ) -> Result<()> {
        let resp = self
            .request(Method::PATCH, "/account/password")?
            .json(&ChangePasswordRequest {
                current_password,
                new_password,
            })
            .send()
            .await?;

        handle_resp_error(resp).await?;

        Ok(())
    }

    // Either request a verification email if token is null, or validate a token
    pub async fn verify(&self, token: Option<String>) -> Result<(bool, bool)> {
        // could dedupe this a bit, but it's simple at the moment
        let (email_sent, verified) = if let Some(token) = token {
            let resp = self
                .request(Method::POST, "/api/v0/account/verify")?
                .json(&VerificationTokenRequest { token })
                .send()
                .await?;
            let resp = handle_resp_error(resp).await?;
            let resp = resp.json::<VerificationTokenResponse>().await?;

            (false, resp.verified)
        } else {
            let resp = self
                .request(Method::POST, "/api/v0/account/send-verification")?
                .send()
                .await?;
            let resp = handle_resp_error(resp).await?;
            let resp = resp.json::<SendVerificationResponse>().await?;

            (resp.email_sent, resp.verified)
        };

        Ok((email_sent, verified))
    }
}
