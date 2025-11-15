use std::time::Duration;

use oauth2::{
    ClientId, ClientSecret, StandardRevocableToken, StandardTokenResponse,
    basic::{
        BasicClient, BasicErrorResponse, BasicRevocationErrorResponse,
        BasicTokenIntrospectionResponse, BasicTokenType,
    },
};
use oauth2::{EndpointNotSet, ExtraTokenFields};
use reqwest::Client as HttpClient;
use serde::{Deserialize, Serialize};
use thiserror::Error;
use tokio::{signal, task::JoinHandle, time};
use tokio_util::sync::CancellationToken;

mod device;
mod pkce;

use super::config::{
    DeviceFlowConfig, PkceFlowConfig, ProviderConfig, ProviderKind, ProviderSelection,
};

const DEFAULT_HTTP_TIMEOUT: Duration = Duration::from_secs(30);
const DEFAULT_DEVICE_POLL_TIMEOUT: Duration = Duration::from_secs(600);
const DEFAULT_PKCE_WAIT_TIMEOUT: Duration = Duration::from_secs(300);
const DEFAULT_LOOPBACK_LIFETIME: Duration = Duration::from_secs(300);

pub type FlowResult<T> = std::result::Result<T, AuthFlowError>;

#[derive(Clone, Debug)]
pub struct FlowController {
    cancellation: CancellationToken,
    timeouts: FlowTimeouts,
}

#[derive(Clone, Copy, Debug)]
pub struct FlowTimeouts {
    pub http: Duration,
    pub device_poll: Duration,
    pub pkce_wait: Duration,
    pub loopback_lifetime: Duration,
}

impl Default for FlowTimeouts {
    fn default() -> Self {
        Self {
            http: DEFAULT_HTTP_TIMEOUT,
            device_poll: DEFAULT_DEVICE_POLL_TIMEOUT,
            pkce_wait: DEFAULT_PKCE_WAIT_TIMEOUT,
            loopback_lifetime: DEFAULT_LOOPBACK_LIFETIME,
        }
    }
}

impl FlowController {
    pub fn new() -> Self {
        Self {
            cancellation: CancellationToken::new(),
            timeouts: FlowTimeouts::default(),
        }
    }

    pub fn with_timeouts(timeouts: FlowTimeouts) -> Self {
        Self {
            cancellation: CancellationToken::new(),
            timeouts,
        }
    }

    pub fn cancellation_token(&self) -> CancellationToken {
        self.cancellation.clone()
    }

    pub fn install_ctrlc_handler(&self) -> JoinHandle<()> {
        let token = self.cancellation_token();
        tokio::spawn(async move {
            if signal::ctrl_c().await.is_ok() {
                token.cancel();
            }
        })
    }

    pub fn http_timeout(&self) -> Duration {
        self.timeouts.http
    }

    pub fn device_poll_timeout(&self) -> Duration {
        self.timeouts.device_poll
    }

    pub fn pkce_wait_timeout(&self) -> Duration {
        self.timeouts.pkce_wait
    }

    pub fn loopback_lifetime(&self) -> Duration {
        self.timeouts.loopback_lifetime
    }

    pub async fn run_with_deadline<F, T>(
        &self,
        stage: &'static str,
        timeout: Duration,
        fut: F,
    ) -> FlowResult<T>
    where
        F: std::future::Future<Output = FlowResult<T>>,
    {
        tokio::select! {
            _ = self.cancellation.cancelled() => Err(AuthFlowError::Cancelled),
            result = time::timeout(timeout, fut) => match result {
                Ok(inner) => inner,
                Err(_) => Err(AuthFlowError::TimedOut { stage, after: timeout }),
            },
        }
    }
}

#[derive(Debug, Error)]
pub enum AuthFlowError {
    #[error("login cancelled")]
    Cancelled,
    #[error("login timed out during {stage} after {after:?}")]
    TimedOut {
        stage: &'static str,
        after: Duration,
    },
    #[error("authentication provider error: {0}")]
    Provider(String),
    #[error("network error: {0}")]
    Network(String),
    #[error("loopback listener error: {0}")]
    Loopback(String),
    #[error("invalid authentication configuration: {0}")]
    InvalidConfig(String),
}

impl AuthFlowError {
    pub fn provider(message: impl Into<String>) -> Self {
        AuthFlowError::Provider(message.into())
    }

    pub fn network(message: impl Into<String>) -> Self {
        AuthFlowError::Network(message.into())
    }

    pub fn loopback(message: impl Into<String>) -> Self {
        AuthFlowError::Loopback(message.into())
    }
}

#[derive(Clone, Debug)]
pub struct DeviceFlowPrompt {
    pub verification_uri: String,
    pub verification_uri_complete: Option<String>,
    pub user_code: String,
    pub expires_in: Duration,
}

#[derive(Clone, Debug)]
pub struct PkceFlowPrompt {
    pub authorization_url: String,
    pub redirect_uri: String,
}

#[derive(Clone, Debug)]
pub struct ExternalToken {
    pub secret: String,
    pub nonce: Option<String>,
}

impl ExternalToken {
    fn new(secret: String) -> Self {
        Self {
            secret,
            nonce: None,
        }
    }

    fn with_nonce(secret: String, nonce: String) -> Self {
        Self {
            secret,
            nonce: Some(nonce),
        }
    }
}

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub(super) struct OidcTokenFields {
    #[serde(default)]
    id_token: Option<String>,
}

impl ExtraTokenFields for OidcTokenFields {}

type OidcTokenResponse = StandardTokenResponse<OidcTokenFields, BasicTokenType>;

type OidcClient<
    HasAuthUrl = EndpointNotSet,
    HasDeviceAuthUrl = EndpointNotSet,
    HasIntrospectionUrl = EndpointNotSet,
    HasRevocationUrl = EndpointNotSet,
    HasTokenUrl = EndpointNotSet,
> = oauth2::Client<
    BasicErrorResponse,
    OidcTokenResponse,
    BasicTokenIntrospectionResponse,
    StandardRevocableToken,
    BasicRevocationErrorResponse,
    HasAuthUrl,
    HasDeviceAuthUrl,
    HasIntrospectionUrl,
    HasRevocationUrl,
    HasTokenUrl,
>;

pub async fn login_device_flow<F>(
    selection: &ProviderSelection,
    notify: &F,
    controller: &FlowController,
) -> FlowResult<ExternalToken>
where
    F: Fn(&DeviceFlowPrompt),
{
    let flow = selection.device_flow().ok_or_else(|| {
        AuthFlowError::InvalidConfig(format!(
            "provider '{}' does not support device-code flow",
            selection.provider_name()
        ))
    })?;

    device::login_device_flow(selection, flow, notify, controller).await
}

pub async fn login_pkce<F>(
    selection: &ProviderSelection,
    notify: &F,
    controller: &FlowController,
) -> FlowResult<ExternalToken>
where
    F: Fn(&PkceFlowPrompt),
{
    let flow = selection.pkce_flow().ok_or_else(|| {
        AuthFlowError::InvalidConfig(format!(
            "provider '{}' does not support auth-code pkce flow",
            selection.provider_name()
        ))
    })?;

    pkce::login_pkce(selection, flow, notify, controller).await
}

pub(super) fn normalize_scopes(provider: &ProviderConfig) -> Vec<String> {
    let mut scopes = provider.scopes.clone();

    if matches!(provider.kind, ProviderKind::Oidc) && !scopes.iter().any(|scope| scope == "openid")
    {
        scopes.insert(0, "openid".to_string());
    }

    scopes
}

pub(super) fn build_http_client() -> FlowResult<HttpClient> {
    HttpClient::builder()
        .build()
        .map_err(|err| AuthFlowError::network(format!("failed to build http client: {err}")))
}

pub(super) fn build_oidc_client(provider: &ProviderConfig) -> FlowResult<OidcClient> {
    let client_id = provider.client_id.as_ref().ok_or_else(|| {
        AuthFlowError::InvalidConfig(format!("provider '{}' missing client_id", provider.name))
    })?;

    let mut client = OidcClient::new(ClientId::new(client_id.clone()));

    if let Some(secret) = &provider.client_secret {
        client = client.set_client_secret(ClientSecret::new(secret.clone()));
    }

    Ok(client)
}

pub(super) fn build_oauth_client(provider: &ProviderConfig) -> FlowResult<BasicClient> {
    let client_id = provider.client_id.as_ref().ok_or_else(|| {
        AuthFlowError::InvalidConfig(format!("provider '{}' missing client_id", provider.name))
    })?;

    let mut client = BasicClient::new(ClientId::new(client_id.clone()));

    if let Some(secret) = &provider.client_secret {
        client = client.set_client_secret(ClientSecret::new(secret.clone()));
    }

    Ok(client)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::auth::config::{
        DeviceFlowConfig, FlowVariant, PkceFlowConfig, ProviderConfig, ProviderSelection,
    };
    use crate::settings::AuthFlowPreference;
    use auth_test_support::{JsonResponse, MockOauthFlowServer, OAuthFlowConfig};
    use reqwest::{Client, StatusCode};
    use serde_json::json;
    use std::sync::{Arc, Mutex};
    use std::time::Duration;
    use tokio::{
        sync::Notify,
        time::{sleep, timeout},
    };

    fn oidc_provider(base: &str) -> ProviderConfig {
        let mut provider = base_provider(base, ProviderKind::Oidc, "oidc");
        provider.flows = vec![FlowVariant::DeviceCode(DeviceFlowConfig {
            token_endpoint: format!("{base}/token"),
            device_authorization_endpoint: format!("{base}/device"),
        })];
        provider
    }

    fn oidc_pkce_provider(base: &str) -> ProviderConfig {
        let mut provider = base_provider(base, ProviderKind::Oidc, "oidc");
        provider.flows = vec![FlowVariant::AuthCodePkce(PkceFlowConfig {
            token_endpoint: format!("{base}/token"),
            authorization_endpoint: format!("{base}/authorize"),
        })];
        provider
    }

    fn oauth_provider(base: &str) -> ProviderConfig {
        let mut provider = base_provider(base, ProviderKind::Oauth2, "oauth");
        provider.scopes = vec!["repo".into()];
        provider.flows = vec![
            FlowVariant::DeviceCode(DeviceFlowConfig {
                token_endpoint: format!("{base}/token"),
                device_authorization_endpoint: format!("{base}/device"),
            }),
            FlowVariant::AuthCodePkce(PkceFlowConfig {
                token_endpoint: format!("{base}/token"),
                authorization_endpoint: format!("{base}/authorize"),
            }),
        ];
        provider
    }

    fn base_provider(base: &str, kind: ProviderKind, name: &str) -> ProviderConfig {
        ProviderConfig {
            name: name.into(),
            display_name: None,
            kind,
            flows: Vec::new(),
            scopes: vec!["profile".into()],
            issuer: Some(format!("{base}/issuer")),
            userinfo_endpoint: None,
            jwks_uri: None,
            client_id: Some("client".into()),
            client_secret: None,
        }
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn device_flow_oauth_yields_access_token() {
        let server = MockOauthFlowServer::start(OAuthFlowConfig::device_and_token(
            JsonResponse::ok(json!({
                "device_code": "device-code",
                "user_code": "ABCD-1234",
                "verification_uri": "https://example.com/device",
                "expires_in": 1800,
                "interval": 1
            })),
            JsonResponse::ok(json!({
                "access_token": "access-token",
                "token_type": "Bearer",
                "expires_in": 3600
            })),
        ))
        .await;

        let provider = oauth_provider(server.uri());
        let flow = provider
            .flows
            .iter()
            .find(|variant| matches!(variant.preference(), AuthFlowPreference::DeviceCode))
            .expect("device flow present")
            .clone();
        let selection = ProviderSelection::new_for_test(provider, flow, None);

        let prompt_slot: Arc<Mutex<Option<DeviceFlowPrompt>>> = Arc::new(Mutex::new(None));
        let notify = {
            let slot = prompt_slot.clone();
            move |prompt: &DeviceFlowPrompt| {
                *slot.lock().unwrap() = Some(prompt.clone());
            }
        };

        let controller = FlowController::new();
        let token = login_device_flow(&selection, &notify, &controller)
            .await
            .expect("device flow succeeds");

        assert_eq!(token.secret, "access-token");
        assert!(token.nonce.is_none());

        let prompt = prompt_slot
            .lock()
            .unwrap()
            .clone()
            .expect("prompt recorded");
        assert_eq!(prompt.user_code, "ABCD-1234");
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn device_flow_oidc_yields_id_token() {
        let server = MockOauthFlowServer::start(OAuthFlowConfig::device_and_token(
            JsonResponse::ok(json!({
                "device_code": "device-code",
                "user_code": "ABCD-1234",
                "verification_uri": "https://example.com/device",
                "expires_in": 1800,
                "interval": 1
            })),
            JsonResponse::ok(json!({
                "access_token": "ignored",
                "id_token": "header.payload.signature",
                "token_type": "Bearer",
                "expires_in": 3600
            })),
        ))
        .await;

        let provider = oidc_provider(server.uri());
        let flow = provider
            .flows
            .first()
            .expect("device flow configured")
            .clone();
        let selection = ProviderSelection::new_for_test(provider, flow, None);

        let controller = FlowController::new();
        let token = login_device_flow(&selection, &|_| {}, &controller)
            .await
            .expect("device flow succeeds");

        assert_eq!(token.secret, "header.payload.signature");
        assert!(token.nonce.is_none());
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn device_flow_reports_provider_errors() {
        let server = MockOauthFlowServer::start(OAuthFlowConfig {
            device_response: Some(JsonResponse::ok(json!({
                "device_code": "device-code",
                "user_code": "ABCD-1234",
                "verification_uri": "https://example.com/device",
                "expires_in": 1800,
                "interval": 1
            }))),
            token_responses: vec![JsonResponse::with_status(
                StatusCode::BAD_REQUEST,
                json!({ "error": "access_denied" }),
            )],
        })
        .await;

        let provider = oauth_provider(server.uri());
        let flow = provider
            .flows
            .iter()
            .find(|variant| matches!(variant.preference(), AuthFlowPreference::DeviceCode))
            .expect("device flow present")
            .clone();
        let selection = ProviderSelection::new_for_test(provider, flow, None);
        let controller = FlowController::new();

        let error = login_device_flow(&selection, &|_| {}, &controller)
            .await
            .expect_err("device flow should surface provider error");

        assert!(matches!(error, AuthFlowError::Provider(_)));
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn pkce_flow_oauth_yields_access_token() {
        let server =
            MockOauthFlowServer::start(OAuthFlowConfig::token_only(JsonResponse::ok(json!({
                "access_token": "access-token",
                "token_type": "Bearer",
                "expires_in": 3600
            }))))
            .await;

        let provider = oauth_provider(server.uri());
        let flow = provider
            .flows
            .iter()
            .find(|variant| matches!(variant.preference(), AuthFlowPreference::AuthCodePkce))
            .expect("pkce flow configured")
            .clone();
        let selection = ProviderSelection::new_for_test(provider, flow, None);

        let prompt_slot: Arc<Mutex<Option<PkceFlowPrompt>>> = Arc::new(Mutex::new(None));
        let signal = Arc::new(Notify::new());

        let notify = {
            let prompt_slot = prompt_slot.clone();
            let signal = signal.clone();
            move |prompt: &PkceFlowPrompt| {
                *prompt_slot.lock().unwrap() = Some(prompt.clone());
                signal.notify_one();
            }
        };

        let controller = FlowController::new();
        let login_task = tokio::spawn({
            let selection = selection.clone();
            let controller = controller.clone();
            async move { login_pkce(&selection, &notify, &controller).await }
        });

        timeout(Duration::from_secs(2), signal.notified())
            .await
            .expect("pkce prompt not emitted in time");
        let prompt = prompt_slot
            .lock()
            .unwrap()
            .clone()
            .expect("prompt should be captured");
        let state = query_value(&prompt.authorization_url, "state");
        let redirect = prompt.redirect_uri.clone();

        let redirect_task = tokio::spawn(async move {
            let url = format!("{redirect}?code=test-code&state={state}");
            Client::new()
                .get(url)
                .send()
                .await
                .expect("loopback callback request");
        });

        let token = login_task
            .await
            .expect("pkce task panicked")
            .expect("pkce login should succeed");
        redirect_task.await.expect("redirect task panicked");

        assert_eq!(token.secret, "access-token");
        assert!(token.nonce.is_none(), "oauth pkce does not use nonce");
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn pkce_flow_oidc_includes_nonce_parameter() {
        let server =
            MockOauthFlowServer::start(OAuthFlowConfig::token_only(JsonResponse::ok(json!({
                "access_token": "ignored",
                "id_token": "header.payload.signature",
                "token_type": "Bearer",
                "expires_in": 3600
            }))))
            .await;

        let provider = oidc_pkce_provider(server.uri());
        let flow = provider
            .flows
            .first()
            .expect("pkce flow configured")
            .clone();
        let selection = ProviderSelection::new_for_test(provider, flow, None);

        let prompt_slot: Arc<Mutex<Option<PkceFlowPrompt>>> = Arc::new(Mutex::new(None));
        let signal = Arc::new(Notify::new());

        let notify = {
            let prompt_slot = prompt_slot.clone();
            let signal = signal.clone();
            move |prompt: &PkceFlowPrompt| {
                *prompt_slot.lock().unwrap() = Some(prompt.clone());
                signal.notify_one();
            }
        };

        let controller = FlowController::new();
        let login_task = tokio::spawn({
            let selection = selection.clone();
            let controller = controller.clone();
            async move { login_pkce(&selection, &notify, &controller).await }
        });

        timeout(Duration::from_secs(2), signal.notified())
            .await
            .expect("pkce prompt not emitted in time");
        let prompt = prompt_slot
            .lock()
            .unwrap()
            .clone()
            .expect("prompt should be captured");
        let nonce = query_value(&prompt.authorization_url, "nonce");
        assert!(!nonce.is_empty(), "nonce must be present in pkce flow");

        let state = query_value(&prompt.authorization_url, "state");
        let redirect = prompt.redirect_uri.clone();

        let redirect_task = tokio::spawn(async move {
            let url = format!("{redirect}?code=test-code&state={state}");
            Client::new()
                .get(url)
                .send()
                .await
                .expect("loopback callback request");
        });

        let token = login_task
            .await
            .expect("pkce task panicked")
            .expect("pkce login should succeed");
        redirect_task.await.expect("redirect task panicked");

        assert_eq!(token.secret, "header.payload.signature");
        assert_eq!(
            token.nonce.as_deref(),
            Some(nonce.as_str()),
            "nonce should round-trip"
        );
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn pkce_flow_times_out_without_callback() {
        let server =
            MockOauthFlowServer::start(OAuthFlowConfig::token_only(JsonResponse::ok(json!({
                "access_token": "access-token",
                "token_type": "Bearer",
                "expires_in": 3600
            }))))
            .await;

        let provider = oauth_provider(server.uri());
        let flow = provider
            .flows
            .iter()
            .find(|variant| matches!(variant.preference(), AuthFlowPreference::AuthCodePkce))
            .expect("pkce flow configured")
            .clone();
        let selection = ProviderSelection::new_for_test(provider, flow, None);

        let controller = FlowController::with_timeouts(FlowTimeouts {
            http: Duration::from_secs(5),
            device_poll: Duration::from_secs(5),
            pkce_wait: Duration::from_millis(200),
            loopback_lifetime: Duration::from_millis(200),
        });

        let error = login_pkce(&selection, &|_| {}, &controller)
            .await
            .expect_err("pkce login should time out");

        assert!(matches!(
            error,
            AuthFlowError::TimedOut {
                stage: "loopback callback",
                ..
            }
        ));
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn pkce_flow_respects_cancellation() {
        let server =
            MockOauthFlowServer::start(OAuthFlowConfig::token_only(JsonResponse::ok(json!({
                "access_token": "access-token",
                "token_type": "Bearer",
                "expires_in": 3600
            }))))
            .await;

        let provider = oauth_provider(server.uri());
        let flow = provider
            .flows
            .iter()
            .find(|variant| matches!(variant.preference(), AuthFlowPreference::AuthCodePkce))
            .expect("pkce flow configured")
            .clone();
        let selection = ProviderSelection::new_for_test(provider, flow, None);

        let controller = FlowController::with_timeouts(FlowTimeouts {
            http: Duration::from_secs(5),
            device_poll: Duration::from_secs(5),
            pkce_wait: Duration::from_secs(30),
            loopback_lifetime: Duration::from_secs(30),
        });
        let cancel_token = controller.cancellation_token();

        let login_task = tokio::spawn({
            let selection = selection.clone();
            let controller = controller.clone();
            async move { login_pkce(&selection, &|_| {}, &controller).await }
        });

        sleep(Duration::from_millis(250)).await;
        cancel_token.cancel();

        let error = login_task
            .await
            .expect("pkce task runs")
            .expect_err("cancellation should fail the flow");

        assert!(matches!(error, AuthFlowError::Cancelled));
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn pkce_flow_reports_provider_errors() {
        let server = MockOauthFlowServer::start(OAuthFlowConfig::token_only(
            JsonResponse::with_status(StatusCode::BAD_REQUEST, json!({ "error": "invalid_grant" })),
        ))
        .await;

        let provider = oauth_provider(server.uri());
        let flow = provider
            .flows
            .iter()
            .find(|variant| matches!(variant.preference(), AuthFlowPreference::AuthCodePkce))
            .expect("pkce flow configured")
            .clone();
        let selection = ProviderSelection::new_for_test(provider, flow, None);

        let controller = FlowController::new();
        let prompt_slot: Arc<Mutex<Option<PkceFlowPrompt>>> = Arc::new(Mutex::new(None));
        let signal = Arc::new(Notify::new());

        let notify = {
            let slot = prompt_slot.clone();
            let signal = signal.clone();
            move |prompt: &PkceFlowPrompt| {
                *slot.lock().unwrap() = Some(prompt.clone());
                signal.notify_one();
            }
        };

        let login_task = tokio::spawn({
            let selection = selection.clone();
            let controller = controller.clone();
            async move { login_pkce(&selection, &notify, &controller).await }
        });

        timeout(Duration::from_secs(2), signal.notified())
            .await
            .expect("pkce prompt not emitted in time");
        let prompt = prompt_slot
            .lock()
            .unwrap()
            .clone()
            .expect("prompt recorded");
        let state = query_value(&prompt.authorization_url, "state");
        let redirect = prompt.redirect_uri.clone();

        let redirect_task = tokio::spawn(async move {
            let url = format!("{redirect}?code=test-code&state={state}");
            Client::new()
                .get(url)
                .send()
                .await
                .expect("loopback callback request");
        });

        let error = login_task
            .await
            .expect("pkce task finished")
            .expect_err("pkce flow should surface provider error");
        redirect_task.await.expect("redirect task panicked");

        assert!(matches!(error, AuthFlowError::Provider(_)));
    }

    fn query_value(url: &str, key: &str) -> String {
        reqwest::Url::parse(url)
            .expect("valid url")
            .query_pairs()
            .find_map(|(k, v)| (k == key).then(|| v.into_owned()))
            .expect("query key present")
    }
}
