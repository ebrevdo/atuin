use std::{
    collections::HashMap,
    fmt,
    path::PathBuf,
    sync::Arc,
    time::{Duration, Instant},
};

use atuin_common::api::{
    AUTH_FLOW_AUTH_CODE_PKCE, AUTH_FLOW_DEVICE_CODE, AuthProviderPublic, AuthProvidersResponse,
};
use fs_err::create_dir_all;
use openidconnect::{IssuerUrl, core::CoreJsonWebKeySet};
use reqwest::Client as OidcHttpClient;
use tokio::{
    sync::RwLock,
    time::{self, MissedTickBehavior},
};
use tokio_util::sync::CancellationToken;
use tracing::warn;

use crate::settings::{AuthFlow, AuthProvider, AuthProviderKind, AuthSettings};

use super::{
    IdentityError, cache,
    error::{AuthRuntimeError, MetadataError},
    oauth, oidc,
};

const METADATA_TTL: Duration = Duration::from_secs(60 * 60);
const DEFAULT_METADATA_REFRESH_INTERVAL: Duration = Duration::from_secs(15 * 60);
const DEFAULT_METADATA_REFRESH_MARGIN: Duration = Duration::from_secs(5 * 60);

#[derive(Clone)]
pub struct AuthRuntime {
    settings: AuthSettings,
    metadata_http: OidcHttpClient,
    http: reqwest::Client,
    providers: Arc<HashMap<String, ProviderHandle>>,
    metadata_refresh_interval: Duration,
    metadata_refresh_margin: Duration,
}

#[derive(Clone)]
pub struct ExternalIdentity {
    pub subject: String,
    pub username: Option<String>,
    pub email: Option<String>,
}

struct ProviderHandle {
    config: AuthProvider,
    cache: RwLock<Option<ResolvedProvider>>,
    snapshot_path: PathBuf,
    snapshot_max_bytes: usize,
}

#[derive(Clone)]
pub(super) struct ResolvedProvider {
    pub(super) issuer: Option<IssuerUrl>,
    pub(super) authorization_endpoint: Option<String>,
    pub(super) token_endpoint: Option<String>,
    pub(super) device_authorization_endpoint: Option<String>,
    pub(super) userinfo_endpoint: Option<String>,
    pub(super) jwks_uri: Option<String>,
    pub(super) jwks: Option<CoreJsonWebKeySet>,
    pub(super) fetched_at: Instant,
}

impl ResolvedProvider {
    pub(super) fn new() -> Self {
        Self {
            issuer: None,
            authorization_endpoint: None,
            token_endpoint: None,
            device_authorization_endpoint: None,
            userinfo_endpoint: None,
            jwks_uri: None,
            jwks: None,
            fetched_at: Instant::now(),
        }
    }

    pub(super) fn is_fresh(&self) -> bool {
        Instant::now().duration_since(self.fetched_at) < METADATA_TTL
    }

    pub(super) fn expires_within(&self, margin: Duration) -> bool {
        if margin >= METADATA_TTL {
            return true;
        }

        let elapsed = Instant::now().duration_since(self.fetched_at);
        let threshold = METADATA_TTL.saturating_sub(margin);

        elapsed >= threshold
    }
}

impl AuthRuntime {
    pub fn from_settings(settings: &AuthSettings) -> Result<Self, AuthRuntimeError> {
        Self::with_cache_dir(
            settings,
            None,
            DEFAULT_METADATA_REFRESH_INTERVAL,
            DEFAULT_METADATA_REFRESH_MARGIN,
        )
    }

    #[cfg(test)]
    pub fn from_settings_with_cache_dir<P: Into<PathBuf>>(
        settings: &AuthSettings,
        cache_dir: P,
    ) -> Result<Self, AuthRuntimeError> {
        Self::with_cache_dir(
            settings,
            Some(cache_dir.into()),
            DEFAULT_METADATA_REFRESH_INTERVAL,
            DEFAULT_METADATA_REFRESH_MARGIN,
        )
    }

    fn with_cache_dir(
        settings: &AuthSettings,
        cache_dir_override: Option<PathBuf>,
        refresh_interval: Duration,
        refresh_margin: Duration,
    ) -> Result<Self, AuthRuntimeError> {
        let metadata_http = OidcHttpClient::builder()
            .user_agent(format!(
                "atuin-server/{version}",
                version = env!("CARGO_PKG_VERSION")
            ))
            .build()
            .map_err(AuthRuntimeError::MetadataHttpClient)?;

        let http = reqwest::Client::builder()
            .user_agent(format!(
                "atuin-server/{version}",
                version = env!("CARGO_PKG_VERSION")
            ))
            .build()
            .map_err(AuthRuntimeError::HttpClient)?;

        let cache_dir = cache_dir_override
            .or_else(|| settings.cache_dir.clone())
            .unwrap_or_else(cache::default_cache_dir);
        let max_snapshot_bytes = settings
            .cache_max_bytes
            .map(|value| {
                let clamped = value.max(1).min(usize::MAX as u64);
                clamped as usize
            })
            .unwrap_or(cache::DEFAULT_MAX_SNAPSHOT_BYTES);
        if !settings.providers.is_empty() {
            create_dir_all(&cache_dir).map_err(|error| AuthRuntimeError::CacheDir {
                path: cache_dir.clone(),
                source: error,
            })?;
        }

        let mut providers = HashMap::new();

        for provider in settings.providers.iter().cloned() {
            let name = provider.name.clone();
            let snapshot_path = cache::provider_cache_path(&cache_dir, &name);
            let initial_cache = if matches!(provider.kind, AuthProviderKind::Oidc) {
                cache::load_provider_snapshot(&name, &snapshot_path, max_snapshot_bytes)
            } else {
                None
            };

            providers.insert(
                name,
                ProviderHandle::new(provider, snapshot_path, initial_cache, max_snapshot_bytes),
            );
        }

        Ok(Self {
            settings: settings.clone(),
            metadata_http,
            http,
            providers: Arc::new(providers),
            metadata_refresh_interval: refresh_interval,
            metadata_refresh_margin: refresh_margin,
        })
    }

    pub fn allow_password(&self) -> bool {
        self.settings.allow_password
    }

    pub fn spawn_metadata_refresh_task(&self, shutdown: CancellationToken) {
        if self.providers.is_empty() {
            return;
        }

        let providers = self.providers.clone();
        let metadata_client = self.metadata_http.clone();
        let refresh_interval = self.metadata_refresh_interval;
        let refresh_margin = self.metadata_refresh_margin;

        tokio::spawn(async move {
            let mut ticker = time::interval(refresh_interval);
            ticker.set_missed_tick_behavior(MissedTickBehavior::Delay);

            loop {
                tokio::select! {
                    _ = shutdown.cancelled() => break,
                    _ = ticker.tick() => {
                        for (name, handle) in providers.iter() {
                            if let Err(error) = handle
                                .refresh_metadata_if_needed(&metadata_client, refresh_margin)
                                .await
                            {
                                warn!(
                                    target = "atuin::auth",
                                    provider = name.as_str(),
                                    ?error,
                                    "failed to refresh provider metadata"
                                );
                            }
                        }
                    }
                }
            }
        });
    }

    pub async fn providers_response(&self) -> AuthProvidersResponse {
        let mut providers = Vec::with_capacity(self.providers.len());

        for handle in self.providers.values() {
            let resolved = handle.resolved(&self.metadata_http).await.ok();

            providers.push(handle.client_view(resolved.as_ref()));
        }

        AuthProvidersResponse {
            allow_password: self.settings.allow_password,
            default_provider: self.settings.default_provider.clone(),
            providers,
        }
    }

    pub async fn verify_identity(
        &self,
        provider: &str,
        token: &str,
        nonce: Option<&str>,
    ) -> Result<ExternalIdentity, IdentityError> {
        let handle = self
            .providers
            .get(provider)
            .ok_or_else(|| IdentityError::UnknownProvider(provider.to_string()))?;

        match handle.config.kind {
            AuthProviderKind::Oidc => self.verify_oidc(handle, token, nonce).await,
            AuthProviderKind::Oauth2 => self.verify_oauth(handle, token).await,
        }
    }

    async fn verify_oidc(
        &self,
        handle: &ProviderHandle,
        token: &str,
        nonce: Option<&str>,
    ) -> Result<ExternalIdentity, IdentityError> {
        let resolved = handle
            .resolved(&self.metadata_http)
            .await
            .map_err(|error| IdentityError::Metadata {
                provider: handle.config.name.clone(),
                source: error,
            })?;

        oidc::verify_identity(&handle.config, &resolved, token, nonce)
    }

    async fn verify_oauth(
        &self,
        handle: &ProviderHandle,
        token: &str,
    ) -> Result<ExternalIdentity, IdentityError> {
        oauth::verify_identity(&handle.config, &self.http, token).await
    }
}

#[cfg(test)]
impl AuthRuntime {
    pub async fn refresh_metadata_now(&self) -> Result<(), MetadataError> {
        for handle in self.providers.values() {
            handle
                .refresh_metadata_if_needed(&self.metadata_http, self.metadata_refresh_margin)
                .await?;
        }

        Ok(())
    }
}

impl ProviderHandle {
    fn new(
        config: AuthProvider,
        snapshot_path: PathBuf,
        initial_cache: Option<ResolvedProvider>,
        snapshot_max_bytes: usize,
    ) -> Self {
        Self {
            config,
            cache: RwLock::new(initial_cache),
            snapshot_path,
            snapshot_max_bytes,
        }
    }

    fn preferred_scopes(&self) -> Vec<String> {
        self.config.scopes.iter().cloned().collect::<Vec<_>>()
    }

    async fn refresh_metadata_if_needed(
        &self,
        client: &OidcHttpClient,
        margin: Duration,
    ) -> Result<(), MetadataError> {
        if !matches!(self.config.kind, AuthProviderKind::Oidc) {
            return Ok(());
        }

        let should_refresh = {
            let cache = self.cache.read().await;
            match cache.as_ref() {
                Some(cache) => cache.expires_within(margin),
                None => true,
            }
        };

        if !should_refresh {
            return Ok(());
        }

        let refreshed = oidc::resolve_metadata(&self.config, client).await?;

        {
            let mut cache = self.cache.write().await;
            *cache = Some(refreshed.clone());
        }

        self.persist_snapshot(&refreshed);

        Ok(())
    }

    async fn resolved(&self, client: &OidcHttpClient) -> Result<ResolvedProvider, MetadataError> {
        {
            let cache = self.cache.read().await;
            if let Some(cache) = cache.as_ref() {
                if cache.is_fresh() || matches!(self.config.kind, AuthProviderKind::Oauth2) {
                    return Ok(cache.clone());
                }
            }
        }

        let mut write_guard = self.cache.write().await;
        if let Some(cache) = write_guard.as_ref() {
            if cache.is_fresh() || matches!(self.config.kind, AuthProviderKind::Oauth2) {
                return Ok(cache.clone());
            }
        }

        let refreshed = match self.config.kind {
            AuthProviderKind::Oidc => oidc::resolve_metadata(&self.config, client).await?,
            AuthProviderKind::Oauth2 => oauth::resolve_metadata(&self.config),
        };

        *write_guard = Some(refreshed.clone());
        drop(write_guard);

        self.persist_snapshot(&refreshed);

        Ok(refreshed)
    }

    fn persist_snapshot(&self, resolved: &ResolvedProvider) {
        if !matches!(self.config.kind, AuthProviderKind::Oidc) {
            return;
        }

        if let Err(error) =
            cache::persist_provider_snapshot(&self.snapshot_path, resolved, self.snapshot_max_bytes)
        {
            warn!(
                target = "atuin::auth",
                provider = self.config.name.as_str(),
                ?error,
                "failed to persist provider snapshot"
            );
        }
    }

    fn client_view(&self, resolved: Option<&ResolvedProvider>) -> AuthProviderPublic {
        AuthProviderPublic {
            name: self.config.name.clone(),
            display_name: self.config.display_name.clone(),
            kind: match self.config.kind {
                AuthProviderKind::Oidc => "oidc".to_string(),
                AuthProviderKind::Oauth2 => "oauth2".to_string(),
            },
            flows: self
                .config
                .flows
                .iter()
                .map(flow_name)
                .map(str::to_string)
                .collect(),
            scopes: self.preferred_scopes(),
            issuer: option_display_to_string(&self.config.issuer).or_else(|| {
                resolved.and_then(|r| r.issuer.as_ref().map(|issuer| issuer.to_string()))
            }),
            authorization_endpoint: option_display_to_string(&self.config.authorization_endpoint)
                .or_else(|| resolved.and_then(|r| r.authorization_endpoint.clone())),
            token_endpoint: option_display_to_string(&self.config.token_endpoint)
                .or_else(|| resolved.and_then(|r| r.token_endpoint.clone())),
            device_authorization_endpoint: option_display_to_string(
                &self.config.device_authorization_endpoint,
            )
            .or_else(|| resolved.and_then(|r| r.device_authorization_endpoint.clone())),
            userinfo_endpoint: option_display_to_string(&self.config.userinfo_endpoint)
                .or_else(|| resolved.and_then(|r| r.userinfo_endpoint.clone())),
            jwks_uri: option_display_to_string(&self.config.jwks_uri)
                .or_else(|| resolved.and_then(|r| r.jwks_uri.clone())),
            client_id: self.config.client_id.clone(),
        }
    }
}

fn flow_name(flow: &AuthFlow) -> &'static str {
    match flow {
        AuthFlow::DeviceCode => AUTH_FLOW_DEVICE_CODE,
        AuthFlow::AuthCodePkce => AUTH_FLOW_AUTH_CODE_PKCE,
    }
}

fn option_display_to_string<T>(value: &Option<T>) -> Option<String>
where
    T: fmt::Display,
{
    value.as_ref().map(|value| value.to_string())
}

#[cfg(test)]
mod tests {
    use super::super::{cache, validation};
    use super::*;
    use auth_test_support::{MockOidcServer, OidcServerConfig};
    use serde_json::{Value, json};
    use std::collections::HashMap;
    use tempfile::tempdir;

    use fs_err::{read_to_string, write};
    use std::{
        path::{Path, PathBuf},
        time::{SystemTime, UNIX_EPOCH},
    };

    #[test]
    fn provider_cache_path_sanitizes_names() {
        let base = Path::new("/tmp/auth-cache");
        let weird = cache::provider_cache_path(base, "../evil%provider");
        assert_eq!(
            weird.file_name().and_then(|n| n.to_str()),
            Some(".._evil_provider.json")
        );

        let empty = cache::provider_cache_path(base, "");
        assert_eq!(empty.file_name().and_then(|n| n.to_str()), Some("_.json"));
    }

    #[test]
    fn claim_filters_accept_matching_claims() {
        let mut settings = mock_auth_settings("https://issuer.example.com/");
        let mut provider = settings.providers.pop().expect("provider");
        provider.required_audience = vec!["api://example-app".into()];
        provider.required_tenant = Some("tenant-id".into());
        provider.required_claims = HashMap::from([("hd".into(), "example.com".into())]);

        let claims = json!({
            "iss": "https://issuer.example.com/",
            "aud": ["api://example-app", "extra"],
            "tid": "tenant-id",
            "hd": "example.com"
        });

        assert!(
            validation::enforce_claim_filters(&provider, &claims).is_ok(),
            "expected claim filters to pass"
        );
    }

    #[test]
    fn claim_filters_reject_unknown_audience() {
        let mut settings = mock_auth_settings("https://issuer.example.com/");
        let mut provider = settings.providers.pop().expect("provider");
        provider.required_audience = vec!["api://expected".into()];

        let claims = json!({
            "iss": "https://issuer.example.com/",
            "aud": ["api://other"]
        });

        let err = validation::enforce_claim_filters(&provider, &claims)
            .expect_err("audience mismatch must fail");
        assert!(err.to_string().contains("claim 'aud'"));
    }

    #[test]
    fn claim_filters_reject_missing_claim() {
        let mut settings = mock_auth_settings("https://issuer.example.com/");
        let mut provider = settings.providers.pop().expect("provider");
        provider.required_claims = HashMap::from([("scp".into(), "user.read".into())]);

        let claims = json!({
            "iss": "https://issuer.example.com/",
            "aud": "client"
        });

        let err = validation::enforce_claim_filters(&provider, &claims)
            .expect_err("missing claim must fail");
        assert!(err.to_string().contains("scp"));
    }

    #[test]
    fn expires_within_margin_detects_expiring_entries() {
        let mut resolved = ResolvedProvider::new();
        resolved.fetched_at = Instant::now();
        assert!(!resolved.expires_within(Duration::from_secs(60)));

        resolved.fetched_at = Instant::now() - (METADATA_TTL - Duration::from_secs(30));
        assert!(resolved.expires_within(Duration::from_secs(60)));
    }

    #[tokio::test]
    async fn refresh_metadata_populates_cache() {
        let server = MockOidcServer::start(OidcServerConfig::default()).await;
        let issuer = server.issuer().to_string();
        let settings = mock_auth_settings(&issuer);
        let runtime = AuthRuntime::from_settings(&settings).expect("runtime");

        let handle = runtime
            .providers
            .get(MOCK_PROVIDER_NAME)
            .expect("provider handle");

        runtime
            .refresh_metadata_now()
            .await
            .expect("refresh succeeds");

        let cache = handle.cache.read().await;
        let resolved = cache.as_ref().expect("cache populated");
        assert!(resolved.jwks.is_some(), "jwks cached");
        assert!(resolved.issuer.is_some(), "issuer cached");
        drop(server);
    }

    #[tokio::test]
    async fn cached_metadata_loaded_on_startup() {
        let temp = tempdir().expect("tempdir");

        write_snapshot(temp.path(), MOCK_PROVIDER_NAME, "http://offline-issuer");

        let settings = mock_auth_settings("http://offline-issuer");
        let runtime =
            AuthRuntime::from_settings_with_cache_dir(&settings, temp.path().to_path_buf())
                .expect("runtime");

        let handle = runtime
            .providers
            .get(MOCK_PROVIDER_NAME)
            .expect("provider handle");

        let cache = handle.cache.read().await;
        assert!(
            cache.as_ref().and_then(|c| c.jwks.as_ref()).is_some(),
            "cached jwks should load from disk"
        );
    }

    #[tokio::test]
    async fn refresh_persists_snapshot_to_disk() {
        let temp = tempdir().expect("tempdir");

        let server = MockOidcServer::start(OidcServerConfig::default()).await;
        let issuer = server.issuer().to_string();
        let settings = mock_auth_settings(&issuer);
        let runtime =
            AuthRuntime::from_settings_with_cache_dir(&settings, temp.path().to_path_buf())
                .expect("runtime");

        runtime
            .refresh_metadata_now()
            .await
            .expect("refresh succeeds");

        let snapshot_path = cache_file(temp.path(), MOCK_PROVIDER_NAME);
        let contents = read_to_string(&snapshot_path)
            .unwrap_or_else(|_| panic!("snapshot missing at {}", snapshot_path.display()));
        let value: Value = serde_json::from_str(&contents).expect("valid snapshot json");

        let cached_issuer = value
            .get("issuer")
            .and_then(|v| v.as_str())
            .expect("issuer present");

        assert_eq!(cached_issuer, format!("{issuer}/"));

        drop(server);
    }

    #[tokio::test]
    async fn discovery_fills_device_endpoint() {
        let server = MockOidcServer::start(OidcServerConfig::default()).await;
        let issuer = server.issuer().to_string();
        let mut settings = mock_auth_settings(&issuer);
        {
            let provider = settings.providers.get_mut(0).expect("provider");
            provider.flows = vec![AuthFlow::DeviceCode];
            provider.device_authorization_endpoint = None;
        }

        let temp = tempdir().expect("tempdir");
        let runtime =
            AuthRuntime::from_settings_with_cache_dir(&settings, temp.path().to_path_buf())
                .expect("runtime");
        runtime
            .refresh_metadata_now()
            .await
            .expect("refresh succeeds");

        let handle = runtime
            .providers
            .get(MOCK_PROVIDER_NAME)
            .expect("provider handle");
        let cache = handle.cache.read().await;
        let resolved = cache.as_ref().expect("cache populated");

        let expected_device = format!("{issuer}/device");
        assert_eq!(
            resolved.device_authorization_endpoint.as_deref(),
            Some(expected_device.as_str())
        );

        drop(server);
    }

    fn cache_file(dir: &Path, provider: &str) -> PathBuf {
        cache::provider_cache_path(dir, provider)
    }

    fn write_snapshot(dir: &Path, provider: &str, issuer: &str) {
        let snapshot = json!({
            "issuer": issuer,
            "authorization_endpoint": format!("{issuer}/authorize"),
            "token_endpoint": format!("{issuer}/token"),
            "device_authorization_endpoint": format!("{issuer}/device"),
            "userinfo_endpoint": format!("{issuer}/userinfo"),
            "jwks_uri": format!("{issuer}/jwks"),
            "jwks": json!({
                "keys": [{
                    "kty": "RSA",
                    "use": "sig",
                    "kid": "cached",
                    "n": "WK_TYieedXU1Tn98SEMvFZBRHLSjkEXtesRX2_Y2RqKKLMfRQtElykTNqOas7o23RDgo7e1XfYBhG3rYWSn-eNSAFwH8M_hMGKWUIEPDfNvjzXd4CILaGB1NNiaSWURFtGSAmUBaL6wjEwzSyEmzWypMNAibZnpDdf5qnVZQq5ghNS2dPbsBzlYB7lv__WFBa3-EvK-qJAJ49F1CNdU23oalILndar0QXyOFFiWLEYhRiEB7Hprjm6DWjo4pF7FQ3Bm82Hhcieg6DXSNmU9KKudv1Yxc0X1-MrRciTNIpzLVaO5GWjsCVyUn5ZV_O907l-0VZHsN1YBCBfBoFk9B8A",
                    "e": "AQAB"
                }]
            }),
            "fetched_at": SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .expect("time")
                .as_secs() as i64,
        });

        write(cache_file(dir, provider), snapshot.to_string()).expect("write snapshot");
    }

    const MOCK_PROVIDER_NAME: &str = "mock-oidc";

    fn mock_auth_settings(issuer: &str) -> AuthSettings {
        let provider = AuthProvider {
            name: MOCK_PROVIDER_NAME.into(),
            display_name: None,
            kind: AuthProviderKind::Oidc,
            issuer: Some(IssuerUrl::new(issuer.to_string()).expect("issuer url")),
            authorization_endpoint: None,
            token_endpoint: None,
            device_authorization_endpoint: None,
            jwks_uri: None,
            userinfo_endpoint: None,
            client_id: Some("client-id".into()),
            client_secret: None,
            scopes: vec!["openid".into()],
            subject_claims: vec!["sub".into(), "id".into(), "user_id".into()],
            flows: vec![AuthFlow::AuthCodePkce],
            auto_provision: true,
            required_audience: Vec::new(),
            required_issuer: None,
            required_tenant: None,
            required_claims: HashMap::new(),
        };

        AuthSettings {
            allow_password: false,
            default_provider: Some(MOCK_PROVIDER_NAME.into()),
            providers: vec![provider],
            cache_dir: None,
            cache_max_bytes: None,
        }
    }
}
