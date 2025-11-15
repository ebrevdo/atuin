use std::{
    collections::{HashMap, HashSet},
    io::prelude::*,
    path::PathBuf,
};

use atuin_server_database::DbSettings;
use config::{Config, Environment, File as ConfigFile, FileFormat};
use eyre::{Result, eyre};
use fs_err::{File, create_dir_all};
use openidconnect::IssuerUrl;
use serde::{Deserialize, Serialize};
use thiserror::Error;
use url::Url;

static EXAMPLE_CONFIG: &str = include_str!("../server.toml");

#[derive(Default, Clone, Debug, Deserialize, Serialize)]
pub struct Mail {
    #[serde(alias = "enable")]
    pub enabled: bool,

    /// Configuration for the postmark api client
    /// This is what we use for Atuin Cloud, the forum, etc.
    #[serde(default)]
    pub postmark: Postmark,

    #[serde(default)]
    pub verification: MailVerification,
}

#[derive(Default, Clone, Debug, Deserialize, Serialize)]
pub struct Postmark {
    #[serde(alias = "token")]
    pub token: Option<String>,
}

#[derive(Default, Clone, Debug, Deserialize, Serialize)]
pub struct MailVerification {
    #[serde(alias = "enable")]
    pub from: String,
    pub subject: String,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct Metrics {
    #[serde(alias = "enabled")]
    pub enable: bool,
    pub host: String,
    pub port: u16,
}

impl Default for Metrics {
    fn default() -> Self {
        Self {
            enable: false,
            host: String::from("127.0.0.1"),
            port: 9001,
        }
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct Settings {
    pub host: String,
    pub port: u16,
    pub path: String,
    pub open_registration: bool,
    pub max_history_length: usize,
    pub max_record_size: usize,
    pub page_size: i64,
    pub register_webhook_url: Option<String>,
    pub register_webhook_username: String,
    pub metrics: Metrics,
    pub tls: Tls,
    pub mail: Mail,
    #[serde(default)]
    pub auth: AuthSettings,

    /// Advertise a version that is not what we are _actually_ running
    /// Many clients compare their version with api.atuin.sh, and if they differ, notify the user
    /// that an update is available.
    /// Now that we take beta releases, we should be able to advertise a different version to avoid
    /// notifying users when the server runs something that is not a stable release.
    pub fake_version: Option<String>,

    #[serde(flatten)]
    pub db_settings: DbSettings,
}

impl Settings {
    pub fn new() -> Result<Self> {
        let mut config_file = if let Ok(p) = std::env::var("ATUIN_CONFIG_DIR") {
            PathBuf::from(p)
        } else {
            let mut config_file = PathBuf::new();
            let config_dir = atuin_common::utils::config_dir();
            config_file.push(config_dir);
            config_file
        };

        config_file.push("server.toml");

        // create the config file if it does not exist
        let mut config_builder = Config::builder()
            .set_default("host", "127.0.0.1")?
            .set_default("port", 8888)?
            .set_default("open_registration", false)?
            .set_default("max_history_length", 8192)?
            .set_default("max_record_size", 1024 * 1024 * 1024)? // pretty chonky
            .set_default("path", "")?
            .set_default("register_webhook_username", "")?
            .set_default("page_size", 1100)?
            .set_default("metrics.enable", false)?
            .set_default("metrics.host", "127.0.0.1")?
            .set_default("metrics.port", 9001)?
            .set_default("mail.enable", false)?
            .set_default("tls.enable", false)?
            .set_default("tls.cert_path", "")?
            .set_default("tls.pkey_path", "")?
            .add_source(
                Environment::with_prefix("atuin")
                    .prefix_separator("_")
                    .separator("__"),
            );

        config_builder = if config_file.exists() {
            config_builder.add_source(ConfigFile::new(
                config_file.to_str().unwrap(),
                FileFormat::Toml,
            ))
        } else {
            create_dir_all(config_file.parent().unwrap())?;
            let mut file = File::create(config_file)?;
            file.write_all(EXAMPLE_CONFIG.as_bytes())?;

            config_builder
        };

        let config = config_builder.build()?;

        let settings: Settings = config
            .try_deserialize()
            .map_err(|e| eyre!("failed to deserialize: {}", e))?;

        settings
            .auth
            .validate()
            .map_err(|e| eyre!("invalid auth configuration: {}", e))?;

        Ok(settings)
    }
}

pub fn example_config() -> &'static str {
    EXAMPLE_CONFIG
}

#[derive(Clone, Debug, Default, Deserialize, Serialize)]
pub struct Tls {
    #[serde(alias = "enabled")]
    pub enable: bool,

    pub cert_path: PathBuf,
    pub pkey_path: PathBuf,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct AuthSettings {
    #[serde(default = "default_allow_password")]
    pub allow_password: bool,
    #[serde(default)]
    pub default_provider: Option<String>,
    #[serde(default)]
    pub providers: Vec<AuthProvider>,
    #[serde(default)]
    pub cache_dir: Option<PathBuf>,
    #[serde(default)]
    pub cache_max_bytes: Option<u64>,
}

// Keep manual Default so password login stays enabled unless explicitly disabled.
// Deriving Default would flip `allow_password` to false and break existing configs.
impl Default for AuthSettings {
    fn default() -> Self {
        Self {
            allow_password: true,
            default_provider: None,
            providers: Vec::new(),
            cache_dir: None,
            cache_max_bytes: None,
        }
    }
}

impl AuthSettings {
    pub fn provider(&self, name: &str) -> Option<&AuthProvider> {
        self.providers.iter().find(|p| p.name == name)
    }

    pub fn validate(&self) -> std::result::Result<(), AuthSettingsError> {
        if self.allow_password {
            if !self.providers.is_empty() {
                return Err(AuthSettingsError::PasswordModeProviderConflict);
            }

            if self.default_provider.is_some() {
                return Err(AuthSettingsError::PasswordModeDefaultProviderConflict);
            }
        } else if self.providers.is_empty() {
            return Err(AuthSettingsError::ExternalModeMissingProviders);
        }

        let mut seen = HashSet::new();
        for provider in &self.providers {
            if !seen.insert(provider.name.clone()) {
                return Err(AuthSettingsError::DuplicateProvider {
                    name: provider.name.clone(),
                });
            }

            provider
                .validate()
                .map_err(|error| AuthSettingsError::Provider {
                    name: provider.name.clone(),
                    source: error,
                })?;
        }

        if let Some(default) = &self.default_provider {
            if !self.providers.iter().any(|p| &p.name == default) {
                return Err(AuthSettingsError::UnknownDefaultProvider {
                    name: default.clone(),
                });
            }
        }

        if let Some(limit) = self.cache_max_bytes {
            if limit == 0 {
                return Err(AuthSettingsError::InvalidCacheLimit);
            }
        }

        Ok(())
    }
}

fn default_allow_password() -> bool {
    true
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct AuthProvider {
    pub name: String,
    #[serde(default)]
    pub display_name: Option<String>,
    #[serde(default)]
    pub kind: AuthProviderKind,
    #[serde(default)]
    pub issuer: Option<IssuerUrl>,
    #[serde(default)]
    pub authorization_endpoint: Option<Url>,
    #[serde(default)]
    pub token_endpoint: Option<Url>,
    #[serde(default)]
    pub device_authorization_endpoint: Option<Url>,
    #[serde(default)]
    pub jwks_uri: Option<Url>,
    #[serde(default)]
    pub userinfo_endpoint: Option<Url>,
    #[serde(default)]
    pub client_id: Option<String>,
    #[serde(default)]
    pub client_secret: Option<String>,
    #[serde(default = "default_scopes")]
    pub scopes: Vec<String>,
    #[serde(default = "default_subject_claims")]
    pub subject_claims: Vec<String>,
    #[serde(default = "default_flows")]
    pub flows: Vec<AuthFlow>,
    #[serde(default = "default_auto_provision")]
    pub auto_provision: bool,
    #[serde(default)]
    pub required_audience: Vec<String>,
    #[serde(default)]
    pub required_issuer: Option<String>,
    #[serde(default)]
    pub required_tenant: Option<String>,
    #[serde(default)]
    pub required_claims: HashMap<String, String>,
}

impl AuthProvider {
    pub fn validate(&self) -> std::result::Result<(), AuthProviderError> {
        if self.name.trim().is_empty() {
            return Err(AuthProviderError::EmptyName);
        }

        if self.flows.is_empty() {
            return Err(AuthProviderError::MissingFlow);
        }

        if self.subject_claims.is_empty() {
            return Err(AuthProviderError::MissingSubjectClaims);
        }

        for claim in &self.subject_claims {
            if claim.trim().is_empty() {
                return Err(AuthProviderError::EmptySubjectClaim {
                    claim: claim.clone(),
                });
            }
        }

        if self
            .client_id
            .as_ref()
            .map(|s| s.trim().is_empty())
            .unwrap_or(true)
        {
            return Err(AuthProviderError::MissingClientId);
        }

        match self.kind {
            AuthProviderKind::Oidc => {
                if self.issuer.is_none() {
                    return Err(AuthProviderError::MissingIssuer);
                }
            }
            AuthProviderKind::Oauth2 => {
                if self.authorization_endpoint.is_none() {
                    return Err(AuthProviderError::MissingAuthorizationEndpoint);
                }
                if self.token_endpoint.is_none() {
                    return Err(AuthProviderError::MissingTokenEndpoint);
                }
                if self.userinfo_endpoint.is_none() {
                    return Err(AuthProviderError::MissingUserinfoEndpoint);
                }
            }
        }

        if self
            .flows
            .iter()
            .any(|flow| matches!(flow, AuthFlow::DeviceCode))
            && matches!(self.kind, AuthProviderKind::Oauth2)
            && self.device_authorization_endpoint.is_none()
        {
            return Err(AuthProviderError::MissingDeviceEndpoint);
        }

        for audience in &self.required_audience {
            if audience.trim().is_empty() {
                return Err(AuthProviderError::EmptyRequiredAudience);
            }
        }

        if let Some(issuer) = &self.required_issuer {
            if issuer.trim().is_empty() {
                return Err(AuthProviderError::EmptyRequiredIssuer);
            }
        }

        if let Some(tenant) = &self.required_tenant {
            if tenant.trim().is_empty() {
                return Err(AuthProviderError::EmptyRequiredTenant);
            }
        }

        for (claim, expected) in &self.required_claims {
            if claim.trim().is_empty() {
                return Err(AuthProviderError::EmptyRequiredClaimKey);
            }

            if expected.is_empty() {
                return Err(AuthProviderError::EmptyRequiredClaimValue {
                    claim: claim.clone(),
                });
            }
        }

        Ok(())
    }
}

fn default_subject_claims() -> Vec<String> {
    vec!["sub".to_owned(), "id".to_owned(), "user_id".to_owned()]
}

fn default_scopes() -> Vec<String> {
    vec![
        "openid".to_owned(),
        "profile".to_owned(),
        "offline_access".to_owned(),
    ]
}

fn default_flows() -> Vec<AuthFlow> {
    vec![AuthFlow::DeviceCode]
}

fn default_auto_provision() -> bool {
    true
}

#[derive(Debug, Error)]
pub enum AuthSettingsError {
    #[error(
        "auth.allow_password=true is password-only mode; remove auth.providers or set auth.allow_password=false before configuring external providers"
    )]
    PasswordModeProviderConflict,
    #[error(
        "auth.default_provider is only valid when auth.allow_password=false (external auth mode)"
    )]
    PasswordModeDefaultProviderConflict,
    #[error("auth.allow_password=false requires at least one provider in auth.providers")]
    ExternalModeMissingProviders,
    #[error("duplicate auth provider '{name}'")]
    DuplicateProvider { name: String },
    #[error("default_provider '{name}' not found in auth.providers")]
    UnknownDefaultProvider { name: String },
    #[error("auth.cache_max_bytes must be greater than zero when set")]
    InvalidCacheLimit,
    #[error("auth provider '{name}': {source}")]
    Provider {
        name: String,
        #[source]
        source: AuthProviderError,
    },
}

#[derive(Debug, Error)]
pub enum AuthProviderError {
    #[error("name may not be empty")]
    EmptyName,
    #[error("must specify at least one flow")]
    MissingFlow,
    #[error("must specify at least one subject_claim")]
    MissingSubjectClaims,
    #[error("subject_claims entries may not be empty")]
    EmptySubjectClaim { claim: String },
    #[error("requires client_id")]
    MissingClientId,
    #[error("oidc providers require an issuer")]
    MissingIssuer,
    #[error("oauth2 providers require authorization_endpoint")]
    MissingAuthorizationEndpoint,
    #[error("oauth2 providers require token_endpoint")]
    MissingTokenEndpoint,
    #[error("oauth2 providers require userinfo_endpoint")]
    MissingUserinfoEndpoint,
    #[error("device_code flow requires device_authorization_endpoint")]
    MissingDeviceEndpoint,
    #[error("required_audience entries may not be empty")]
    EmptyRequiredAudience,
    #[error("required_issuer may not be empty")]
    EmptyRequiredIssuer,
    #[error("required_tenant may not be empty")]
    EmptyRequiredTenant,
    #[error("required_claims keys may not be empty")]
    EmptyRequiredClaimKey,
    #[error("required_claims value for '{claim}' may not be empty")]
    EmptyRequiredClaimValue { claim: String },
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum AuthFlow {
    DeviceCode,
    AuthCodePkce,
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum AuthProviderKind {
    Oidc,
    Oauth2,
}

impl Default for AuthProviderKind {
    fn default() -> Self {
        Self::Oidc
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;

    #[test]
    fn validate_rejects_missing_oidc_issuer() {
        let mut provider = sample_oidc_provider();
        provider.issuer = None;

        let settings = sample_settings(provider);
        let err = settings.validate().expect_err("missing issuer must fail");
        assert!(err.to_string().contains("issuer"));
    }

    #[test]
    fn validate_rejects_invalid_oauth_endpoint() {
        let mut provider = sample_oauth_provider();
        provider.authorization_endpoint = None;

        let settings = sample_settings(provider);
        let err = settings
            .validate()
            .expect_err("missing authorization url must fail");
        assert!(err.to_string().contains("authorization_endpoint"));
    }

    #[test]
    fn validate_rejects_password_with_providers() {
        let settings = AuthSettings {
            allow_password: true,
            default_provider: None,
            providers: vec![sample_oidc_provider()],
            cache_dir: None,
            cache_max_bytes: None,
        };

        let err = settings
            .validate()
            .expect_err("password auth must not allow additional providers");
        assert!(
            err.to_string()
                .contains("allow_password=true is password-only mode")
        );
    }

    #[test]
    fn validate_allows_multiple_providers_when_password_disabled() {
        let settings = AuthSettings {
            allow_password: false,
            default_provider: Some("oauth".into()),
            providers: vec![sample_oidc_provider(), sample_oauth_provider()],
            cache_dir: None,
            cache_max_bytes: None,
        };

        settings
            .validate()
            .expect("multiple providers should be accepted when password auth is disabled");
    }

    fn sample_settings(provider: AuthProvider) -> AuthSettings {
        AuthSettings {
            allow_password: false,
            default_provider: Some(provider.name.clone()),
            providers: vec![provider],
            cache_dir: None,
            cache_max_bytes: None,
        }
    }

    fn sample_oidc_provider() -> AuthProvider {
        AuthProvider {
            name: "oidc".into(),
            display_name: None,
            kind: AuthProviderKind::Oidc,
            issuer: Some(IssuerUrl::new("https://issuer.example.com".into()).unwrap()),
            authorization_endpoint: None,
            token_endpoint: None,
            device_authorization_endpoint: None,
            jwks_uri: None,
            userinfo_endpoint: None,
            client_id: Some("client".into()),
            client_secret: None,
            scopes: vec!["openid".into()],
            subject_claims: default_subject_claims(),
            flows: vec![AuthFlow::DeviceCode],
            auto_provision: true,
            required_audience: Vec::new(),
            required_issuer: None,
            required_tenant: None,
            required_claims: HashMap::new(),
        }
    }

    fn sample_oauth_provider() -> AuthProvider {
        AuthProvider {
            name: "oauth".into(),
            display_name: None,
            kind: AuthProviderKind::Oauth2,
            issuer: None,
            authorization_endpoint: Some(Url::parse("https://example.com/authorize").unwrap()),
            token_endpoint: Some(Url::parse("https://example.com/token").unwrap()),
            device_authorization_endpoint: Some(Url::parse("https://example.com/device").unwrap()),
            jwks_uri: None,
            userinfo_endpoint: Some(Url::parse("https://example.com/userinfo").unwrap()),
            client_id: Some("client".into()),
            client_secret: None,
            scopes: vec!["profile".into()],
            subject_claims: default_subject_claims(),
            flows: vec![AuthFlow::DeviceCode],
            auto_provision: true,
            required_audience: Vec::new(),
            required_issuer: None,
            required_tenant: None,
            required_claims: HashMap::new(),
        }
    }
}
