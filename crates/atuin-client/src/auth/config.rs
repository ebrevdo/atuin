use std::collections::HashSet;

use atuin_common::api::{
    AUTH_FLOW_AUTH_CODE_PKCE, AUTH_FLOW_DEVICE_CODE, AuthProviderPublic, AuthProvidersResponse,
};
use log::trace;
use thiserror::Error;

use crate::settings::{AuthClientSettings, AuthFlowPreference, AuthProviderOverride};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum ProviderKind {
    Oidc,
    Oauth2,
}

#[derive(Clone, Debug)]
pub(crate) struct ProviderConfig {
    pub(crate) name: String,
    pub(crate) display_name: Option<String>,
    pub(crate) kind: ProviderKind,
    pub(crate) flows: Vec<FlowVariant>,
    pub(crate) scopes: Vec<String>,
    #[allow(dead_code)]
    pub(crate) issuer: Option<String>,
    #[allow(dead_code)]
    pub(crate) userinfo_endpoint: Option<String>,
    #[allow(dead_code)]
    pub(crate) jwks_uri: Option<String>,
    pub(crate) client_id: Option<String>,
    pub(crate) client_secret: Option<String>,
}

#[derive(Clone, Debug)]
pub(crate) enum FlowVariant {
    DeviceCode(DeviceFlowConfig),
    AuthCodePkce(PkceFlowConfig),
}

impl FlowVariant {
    pub(crate) fn preference(&self) -> AuthFlowPreference {
        match self {
            FlowVariant::DeviceCode(_) => AuthFlowPreference::DeviceCode,
            FlowVariant::AuthCodePkce(_) => AuthFlowPreference::AuthCodePkce,
        }
    }
}

#[derive(Clone, Debug)]
pub(crate) struct DeviceFlowConfig {
    pub(crate) token_endpoint: String,
    pub(crate) device_authorization_endpoint: String,
}

#[derive(Clone, Debug)]
pub(crate) struct PkceFlowConfig {
    pub(crate) token_endpoint: String,
    pub(crate) authorization_endpoint: String,
}

#[derive(Clone, Debug)]
pub struct ProviderSelection {
    provider: ProviderConfig,
    flow: FlowVariant,
    pkce_redirect_port: Option<u16>,
}

type Result<T> = std::result::Result<T, AuthConfigError>;

#[derive(Debug, Error)]
pub enum AuthConfigError {
    #[error("server is configured for password authentication")]
    PasswordAuthOnly,
    #[error("server has not enabled any external auth providers")]
    NoExternalProviders,
    #[error("multiple auth providers available: {providers:?}")]
    MultipleProviders { providers: Vec<String> },
    #[error("server did not advertise auth provider '{0}'")]
    UnknownProvider(String),
    #[error("provider '{provider}' is missing required field '{field}'")]
    MissingField {
        provider: String,
        field: &'static str,
    },
    #[error("provider '{provider}' cannot run {flow:?} flow")]
    UnsupportedFlow {
        provider: String,
        flow: AuthFlowPreference,
    },
    #[error("provider '{provider}' has no usable auth flows")]
    NoUsableFlows { provider: String },
}

impl ProviderSelection {
    pub fn flow(&self) -> AuthFlowPreference {
        self.flow.preference()
    }

    pub fn provider_name(&self) -> &str {
        self.provider.name.as_str()
    }

    pub fn display_label(&self) -> &str {
        self.provider
            .display_name
            .as_deref()
            .unwrap_or(self.provider.name.as_str())
    }

    pub fn is_oidc(&self) -> bool {
        matches!(self.provider.kind, ProviderKind::Oidc)
    }

    pub(crate) fn provider(&self) -> &ProviderConfig {
        &self.provider
    }

    pub(crate) fn provider_kind(&self) -> ProviderKind {
        self.provider.kind
    }

    pub(crate) fn device_flow(&self) -> Option<&DeviceFlowConfig> {
        match &self.flow {
            FlowVariant::DeviceCode(cfg) => Some(cfg),
            _ => None,
        }
    }

    pub(crate) fn pkce_flow(&self) -> Option<&PkceFlowConfig> {
        match &self.flow {
            FlowVariant::AuthCodePkce(cfg) => Some(cfg),
            _ => None,
        }
    }

    pub(crate) fn pkce_redirect_port(&self) -> Option<u16> {
        self.pkce_redirect_port
    }

    #[cfg(test)]
    pub(crate) fn new_for_test(
        provider: ProviderConfig,
        flow: FlowVariant,
        pkce_redirect_port: Option<u16>,
    ) -> Self {
        Self {
            provider,
            flow,
            pkce_redirect_port,
        }
    }
}

pub fn select_provider(
    response: &AuthProvidersResponse,
    settings: &AuthClientSettings,
    requested: Option<&str>,
) -> Result<ProviderSelection> {
    if response.allow_password {
        return Err(AuthConfigError::PasswordAuthOnly);
    }

    if response.providers.is_empty() {
        return Err(AuthConfigError::NoExternalProviders);
    }

    let server_provider = pick_provider(response, settings, requested)?;
    let override_cfg = settings.provider_override(&server_provider.name);
    let provider = merge_provider(server_provider, override_cfg)?;

    let preferred_order = override_cfg
        .and_then(|o| o.flows.as_ref())
        .and_then(|f| f.first())
        .copied();

    let flow = pick_flow(&provider, preferred_order)?;

    Ok(ProviderSelection {
        provider,
        flow,
        pkce_redirect_port: settings.redirect_port(),
    })
}

fn pick_provider<'a>(
    response: &'a AuthProvidersResponse,
    settings: &AuthClientSettings,
    requested: Option<&str>,
) -> Result<&'a AuthProviderPublic> {
    if let Some(name) = requested {
        return find_provider(response, name);
    }

    if let Some(name) = settings.provider() {
        return find_provider(response, name);
    }

    if let Some(default_name) = response.default_provider.as_deref() {
        return find_provider(response, default_name);
    }

    if response.providers.len() == 1 {
        return Ok(&response.providers[0]);
    }

    let available = response.providers.iter().map(|p| p.name.clone()).collect();
    Err(AuthConfigError::MultipleProviders {
        providers: available,
    })
}

fn find_provider<'a>(
    response: &'a AuthProvidersResponse,
    name: &str,
) -> Result<&'a AuthProviderPublic> {
    response
        .providers
        .iter()
        .find(|p| p.name == name)
        .ok_or_else(|| AuthConfigError::UnknownProvider(name.to_string()))
}

fn merge_provider(
    public: &AuthProviderPublic,
    override_cfg: Option<&AuthProviderOverride>,
) -> Result<ProviderConfig> {
    let kind = match public.kind.as_str() {
        "oidc" => ProviderKind::Oidc,
        "oauth2" => ProviderKind::Oauth2,
        other => {
            trace!(
                "unknown auth kind '{}' for provider '{}'; defaulting to oauth2",
                other,
                public.name.as_str()
            );
            ProviderKind::Oauth2
        }
    };

    let client_id = override_cfg
        .and_then(|o| o.client_id.clone())
        .or_else(|| public.client_id.clone());

    let client_secret = override_cfg.and_then(|o| o.client_secret.clone());

    let scopes = override_cfg
        .and_then(|o| o.scopes.clone())
        .unwrap_or_else(|| public.scopes.clone());

    let mut flow_order = if let Some(override_flows) = override_cfg.and_then(|o| o.flows.clone()) {
        override_flows
    } else {
        parse_flow_strings(&public.flows)
    };

    let issuer = override_cfg
        .and_then(|o| o.issuer.as_ref().map(|url| url.to_string()))
        .or_else(|| public.issuer.clone());

    let token_endpoint = override_cfg
        .and_then(|o| o.token_endpoint.as_ref().map(|url| url.to_string()))
        .or_else(|| public.token_endpoint.clone());

    let authorization_endpoint = override_cfg
        .and_then(|o| o.authorization_endpoint.as_ref().map(|url| url.to_string()))
        .or_else(|| public.authorization_endpoint.clone());

    let device_authorization_endpoint = override_cfg
        .and_then(|o| {
            o.device_authorization_endpoint
                .as_ref()
                .map(|url| url.to_string())
        })
        .or_else(|| public.device_authorization_endpoint.clone());

    if flow_order.is_empty() {
        if token_endpoint.is_some() && device_authorization_endpoint.is_some() {
            flow_order.push(AuthFlowPreference::DeviceCode);
        }
        if token_endpoint.is_some() && authorization_endpoint.is_some() {
            flow_order.push(AuthFlowPreference::AuthCodePkce);
        }
    }

    dedupe_flows(&mut flow_order);

    let flows = build_flow_variants(
        flow_order,
        &token_endpoint,
        &authorization_endpoint,
        &device_authorization_endpoint,
        public.name.as_str(),
    )?;

    if flows.is_empty() {
        return Err(AuthConfigError::NoUsableFlows {
            provider: public.name.clone(),
        });
    }

    Ok(ProviderConfig {
        name: public.name.clone(),
        display_name: public.display_name.clone(),
        kind,
        flows,
        scopes,
        issuer,
        userinfo_endpoint: override_cfg
            .and_then(|o| o.userinfo_endpoint.as_ref().map(|url| url.to_string()))
            .or_else(|| public.userinfo_endpoint.clone()),
        jwks_uri: override_cfg
            .and_then(|o| o.jwks_uri.as_ref().map(|url| url.to_string()))
            .or_else(|| public.jwks_uri.clone()),
        client_id,
        client_secret,
    })
}

fn parse_flow_strings(values: &[String]) -> Vec<AuthFlowPreference> {
    values
        .iter()
        .filter_map(|raw| {
            let normalized = raw.to_ascii_lowercase();
            match normalized.as_str() {
                AUTH_FLOW_DEVICE_CODE => Some(AuthFlowPreference::DeviceCode),
                AUTH_FLOW_AUTH_CODE_PKCE | "authorization_code" => {
                    Some(AuthFlowPreference::AuthCodePkce)
                }
                _ => None,
            }
        })
        .collect()
}

fn dedupe_flows(flows: &mut Vec<AuthFlowPreference>) {
    let mut seen = HashSet::new();
    flows.retain(|f| seen.insert(*f));
    flows.sort_by_key(|f| match f {
        AuthFlowPreference::DeviceCode => 0,
        AuthFlowPreference::AuthCodePkce => 1,
    });
}

fn build_flow_variants(
    flows: Vec<AuthFlowPreference>,
    token_endpoint: &Option<String>,
    authorization_endpoint: &Option<String>,
    device_endpoint: &Option<String>,
    provider: &str,
) -> Result<Vec<FlowVariant>> {
    flows
        .into_iter()
        .map(|flow| match flow {
            AuthFlowPreference::DeviceCode => {
                let token = clone_required(token_endpoint, provider, "token_endpoint")?;
                let device =
                    clone_required(device_endpoint, provider, "device_authorization_endpoint")?;
                Ok(FlowVariant::DeviceCode(DeviceFlowConfig {
                    token_endpoint: token,
                    device_authorization_endpoint: device,
                }))
            }
            AuthFlowPreference::AuthCodePkce => {
                let token = clone_required(token_endpoint, provider, "token_endpoint")?;
                let auth =
                    clone_required(authorization_endpoint, provider, "authorization_endpoint")?;
                Ok(FlowVariant::AuthCodePkce(PkceFlowConfig {
                    token_endpoint: token,
                    authorization_endpoint: auth,
                }))
            }
        })
        .collect()
}

fn clone_required(value: &Option<String>, provider: &str, field: &'static str) -> Result<String> {
    value.clone().ok_or_else(|| AuthConfigError::MissingField {
        provider: provider.to_string(),
        field,
    })
}

fn pick_flow(
    provider: &ProviderConfig,
    preference: Option<AuthFlowPreference>,
) -> Result<FlowVariant> {
    if let Some(flow) = preference {
        if let Some(variant) = provider
            .flows
            .iter()
            .find(|candidate| candidate.preference() == flow)
        {
            return Ok(variant.clone());
        }
        return Err(AuthConfigError::UnsupportedFlow {
            provider: provider.name.clone(),
            flow,
        });
    }

    if let Some(first) = provider.flows.first() {
        return Ok(first.clone());
    }

    Err(AuthConfigError::NoUsableFlows {
        provider: provider.name.clone(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::settings::{AuthClientSettings, AuthProviderOverride};
    use atuin_common::api::{AuthProviderPublic, AuthProvidersResponse};

    fn make_provider(name: &str, kind: &str, flows: &[&str]) -> AuthProviderPublic {
        AuthProviderPublic {
            name: name.to_string(),
            display_name: None,
            kind: kind.to_string(),
            flows: flows.iter().map(|f| f.to_string()).collect(),
            scopes: vec!["profile".into()],
            issuer: Some("https://issuer.example.com".into()),
            authorization_endpoint: Some("https://issuer.example.com/authorize".into()),
            token_endpoint: Some("https://issuer.example.com/token".into()),
            device_authorization_endpoint: Some("https://issuer.example.com/device".into()),
            userinfo_endpoint: Some("https://issuer.example.com/userinfo".into()),
            jwks_uri: Some("https://issuer.example.com/jwks".into()),
            client_id: Some("client".into()),
        }
    }

    fn providers_response(
        providers: Vec<AuthProviderPublic>,
        allow_password: bool,
        default_provider: Option<&str>,
    ) -> AuthProvidersResponse {
        AuthProvidersResponse {
            allow_password,
            default_provider: default_provider.map(|name| name.to_string()),
            providers,
        }
    }

    #[test]
    fn select_provider_rejects_password_only() {
        let response = providers_response(Vec::new(), true, None);

        let error = select_provider(&response, &AuthClientSettings::default(), None)
            .expect_err("password-only config should be rejected");

        assert!(matches!(error, AuthConfigError::PasswordAuthOnly));
    }

    #[test]
    fn select_provider_rejects_multiple_providers() {
        let response = providers_response(
            vec![
                make_provider("azure", "oidc", &["device_code"]),
                make_provider("google", "oidc", &["device_code"]),
            ],
            false,
            None,
        );

        let error = select_provider(&response, &AuthClientSettings::default(), None)
            .expect_err("multiple providers should fail");

        let AuthConfigError::MultipleProviders { providers } = error else {
            panic!("expected multiple providers error");
        };

        assert_eq!(providers, vec!["azure", "google"]);
    }

    #[test]
    fn select_provider_returns_single_provider() {
        let response = providers_response(
            vec![make_provider(
                "azure",
                "oidc",
                &["device_code", "auth_code_pkce"],
            )],
            false,
            None,
        );

        let selection = select_provider(&response, &AuthClientSettings::default(), None)
            .expect("single provider should work");

        assert_eq!(selection.provider_name(), "azure");
        assert_eq!(selection.flow(), AuthFlowPreference::DeviceCode);
    }

    #[test]
    fn select_provider_respects_override_flow() {
        let response = providers_response(
            vec![make_provider(
                "azure",
                "oidc",
                &["device_code", "auth_code_pkce"],
            )],
            false,
            None,
        );

        let mut settings = AuthClientSettings::default();
        settings.providers.push(AuthProviderOverride {
            name: "azure".into(),
            flows: Some(vec![AuthFlowPreference::AuthCodePkce]),
            issuer: None,
            authorization_endpoint: None,
            token_endpoint: None,
            device_authorization_endpoint: None,
            jwks_uri: None,
            userinfo_endpoint: None,
            client_id: None,
            client_secret: None,
            scopes: None,
        });

        let selection =
            select_provider(&response, &settings, None).expect("override should pick pkce");

        assert_eq!(selection.flow(), AuthFlowPreference::AuthCodePkce);
    }

    #[test]
    fn select_provider_carries_redirect_port() {
        let response = providers_response(
            vec![make_provider("azure", "oidc", &["auth_code_pkce"])],
            false,
            None,
        );

        let mut settings = AuthClientSettings::default();
        settings.redirect_port = Some(4812);

        let selection =
            select_provider(&response, &settings, None).expect("should select provider");

        assert_eq!(selection.pkce_redirect_port(), Some(4812));
    }

    #[test]
    fn select_provider_prefers_server_default() {
        let response = providers_response(
            vec![
                make_provider("azure", "oidc", &["device_code"]),
                make_provider("google", "oidc", &["device_code"]),
            ],
            false,
            Some("google"),
        );

        let selection =
            select_provider(&response, &AuthClientSettings::default(), None).expect("uses default");

        assert_eq!(selection.provider_name(), "google");
    }

    #[test]
    fn select_provider_prefers_client_setting() {
        let response = providers_response(
            vec![
                make_provider("azure", "oidc", &["device_code"]),
                make_provider("google", "oidc", &["device_code"]),
            ],
            false,
            Some("azure"),
        );

        let mut settings = AuthClientSettings::default();
        settings.provider = Some("google".into());

        let selection =
            select_provider(&response, &settings, None).expect("uses client preference");

        assert_eq!(selection.provider_name(), "google");
    }

    #[test]
    fn select_provider_honors_requested_name() {
        let response = providers_response(
            vec![
                make_provider("azure", "oidc", &["device_code"]),
                make_provider("github", "oauth2", &["device_code"]),
            ],
            false,
            None,
        );

        let selection = select_provider(&response, &AuthClientSettings::default(), Some("github"))
            .expect("uses requested provider");

        assert_eq!(selection.provider_name(), "github");
    }
}
