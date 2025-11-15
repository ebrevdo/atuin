use oauth2::{AuthUrl, CsrfToken, PkceCodeChallenge, RedirectUrl, Scope, TokenResponse, TokenUrl};

use super::super::loopback::{LoopbackConfig, spawn_loopback_listener};
use super::{
    AuthFlowError, ExternalToken, FlowController, FlowResult, PkceFlowConfig, PkceFlowPrompt,
    ProviderConfig, ProviderKind, ProviderSelection, build_http_client, build_oauth_client,
    build_oidc_client, normalize_scopes,
};

pub(super) async fn login_pkce<F>(
    selection: &ProviderSelection,
    flow: &PkceFlowConfig,
    notify: &F,
    controller: &FlowController,
) -> FlowResult<ExternalToken>
where
    F: Fn(&PkceFlowPrompt),
{
    match selection.provider_kind() {
        ProviderKind::Oidc => {
            pkce_oidc(
                selection.provider(),
                flow,
                selection.pkce_redirect_port(),
                notify,
                controller,
            )
            .await
        }
        ProviderKind::Oauth2 => {
            pkce_oauth(
                selection.provider(),
                flow,
                selection.pkce_redirect_port(),
                notify,
                controller,
            )
            .await
        }
    }
}

async fn pkce_oidc<F>(
    provider: &ProviderConfig,
    flow: &PkceFlowConfig,
    redirect_port: Option<u16>,
    notify: &F,
    controller: &FlowController,
) -> FlowResult<ExternalToken>
where
    F: Fn(&PkceFlowPrompt),
{
    let client = build_oidc_client(provider)?;
    let token_url = TokenUrl::new(flow.token_endpoint.clone()).map_err(|err| {
        AuthFlowError::InvalidConfig(format!(
            "invalid token endpoint URL for provider '{}': {err}",
            provider.name
        ))
    })?;
    let auth_url = AuthUrl::new(flow.authorization_endpoint.clone()).map_err(|err| {
        AuthFlowError::InvalidConfig(format!(
            "invalid authorization endpoint URL for provider '{}': {err}",
            provider.name
        ))
    })?;

    let client = client.set_token_uri(token_url).set_auth_uri(auth_url);

    let loopback = spawn_loopback_listener(LoopbackConfig {
        redirect_port,
        cancellation: controller.cancellation_token(),
        lifetime: controller.loopback_lifetime(),
    })
    .await?;
    let redirect_uri = loopback.redirect_uri().to_string();
    let client =
        client.set_redirect_uri(RedirectUrl::new(redirect_uri.clone()).map_err(|err| {
            AuthFlowError::InvalidConfig(format!(
                "invalid redirect URI '{redirect_uri}' for provider '{}': {err}",
                provider.name
            ))
        })?);

    let scopes = normalize_scopes(provider);
    let (pkce_challenge, pkce_verifier) = PkceCodeChallenge::new_random_sha256();
    let nonce_value = uuid::Uuid::new_v4().to_string();
    let (authorize_url, csrf_state) = client
        .authorize_url(CsrfToken::new_random)
        .add_extra_param("nonce", nonce_value.as_str())
        .set_pkce_challenge(pkce_challenge)
        .add_scopes(scopes.iter().map(|scope| Scope::new(scope.clone())))
        .url();

    loopback.expect_state(&csrf_state);
    notify(&PkceFlowPrompt {
        authorization_url: authorize_url.to_string(),
        redirect_uri: redirect_uri.clone(),
    });

    let (code, state) = loopback.wait().await?;

    if state.secret() != csrf_state.secret() {
        return Err(AuthFlowError::provider("authorization state mismatch"));
    }

    let http_client = build_http_client()?;

    let token = controller
        .run_with_deadline("pkce token exchange", controller.http_timeout(), async {
            client
                .exchange_code(code)
                .set_pkce_verifier(pkce_verifier)
                .request_async(&http_client)
                .await
                .map_err(|err| {
                    AuthFlowError::provider(format!("failed to exchange authorization code: {err}"))
                })
        })
        .await?;

    let id_token = token.extra_fields().id_token.clone().ok_or_else(|| {
        AuthFlowError::provider(format!(
            "provider '{}' did not return an id_token",
            provider.name
        ))
    })?;

    Ok(ExternalToken::with_nonce(id_token, nonce_value))
}

async fn pkce_oauth<F>(
    provider: &ProviderConfig,
    flow: &PkceFlowConfig,
    redirect_port: Option<u16>,
    notify: &F,
    controller: &FlowController,
) -> FlowResult<ExternalToken>
where
    F: Fn(&PkceFlowPrompt),
{
    let client = build_oauth_client(provider)?;
    let token_url = TokenUrl::new(flow.token_endpoint.clone()).map_err(|err| {
        AuthFlowError::InvalidConfig(format!(
            "invalid token endpoint URL for provider '{}': {err}",
            provider.name
        ))
    })?;
    let auth_url = AuthUrl::new(flow.authorization_endpoint.clone()).map_err(|err| {
        AuthFlowError::InvalidConfig(format!(
            "invalid authorization endpoint URL for provider '{}': {err}",
            provider.name
        ))
    })?;

    let client = client.set_token_uri(token_url).set_auth_uri(auth_url);

    let loopback = spawn_loopback_listener(LoopbackConfig {
        redirect_port,
        cancellation: controller.cancellation_token(),
        lifetime: controller.loopback_lifetime(),
    })
    .await?;
    let redirect_uri = loopback.redirect_uri().to_string();
    let client =
        client.set_redirect_uri(RedirectUrl::new(redirect_uri.clone()).map_err(|err| {
            AuthFlowError::InvalidConfig(format!(
                "invalid redirect URI '{redirect_uri}' for provider '{}': {err}",
                provider.name
            ))
        })?);

    let scopes = normalize_scopes(provider);
    let (pkce_challenge, pkce_verifier) = PkceCodeChallenge::new_random_sha256();
    let (authorize_url, csrf_state) = client
        .authorize_url(CsrfToken::new_random)
        .set_pkce_challenge(pkce_challenge)
        .add_scopes(scopes.iter().map(|scope| Scope::new(scope.clone())))
        .url();

    loopback.expect_state(&csrf_state);
    notify(&PkceFlowPrompt {
        authorization_url: authorize_url.to_string(),
        redirect_uri: redirect_uri.clone(),
    });

    let (code, state) = loopback.wait().await?;

    if state.secret() != csrf_state.secret() {
        return Err(AuthFlowError::provider("authorization state mismatch"));
    }

    let http_client = build_http_client()?;

    let token = controller
        .run_with_deadline("pkce token exchange", controller.http_timeout(), async {
            client
                .exchange_code(code)
                .set_pkce_verifier(pkce_verifier)
                .request_async(&http_client)
                .await
                .map_err(|err| {
                    AuthFlowError::provider(format!("failed to exchange authorization code: {err}"))
                })
        })
        .await?;

    Ok(ExternalToken::new(
        token.access_token().secret().to_string(),
    ))
}
