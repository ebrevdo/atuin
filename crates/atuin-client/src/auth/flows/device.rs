use super::{
    AuthFlowError, DeviceFlowPrompt, ExternalToken, FlowController, FlowResult, ProviderConfig,
    ProviderKind, ProviderSelection,
};
use oauth2::{
    DeviceAuthorizationUrl, Scope, StandardDeviceAuthorizationResponse, TokenResponse, TokenUrl,
};
use tokio::time;

use super::{
    DeviceFlowConfig, build_http_client, build_oauth_client, build_oidc_client, normalize_scopes,
};

pub(super) async fn login_device_flow<F>(
    selection: &ProviderSelection,
    flow: &DeviceFlowConfig,
    notify: &F,
    controller: &FlowController,
) -> FlowResult<ExternalToken>
where
    F: Fn(&DeviceFlowPrompt),
{
    match selection.provider_kind() {
        ProviderKind::Oidc => {
            device_flow_oidc(selection.provider(), flow, notify, controller).await
        }
        ProviderKind::Oauth2 => {
            device_flow_oauth(selection.provider(), flow, notify, controller).await
        }
    }
}

async fn device_flow_oidc<F>(
    provider: &ProviderConfig,
    flow: &DeviceFlowConfig,
    notify: &F,
    controller: &FlowController,
) -> FlowResult<ExternalToken>
where
    F: Fn(&DeviceFlowPrompt),
{
    let client = build_oidc_client(provider)?;
    let token_url = TokenUrl::new(flow.token_endpoint.clone()).map_err(|err| {
        AuthFlowError::InvalidConfig(format!(
            "invalid token endpoint URL for provider '{}': {err}",
            provider.name
        ))
    })?;
    let device_url = DeviceAuthorizationUrl::new(flow.device_authorization_endpoint.clone())
        .map_err(|err| {
            AuthFlowError::InvalidConfig(format!(
                "invalid device endpoint URL for provider '{}': {err}",
                provider.name
            ))
        })?;

    let client = client
        .set_token_uri(token_url)
        .set_device_authorization_url(device_url);

    let scopes = normalize_scopes(provider);

    let http_client = build_http_client()?;

    let request = client
        .exchange_device_code()
        .add_scopes(scopes.iter().map(|scope| Scope::new(scope.clone())));

    let response: StandardDeviceAuthorizationResponse = controller
        .run_with_deadline("device authorization", controller.http_timeout(), async {
            request.request_async(&http_client).await.map_err(|err| {
                AuthFlowError::provider(format!("device authorization failed: {err}"))
            })
        })
        .await?;

    notify(&DeviceFlowPrompt {
        verification_uri: response.verification_uri().url().to_string(),
        verification_uri_complete: response
            .verification_uri_complete()
            .map(|uri| uri.secret().to_string()),
        user_code: response.user_code().secret().to_string(),
        expires_in: response.expires_in(),
    });

    let token = controller
        .run_with_deadline(
            "device token polling",
            controller.device_poll_timeout(),
            async {
                client
                    .exchange_device_access_token(&response)
                    .request_async(&http_client, |dur| time::sleep(dur), None)
                    .await
                    .map_err(|err| {
                        AuthFlowError::provider(format!("failed to poll token endpoint: {err}"))
                    })
            },
        )
        .await?;

    token
        .extra_fields()
        .id_token
        .clone()
        .map(ExternalToken::new)
        .ok_or_else(|| {
            AuthFlowError::provider(format!(
                "provider '{}' did not return an id_token",
                provider.name
            ))
        })
}

async fn device_flow_oauth<F>(
    provider: &ProviderConfig,
    flow: &DeviceFlowConfig,
    notify: &F,
    controller: &FlowController,
) -> FlowResult<ExternalToken>
where
    F: Fn(&DeviceFlowPrompt),
{
    let client = build_oauth_client(provider)?;
    let token_url = TokenUrl::new(flow.token_endpoint.clone()).map_err(|err| {
        AuthFlowError::InvalidConfig(format!(
            "invalid token endpoint URL for provider '{}': {err}",
            provider.name
        ))
    })?;
    let device_url = DeviceAuthorizationUrl::new(flow.device_authorization_endpoint.clone())
        .map_err(|err| {
            AuthFlowError::InvalidConfig(format!(
                "invalid device endpoint URL for provider '{}': {err}",
                provider.name
            ))
        })?;

    let client = client
        .set_token_uri(token_url)
        .set_device_authorization_url(device_url);

    let scopes = normalize_scopes(provider);

    let http_client = build_http_client()?;

    let request = client
        .exchange_device_code()
        .add_scopes(scopes.iter().map(|scope| Scope::new(scope.clone())));

    let response: StandardDeviceAuthorizationResponse = controller
        .run_with_deadline("device authorization", controller.http_timeout(), async {
            request.request_async(&http_client).await.map_err(|err| {
                AuthFlowError::provider(format!("device authorization failed: {err}"))
            })
        })
        .await?;

    notify(&DeviceFlowPrompt {
        verification_uri: response.verification_uri().url().to_string(),
        verification_uri_complete: response
            .verification_uri_complete()
            .map(|uri| uri.secret().to_string()),
        user_code: response.user_code().secret().to_string(),
        expires_in: response.expires_in(),
    });

    let token = controller
        .run_with_deadline(
            "device token polling",
            controller.device_poll_timeout(),
            async {
                client
                    .exchange_device_access_token(&response)
                    .request_async(&http_client, |dur| time::sleep(dur), None)
                    .await
                    .map_err(|err| {
                        AuthFlowError::provider(format!("failed to poll token endpoint: {err}"))
                    })
            },
        )
        .await?;

    Ok(ExternalToken::new(
        token.access_token().secret().to_string(),
    ))
}
