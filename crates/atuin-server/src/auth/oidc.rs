use openidconnect::{
    AdditionalProviderMetadata, ClientId, DeviceAuthorizationUrl, Nonce, ProviderMetadata,
    core::{
        CoreAuthDisplay, CoreClaimName, CoreClaimType, CoreClientAuthMethod, CoreGrantType,
        CoreIdToken, CoreIdTokenVerifier, CoreJsonWebKey, CoreJweContentEncryptionAlgorithm,
        CoreJweKeyManagementAlgorithm, CoreResponseMode, CoreResponseType,
        CoreSubjectIdentifierType,
    },
};
use reqwest::Client as OidcHttpClient;

use crate::settings::{AuthFlow, AuthProvider};

use super::{
    IdentityError,
    error::MetadataError,
    runtime::{ExternalIdentity, ResolvedProvider},
    validation,
};

#[derive(Clone, Debug, Default, serde::Deserialize, serde::Serialize)]
struct ProviderMetadataExtras {
    #[serde(default, rename = "device_authorization_endpoint")]
    device_authorization_endpoint: Option<DeviceAuthorizationUrl>,
}

impl AdditionalProviderMetadata for ProviderMetadataExtras {}

type DeviceAwareProviderMetadata = ProviderMetadata<
    ProviderMetadataExtras,
    CoreAuthDisplay,
    CoreClientAuthMethod,
    CoreClaimName,
    CoreClaimType,
    CoreGrantType,
    CoreJweContentEncryptionAlgorithm,
    CoreJweKeyManagementAlgorithm,
    CoreJsonWebKey,
    CoreResponseMode,
    CoreResponseType,
    CoreSubjectIdentifierType,
>;

pub(super) async fn resolve_metadata(
    config: &AuthProvider,
    client: &OidcHttpClient,
) -> Result<ResolvedProvider, MetadataError> {
    let issuer = config
        .issuer
        .clone()
        .ok_or_else(|| MetadataError::MissingIssuer {
            provider: config.name.clone(),
        })?;
    let issuer_url = issuer.clone();

    let provider_metadata = DeviceAwareProviderMetadata::discover_async(issuer_url.clone(), client)
        .await
        .map_err(|error| MetadataError::Discovery {
            provider: config.name.clone(),
            source: error,
        })?;

    let jwks = provider_metadata.jwks().clone();

    let authorization_endpoint = Some(provider_metadata.authorization_endpoint().url().to_string());
    let token_endpoint = provider_metadata
        .token_endpoint()
        .map(|url| url.url().to_string());
    let userinfo_endpoint = provider_metadata
        .userinfo_endpoint()
        .map(|url| url.url().to_string());
    let jwks_uri = Some(provider_metadata.jwks_uri().url().to_string());
    let discovered_device = provider_metadata
        .additional_metadata()
        .device_authorization_endpoint
        .as_ref()
        .map(|url| url.to_string());
    let device_authorization_endpoint = config
        .device_authorization_endpoint
        .as_ref()
        .map(|url| url.to_string())
        .or(discovered_device);

    if config
        .flows
        .iter()
        .any(|flow| matches!(flow, AuthFlow::DeviceCode))
        && device_authorization_endpoint.is_none()
    {
        return Err(MetadataError::MissingDeviceEndpoint {
            provider: config.name.clone(),
        });
    }

    Ok(ResolvedProvider {
        issuer: Some(issuer_url),
        authorization_endpoint,
        token_endpoint,
        device_authorization_endpoint,
        userinfo_endpoint,
        jwks_uri,
        jwks: Some(jwks),
        fetched_at: std::time::Instant::now(),
    })
}

pub(super) fn verify_identity(
    provider: &AuthProvider,
    resolved: &ResolvedProvider,
    token: &str,
    nonce: Option<&str>,
) -> Result<ExternalIdentity, IdentityError> {
    let jwks = resolved
        .jwks
        .clone()
        .ok_or_else(|| IdentityError::MissingField {
            provider: provider.name.clone(),
            field: "jwks",
        })?;
    let issuer = resolved
        .issuer
        .clone()
        .ok_or_else(|| IdentityError::MissingField {
            provider: provider.name.clone(),
            field: "issuer",
        })?;
    let client_id = provider
        .client_id
        .as_ref()
        .ok_or_else(|| IdentityError::MissingField {
            provider: provider.name.clone(),
            field: "client_id",
        })?
        .clone();

    let id_token: CoreIdToken = token
        .parse()
        .map_err(|e| IdentityError::VerificationFailed {
            provider: provider.name.clone(),
            reason: format!("invalid id token: {e}"),
        })?;

    let verifier = CoreIdTokenVerifier::new_public_client(ClientId::new(client_id), issuer, jwks);

    let expected_nonce = nonce.map(|value| Nonce::new(value.to_string()));
    let claims = match expected_nonce {
        Some(ref nonce) => id_token.claims(&verifier, nonce),
        None => id_token.claims(&verifier, |_: Option<&Nonce>| Ok(())),
    }
    .map_err(|e| IdentityError::VerificationFailed {
        provider: provider.name.clone(),
        reason: format!("failed to verify id token: {e}"),
    })?;

    let raw_claims =
        serde_json::to_value(&claims).map_err(|error| IdentityError::VerificationFailed {
            provider: provider.name.clone(),
            reason: format!("failed to serialize id token claims: {error}"),
        })?;
    validation::enforce_claim_filters(provider, &raw_claims)?;

    let subject = claims.subject().to_string();
    let username = claims.preferred_username().map(|u| u.to_string());
    let email = claims.email().map(|e| e.to_string());

    Ok(ExternalIdentity {
        subject,
        username,
        email,
    })
}
