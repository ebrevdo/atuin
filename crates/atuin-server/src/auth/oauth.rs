use reqwest::Client as HttpClient;
use serde_json::Value;

use crate::settings::AuthProvider;

use super::{
    IdentityError,
    runtime::{ExternalIdentity, ResolvedProvider},
    validation,
};

pub(super) async fn verify_identity(
    provider: &AuthProvider,
    http: &HttpClient,
    token: &str,
) -> Result<ExternalIdentity, IdentityError> {
    let userinfo_endpoint =
        provider
            .userinfo_endpoint
            .clone()
            .ok_or_else(|| IdentityError::MissingField {
                provider: provider.name.clone(),
                field: "userinfo_endpoint",
            })?;

    let response = http
        .get(userinfo_endpoint)
        .bearer_auth(token)
        .send()
        .await
        .map_err(|error| IdentityError::UserinfoRequest {
            provider: provider.name.clone(),
            source: error,
        })?;

    if !response.status().is_success() {
        return Err(IdentityError::UserinfoStatus {
            provider: provider.name.clone(),
            status: response.status(),
        });
    }

    let body: Value = response
        .json()
        .await
        .map_err(|error| IdentityError::VerificationFailed {
            provider: provider.name.clone(),
            reason: format!("failed to parse userinfo response: {error}"),
        })?;

    validation::enforce_claim_filters(provider, &body)?;

    let subject_fields = provider
        .subject_claims
        .iter()
        .map(|claim| claim.as_str())
        .collect::<Vec<_>>();

    let subject =
        extract_field(&body, &subject_fields).ok_or_else(|| IdentityError::MissingSubject {
            provider: provider.name.clone(),
            claims: provider.subject_claims.clone(),
        })?;
    let username = extract_field(&body, &["preferred_username", "login", "username", "name"]);
    let email = extract_field(&body, &["email"]);

    Ok(ExternalIdentity {
        subject,
        username,
        email,
    })
}

pub(super) fn resolve_metadata(config: &AuthProvider) -> ResolvedProvider {
    let mut resolved = ResolvedProvider::new();
    resolved.authorization_endpoint = config
        .authorization_endpoint
        .as_ref()
        .map(|url| url.to_string());
    resolved.token_endpoint = config.token_endpoint.as_ref().map(|url| url.to_string());
    resolved.device_authorization_endpoint = config
        .device_authorization_endpoint
        .as_ref()
        .map(|url| url.to_string());
    resolved.userinfo_endpoint = config.userinfo_endpoint.as_ref().map(|url| url.to_string());
    resolved.jwks_uri = config.jwks_uri.as_ref().map(|url| url.to_string());
    resolved
}

fn extract_field(value: &Value, keys: &[&str]) -> Option<String> {
    for key in keys {
        if let Some(found) = value.get(key) {
            match found {
                Value::String(s) if !s.is_empty() => return Some(s.clone()),
                Value::Number(n) => return Some(n.to_string()),
                Value::Bool(b) => return Some(b.to_string()),
                _ => continue,
            }
        }
    }

    None
}

#[cfg(test)]
mod tests {
    use super::extract_field;
    use serde_json::json;

    #[test]
    fn extract_field_returns_first_matching_entry() {
        let body = json!({
            "preferred_username": "alice",
            "login": "alice-gh",
            "email": "alice@example.com"
        });

        assert_eq!(
            extract_field(&body, &["login", "preferred_username"]),
            Some("alice-gh".into())
        );

        assert_eq!(
            extract_field(&body, &["missing", "email"]),
            Some("alice@example.com".into())
        );

        assert_eq!(extract_field(&body, &["unknown"]), None);
    }
}
