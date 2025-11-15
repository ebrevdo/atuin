use serde_json::Value;

use crate::settings::AuthProvider;

use super::IdentityError;

pub(super) fn enforce_claim_filters(
    provider: &AuthProvider,
    claims: &Value,
) -> Result<(), IdentityError> {
    if let Some(expected) = provider
        .required_issuer
        .as_ref()
        .map(|s| s.as_str())
        .or_else(|| provider.issuer.as_ref().map(|issuer| issuer.url().as_str()))
    {
        let actual =
            claim_value_as_string(claims, "iss").ok_or_else(|| IdentityError::MissingClaim {
                provider: provider.name.clone(),
                claim: "iss".into(),
            })?;
        if actual != expected {
            return Err(IdentityError::ClaimRejected {
                provider: provider.name.clone(),
                claim: "iss".into(),
            });
        }
    }

    if !provider.required_audience.is_empty() {
        let audiences = claim_values(claims, "aud");
        if audiences.is_empty() {
            return Err(IdentityError::MissingClaim {
                provider: provider.name.clone(),
                claim: "aud".into(),
            });
        }

        let allowed = audiences.iter().any(|aud| {
            provider
                .required_audience
                .iter()
                .any(|required| required == aud)
        });

        if !allowed {
            return Err(IdentityError::ClaimRejected {
                provider: provider.name.clone(),
                claim: "aud".into(),
            });
        }
    }

    if let Some(expected_tenant) = &provider.required_tenant {
        let tenant = claim_value_as_string(claims, "tid")
            .or_else(|| claim_value_as_string(claims, "tenant"))
            .or_else(|| claim_value_as_string(claims, "tenant_id"));

        match tenant {
            Some(actual) if actual == *expected_tenant => {}
            Some(_) => {
                return Err(IdentityError::ClaimRejected {
                    provider: provider.name.clone(),
                    claim: "tenant".into(),
                });
            }
            None => {
                return Err(IdentityError::MissingClaim {
                    provider: provider.name.clone(),
                    claim: "tenant".into(),
                });
            }
        }
    }

    for (claim, expected_value) in &provider.required_claims {
        let actual =
            claim_value_as_string(claims, claim).ok_or_else(|| IdentityError::MissingClaim {
                provider: provider.name.clone(),
                claim: claim.clone(),
            })?;

        if &actual != expected_value {
            return Err(IdentityError::ClaimRejected {
                provider: provider.name.clone(),
                claim: claim.clone(),
            });
        }
    }

    Ok(())
}

fn claim_value_as_string(claims: &Value, key: &str) -> Option<String> {
    claims.get(key).and_then(claim_scalar_to_string)
}

fn claim_values(claims: &Value, key: &str) -> Vec<String> {
    match claims.get(key) {
        Some(Value::Array(items)) => items
            .iter()
            .filter_map(claim_scalar_to_string)
            .collect::<Vec<_>>(),
        Some(value) => claim_scalar_to_string(value)
            .map(|single| vec![single])
            .unwrap_or_default(),
        None => Vec::new(),
    }
}

fn claim_scalar_to_string(value: &Value) -> Option<String> {
    match value {
        Value::String(s) => Some(s.clone()),
        Value::Number(n) => Some(n.to_string()),
        Value::Bool(b) => Some(b.to_string()),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::{IdentityError, enforce_claim_filters};
    use crate::settings::{AuthFlow, AuthProvider, AuthProviderKind};
    use openidconnect::IssuerUrl;
    use serde_json::json;
    use std::collections::HashMap;

    fn mock_provider(issuer: &str) -> AuthProvider {
        AuthProvider {
            name: "test".into(),
            display_name: None,
            kind: AuthProviderKind::Oidc,
            issuer: Some(IssuerUrl::new(issuer.into()).unwrap()),
            authorization_endpoint: None,
            token_endpoint: None,
            device_authorization_endpoint: None,
            jwks_uri: None,
            userinfo_endpoint: None,
            client_id: Some("client".into()),
            client_secret: None,
            scopes: vec!["openid".into()],
            subject_claims: vec!["sub".into()],
            flows: vec![AuthFlow::DeviceCode],
            auto_provision: true,
            required_audience: Vec::new(),
            required_issuer: None,
            required_tenant: None,
            required_claims: HashMap::new(),
        }
    }

    #[test]
    fn claim_filters_accept_matching_claims() {
        let mut provider = mock_provider("https://issuer.example.com");
        provider.required_audience = vec!["api://example-app".into()];
        provider.required_tenant = Some("tenant-id".into());
        provider.required_claims = HashMap::from([(String::from("hd"), "example.com".into())]);

        let claims = json!({
            "iss": "https://issuer.example.com/",
            "aud": ["api://example-app", "extra"],
            "tid": "tenant-id",
            "hd": "example.com"
        });

        assert!(enforce_claim_filters(&provider, &claims).is_ok());
    }

    #[test]
    fn claim_filters_reject_unknown_audience() {
        let mut provider = mock_provider("https://issuer.example.com");
        provider.required_audience = vec!["api://expected".into()];

        let claims = json!({
            "iss": "https://issuer.example.com/",
            "aud": ["api://other"]
        });

        let err = enforce_claim_filters(&provider, &claims).expect_err("audience mismatch");
        assert!(matches!(err, IdentityError::ClaimRejected { ref claim, .. } if claim == "aud"));
    }
}
