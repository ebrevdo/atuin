use lazy_static::lazy_static;
use semver::Version;
use serde::de::Error as DeError;
use serde::{Deserialize, Deserializer, Serialize};
use std::borrow::Cow;
use time::OffsetDateTime;

// the usage of X- has been deprecated for quite along time, it turns out
pub static ATUIN_HEADER_VERSION: &str = "Atuin-Version";
pub static ATUIN_CARGO_VERSION: &str = env!("CARGO_PKG_VERSION");

lazy_static! {
    pub static ref ATUIN_VERSION: Version =
        Version::parse(ATUIN_CARGO_VERSION).expect("failed to parse self semver");
}

pub const AUTH_FLOW_DEVICE_CODE: &str = "device_code";
pub const AUTH_FLOW_AUTH_CODE_PKCE: &str = "auth_code_pkce";

#[derive(Debug, Serialize, Deserialize)]
pub struct UserResponse {
    pub username: String,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct RegisterRequest {
    pub email: String,
    pub username: String,
    pub password: String,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct RegisterResponse {
    pub session: String,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct DeleteUserResponse {}

#[derive(Debug, Serialize, Deserialize)]
pub struct SendVerificationResponse {
    pub email_sent: bool,
    pub verified: bool,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct VerificationTokenRequest {
    pub token: String,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct VerificationTokenResponse {
    pub verified: bool,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct ChangePasswordRequest {
    pub current_password: String,
    pub new_password: String,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct ChangePasswordResponse {}

#[derive(Debug, Serialize)]
#[serde(tag = "type", rename_all = "lowercase")]
pub enum LoginRequest {
    Password {
        username: String,
        password: String,
    },
    Oidc {
        provider: String,
        token: String,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        nonce: Option<String>,
    },
    Oauth {
        provider: String,
        token: String,
    },
}

impl<'de> Deserialize<'de> for LoginRequest {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        #[derive(Deserialize)]
        #[serde(tag = "type", rename_all = "lowercase")]
        enum Tagged {
            Password {
                username: String,
                password: String,
            },
            Oidc {
                provider: String,
                token: String,
                #[serde(default)]
                nonce: Option<String>,
            },
            Oauth {
                provider: String,
                token: String,
            },
        }

        #[derive(Deserialize)]
        struct Legacy {
            username: String,
            password: String,
        }

        #[derive(Deserialize)]
        #[serde(untagged)]
        enum Helper {
            Tagged(Tagged),
            Legacy(Legacy),
        }

        match Helper::deserialize(deserializer)? {
            Helper::Tagged(Tagged::Password { username, password })
            | Helper::Legacy(Legacy { username, password }) => {
                Ok(LoginRequest::Password { username, password })
            }
            Helper::Tagged(Tagged::Oidc {
                provider,
                token,
                nonce,
            }) => Ok(LoginRequest::Oidc {
                provider,
                token,
                nonce,
            }),
            Helper::Tagged(Tagged::Oauth { provider, token }) => {
                Ok(LoginRequest::Oauth { provider, token })
            }
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(tag = "type", rename_all = "lowercase")]
pub enum AuthMethod {
    Password,
    Oidc { provider: String },
    Oauth { provider: String },
}

impl<'de> Deserialize<'de> for AuthMethod {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        #[derive(Deserialize)]
        #[serde(tag = "type", rename_all = "lowercase")]
        enum Tagged {
            Password,
            Oidc { provider: String },
            Oauth { provider: String },
        }

        #[derive(Deserialize)]
        #[serde(untagged)]
        enum Helper {
            Tagged(Tagged),
            Legacy(String),
        }

        match Helper::deserialize(deserializer)? {
            Helper::Tagged(Tagged::Password) => Ok(AuthMethod::Password),
            Helper::Tagged(Tagged::Oidc { provider }) => Ok(AuthMethod::Oidc { provider }),
            Helper::Tagged(Tagged::Oauth { provider }) => Ok(AuthMethod::Oauth { provider }),
            Helper::Legacy(value) => AuthMethod::from_legacy(value).map_err(DeError::custom),
        }
    }
}

impl AuthMethod {
    fn from_legacy(value: String) -> Result<Self, String> {
        if value.eq_ignore_ascii_case("password") {
            return Ok(AuthMethod::Password);
        }

        let (kind, provider) = value
            .split_once(':')
            .ok_or_else(|| format!("invalid legacy auth_method '{value}'"))?;

        if provider.is_empty() {
            return Err(format!("legacy auth_method '{value}' is missing provider"));
        }

        match kind {
            "oidc" => Ok(AuthMethod::Oidc {
                provider: provider.to_string(),
            }),
            "oauth" | "oauth2" => Ok(AuthMethod::Oauth {
                provider: provider.to_string(),
            }),
            other => Err(format!("legacy auth_method kind '{other}' unsupported")),
        }
    }
}

#[derive(Debug, Serialize, Deserialize)]
pub struct LoginResponse {
    pub session: String,
    #[serde(default = "default_auth_method")]
    pub auth_method: AuthMethod,
}

fn default_auth_method() -> AuthMethod {
    AuthMethod::Password
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn login_request_deserializes_legacy_payload() {
        let json = json!({
            "username": "alice",
            "password": "secret"
        });

        let request: LoginRequest = serde_json::from_value(json).expect("legacy request parses");

        match request {
            LoginRequest::Password { username, password } => {
                assert_eq!(username, "alice");
                assert_eq!(password, "secret");
            }
            _ => panic!("legacy payload should map to password request"),
        }
    }

    #[test]
    fn login_request_serializes_nonce_only_when_present() {
        let request = LoginRequest::Oidc {
            provider: "demo".into(),
            token: "token".into(),
            nonce: Some("nonce".into()),
        };

        let value = serde_json::to_value(&request).expect("serialize");
        assert_eq!(value["nonce"], "nonce");

        let request = LoginRequest::Oidc {
            provider: "demo".into(),
            token: "token".into(),
            nonce: None,
        };

        let value = serde_json::to_value(&request).expect("serialize");
        assert!(value.get("nonce").is_none());
    }

    #[test]
    fn login_request_oauth_roundtrips() {
        let request = LoginRequest::Oauth {
            provider: "github".into(),
            token: "token".into(),
        };

        let json = serde_json::to_value(&request).expect("serialize oauth");

        assert_eq!(json["type"], "oauth");
        assert_eq!(json["provider"], "github");
        assert_eq!(json["token"], "token");

        let back: LoginRequest = serde_json::from_value(json).expect("deserialize oauth");
        match back {
            LoginRequest::Oauth { provider, token } => {
                assert_eq!(provider, "github");
                assert_eq!(token, "token");
            }
            _ => panic!("roundtrip should yield oauth variant"),
        }
    }

    #[test]
    fn login_response_defaults_auth_method_when_missing() {
        let json = json!({
            "session": "token123"
        });

        let response: LoginResponse = serde_json::from_value(json).expect("response parses");

        assert_eq!(response.session, "token123");
        assert_eq!(response.auth_method, AuthMethod::Password);
    }

    #[test]
    fn login_response_preserves_explicit_auth_method() {
        let json = json!({
            "session": "token456",
            "auth_method": {
                "type": "oidc",
                "provider": "azure"
            }
        });

        let response: LoginResponse = serde_json::from_value(json).expect("response parses");

        assert_eq!(response.session, "token456");
        assert_eq!(
            response.auth_method,
            AuthMethod::Oidc {
                provider: "azure".into()
            }
        );
    }

    #[test]
    fn login_response_accepts_legacy_auth_method_string() {
        let json = json!({
            "session": "token789",
            "auth_method": "oauth:github"
        });

        let response: LoginResponse = serde_json::from_value(json).expect("response parses");

        assert_eq!(response.session, "token789");
        assert_eq!(
            response.auth_method,
            AuthMethod::Oauth {
                provider: "github".into()
            }
        );
    }

    #[test]
    fn auth_method_serializes_with_tag() {
        let response = LoginResponse {
            session: "session".into(),
            auth_method: AuthMethod::Oidc {
                provider: "example".into(),
            },
        };

        let json = serde_json::to_value(&response).expect("serialize response");

        assert_eq!(json["auth_method"]["type"], "oidc");
        assert_eq!(json["auth_method"]["provider"], "example");
    }

    #[test]
    fn login_request_rejects_unknown_type() {
        let json = json!({
            "type": "saml",
            "username": "ignored"
        });

        assert!(serde_json::from_value::<LoginRequest>(json).is_err());
    }

    #[test]
    fn auth_method_rejects_unknown_tag() {
        let json = json!({
            "type": "totp"
        });

        assert!(serde_json::from_value::<AuthMethod>(json).is_err());
    }
}

#[derive(Debug, Serialize, Deserialize)]
pub struct AddHistoryRequest {
    pub id: String,
    #[serde(with = "time::serde::rfc3339")]
    pub timestamp: OffsetDateTime,
    pub data: String,
    pub hostname: String,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct CountResponse {
    pub count: i64,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct SyncHistoryRequest {
    #[serde(with = "time::serde::rfc3339")]
    pub sync_ts: OffsetDateTime,
    #[serde(with = "time::serde::rfc3339")]
    pub history_ts: OffsetDateTime,
    pub host: String,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct SyncHistoryResponse {
    pub history: Vec<String>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct ErrorResponse<'a> {
    pub reason: Cow<'a, str>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct IndexResponse {
    pub homage: String,
    pub version: String,
    pub total_history: i64,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct StatusResponse {
    pub count: i64,
    pub username: String,
    pub deleted: Vec<String>,

    // These could/should also go on the index of the server
    // However, we do not request the server index as a part of normal sync
    // I'd rather slightly increase the size of this response, than add an extra HTTP request
    pub page_size: i64, // max page size supported by the server
    pub version: String,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct DeleteHistoryRequest {
    pub client_id: String,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct MessageResponse {
    pub message: String,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct MeResponse {
    pub username: String,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct AuthProvidersResponse {
    pub allow_password: bool,
    pub default_provider: Option<String>,
    pub providers: Vec<AuthProviderPublic>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct AuthProviderPublic {
    pub name: String,
    pub display_name: Option<String>,
    pub kind: String,
    pub flows: Vec<String>,
    pub scopes: Vec<String>,
    pub issuer: Option<String>,
    pub authorization_endpoint: Option<String>,
    pub token_endpoint: Option<String>,
    pub device_authorization_endpoint: Option<String>,
    pub userinfo_endpoint: Option<String>,
    pub jwks_uri: Option<String>,
    pub client_id: Option<String>,
}
