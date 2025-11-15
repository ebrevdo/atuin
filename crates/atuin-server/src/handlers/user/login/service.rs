use rand::{Rng, distributions::Alphanumeric};
use serde_json::Value;
use sha2::{Digest, Sha256};
use std::{collections::HashSet, fmt};
use tracing::{Span, debug, error};

use atuin_common::{
    api::{AuthMethod, LoginRequest},
    utils::crypto_random_string,
};
use atuin_server_database::{
    Database, DbError,
    models::{ExternalIdentity as DbExternalIdentity, NewExternalIdentity, NewSession, NewUser},
};

use crate::{
    auth::{ExternalIdentity, IdentityError},
    router::AppState,
    settings::{AuthProvider, AuthProviderKind},
};

use crate::handlers::user::{hash_secret, verify_str};

#[derive(Debug, Clone)]
pub(super) struct LoginSuccess {
    pub session: String,
    pub auth_method: AuthMethod,
}

#[derive(Debug)]
pub(super) enum LoginError {
    PasswordLoginDisabled,
    UserNotFound,
    PasswordIncorrect,
    ProviderNotEnabled,
    IdentityVerification(IdentityError),
    UsernameDerivationFailed,
    IdentityNotLinked,
    IdentityBindingInvalid,
    Database,
    SessionLoad,
    SessionCreate,
    Provisioning,
}

pub(super) async fn handle_login<DB: Database>(
    state: &AppState<DB>,
    login: LoginRequest,
) -> Result<LoginSuccess, LoginError> {
    let span = Span::current();

    match login {
        LoginRequest::Password { username, password } => {
            span.record("auth.method", &tracing::field::display("password"));
            if !state.auth.allow_password() {
                return Err(LoginError::PasswordLoginDisabled);
            }

            password_login(state, username, password).await
        }
        LoginRequest::Oidc {
            provider,
            token,
            nonce,
        } => {
            span.record("auth.method", &tracing::field::display("oidc"));
            span.record("auth.provider", &tracing::field::display(&provider));
            oidc_login(state, provider, token, nonce).await
        }
        LoginRequest::Oauth { provider, token } => {
            span.record("auth.method", &tracing::field::display("oauth"));
            span.record("auth.provider", &tracing::field::display(&provider));
            oidc_login(state, provider, token, None).await
        }
    }
}

pub(super) async fn password_login<DB: Database>(
    state: &AppState<DB>,
    username: String,
    password: String,
) -> Result<LoginSuccess, LoginError> {
    let db = &state.database;
    let user = match db.get_user(username.as_str()).await {
        Ok(u) => u,
        Err(DbError::NotFound) => {
            return Err(LoginError::UserNotFound);
        }
        Err(DbError::Other(e)) => {
            error!("failed to get user {}: {}", username, e);

            return Err(LoginError::Database);
        }
    };
    Span::current().record("user.id", &tracing::field::display(user.id));

    let verified = verify_str(user.password.as_str(), password.as_str());

    if !verified {
        debug!(user_id = user.id, "login failed");
        return Err(LoginError::PasswordIncorrect);
    }

    debug!(user_id = user.id, "login success");

    Span::current().record("user.id", &tracing::field::display(user.id));

    let session_token = ensure_session(db, &user).await?;

    Ok(LoginSuccess {
        session: session_token,
        auth_method: AuthMethod::Password,
    })
}

async fn oidc_login<DB: Database>(
    state: &AppState<DB>,
    provider: String,
    token: String,
    nonce: Option<String>,
) -> Result<LoginSuccess, LoginError> {
    let provider_cfg = state
        .settings
        .auth
        .provider(provider.as_str())
        .ok_or(LoginError::ProviderNotEnabled)?;

    let identity = state
        .auth
        .verify_identity(&provider, &token, nonce.as_deref())
        .await
        .map_err(|err| {
            error!(error = ?err, provider = provider, "external identity verification failed");
            LoginError::IdentityVerification(err)
        })?;

    let db = &state.database;
    let candidates = if provider_cfg.auto_provision {
        let derived = username_candidates(provider_cfg, &identity);
        if derived.is_empty() {
            return Err(LoginError::UsernameDerivationFailed);
        }

        Some(derived)
    } else {
        None
    };

    let user = match db
        .get_external_identity(provider_cfg.name.as_str(), &identity.subject)
        .await
    {
        Ok(binding) => match db.get_user_by_id(binding.user_id).await {
            Ok(user) => user,
            Err(DbError::NotFound) => {
                error!(
                    provider = provider,
                    user_id = binding.user_id,
                    identity = %IdentityLogInfo::from_binding(&binding),
                    "external identity points to missing user"
                );
                return Err(LoginError::IdentityBindingInvalid);
            }
            Err(DbError::Other(e)) => {
                error!(
                    error = ?e,
                    provider = provider,
                    identity = %IdentityLogInfo::from_binding(&binding),
                    "failed to load bound user"
                );
                return Err(LoginError::Database);
            }
        },
        Err(DbError::NotFound) => {
            if !provider_cfg.auto_provision {
                return Err(LoginError::IdentityNotLinked);
            }

            let candidates = candidates.as_ref().expect("candidates computed");
            let user = provision_external_user(db, provider_cfg, &identity, &candidates[0]).await?;

            let snapshot = identity_display_claims(&identity);
            let new_identity = NewExternalIdentity {
                user_id: user.id,
                provider: provider_cfg.name.clone(),
                subject: identity.subject.clone(),
                display_claims: snapshot,
            };

            if let Err(error) = db.link_external_identity(&new_identity).await {
                error!(
                    error = ?error,
                    provider = provider,
                    identity = %IdentityLogInfo::from_verified(&identity),
                    "failed to persist identity binding"
                );
                let _ = db.delete_user(&user).await;
                return Err(LoginError::Provisioning);
            }

            user
        }
        Err(DbError::Other(error)) => {
            error!(
                error = ?error,
                provider = provider,
                identity = %IdentityLogInfo::from_verified(&identity),
                "database error during identity lookup"
            );
            return Err(LoginError::Database);
        }
    };

    let session_token = ensure_session(db, &user).await?;

    let auth_method = match provider_cfg.kind {
        AuthProviderKind::Oidc => AuthMethod::Oidc {
            provider: provider.clone(),
        },
        AuthProviderKind::Oauth2 => AuthMethod::Oauth {
            provider: provider.clone(),
        },
    };

    Ok(LoginSuccess {
        session: session_token,
        auth_method,
    })
}

async fn ensure_session<DB: Database>(
    db: &DB,
    user: &atuin_server_database::models::User,
) -> Result<String, LoginError> {
    match db.get_user_session(user).await {
        Ok(session) => return Ok(session.token),
        Err(DbError::NotFound) => {}
        Err(error) => {
            error!(error = ?error, user_id = user.id, "failed to load existing session");
            return Err(LoginError::SessionLoad);
        }
    }

    let token = crypto_random_string::<24>();
    let new_session = NewSession {
        user_id: user.id,
        token: token.clone(),
    };

    match db.add_session(&new_session).await {
        Ok(()) => Ok(token),
        Err(error) => {
            error!(error = ?error, user_id = user.id, "failed to create session");

            if let Ok(session) = db.get_user_session(user).await {
                debug!(
                    user_id = user.id,
                    "session likely created concurrently; reusing token"
                );
                return Ok(session.token);
            }

            Err(LoginError::SessionCreate)
        }
    }
}

async fn provision_external_user<DB: Database>(
    db: &DB,
    provider: &AuthProvider,
    identity: &ExternalIdentity,
    username: &str,
) -> Result<atuin_server_database::models::User, LoginError> {
    let email = identity
        .email
        .clone()
        .unwrap_or_else(|| fallback_email(username, provider));

    let password = random_password();
    let hashed = hash_secret(&password).map_err(|error| {
        error!(error = ?error, provider = provider.name, "failed to hash password");
        LoginError::Provisioning
    })?;

    let new_user = NewUser {
        username: username.to_string(),
        email,
        password: hashed,
    };

    let user_id = db.add_user(&new_user).await.map_err(|e| {
        error!(error = ?e, username, provider = provider.name, "failed to add user");
        LoginError::Provisioning
    })?;

    let token = crypto_random_string::<24>();
    let new_session = NewSession {
        user_id,
        token: token.clone(),
    };

    db.add_session(&new_session).await.map_err(|e| {
        error!(error = ?e, user_id, "failed to add session for provisioned user");
        LoginError::Provisioning
    })?;

    db.get_user(username).await.map_err(|e| {
        error!(error = ?e, username, "failed to fetch provisioned user");
        LoginError::Provisioning
    })
}

pub(super) fn username_candidates(
    provider: &AuthProvider,
    identity: &ExternalIdentity,
) -> Vec<String> {
    let mut seen = HashSet::new();
    [
        identity.username.as_deref().and_then(sanitize_username),
        identity
            .email
            .as_deref()
            .map(|email| {
                email
                    .split_once('@')
                    .map(|(local, _)| local)
                    .unwrap_or(email)
            })
            .and_then(sanitize_username),
        sanitize_username(&format!("{}-{}", provider.name, identity.subject)),
    ]
    .into_iter()
    .flatten()
    .filter(|value| seen.insert(value.clone()))
    .collect()
}

pub(super) fn sanitize_username(input: &str) -> Option<String> {
    let sanitized: String = input
        .chars()
        .filter(|c| matches!(c, 'a'..='z' | 'A'..='Z' | '0'..='9' | '-'))
        .take(64)
        .collect();

    if sanitized.is_empty() {
        None
    } else {
        Some(sanitized)
    }
}

pub(super) fn fallback_email(username: &str, provider: &AuthProvider) -> String {
    let suffix: String = provider
        .name
        .chars()
        .map(|c| if c.is_ascii_alphanumeric() { c } else { '-' })
        .collect();

    format!("{username}@{suffix}.oidc.local")
}

// Generates a placeholder credential for auto-provisioned users; never shown to humans.
fn random_password() -> String {
    rand::thread_rng()
        .sample_iter(&Alphanumeric)
        .take(32)
        .map(char::from)
        .collect()
}

// Captures optional username/email purely for operator UX; never influences auth decisions.
fn identity_display_claims(identity: &ExternalIdentity) -> Option<Value> {
    if identity.username.is_none() && identity.email.is_none() {
        return None;
    }

    let mut map = serde_json::Map::new();
    if let Some(username) = &identity.username {
        map.insert("username".to_string(), Value::String(username.clone()));
    }
    if let Some(email) = &identity.email {
        map.insert("email".to_string(), Value::String(email.clone()));
    }

    Some(Value::Object(map))
}

const SUBJECT_HASH_BYTES: usize = 6;

fn subject_hash(subject: &str) -> String {
    use std::fmt::Write as _;

    let mut hasher = Sha256::new();
    hasher.update(subject.as_bytes());
    let digest = hasher.finalize();

    let mut short = String::with_capacity(SUBJECT_HASH_BYTES * 2);
    for byte in digest.iter().take(SUBJECT_HASH_BYTES) {
        write!(&mut short, "{byte:02x}").expect("format digest");
    }

    format!("sha256:{short}")
}

fn clean_claim_ref(value: Option<&str>) -> Option<String> {
    value.and_then(|val| {
        let trimmed = val.trim();
        if trimmed.is_empty() {
            None
        } else {
            Some(trimmed.to_owned())
        }
    })
}

fn clean_claim_owned(value: Option<String>) -> Option<String> {
    value.and_then(|val| {
        let trimmed = val.trim();
        if trimmed.is_empty() {
            None
        } else if trimmed.len() == val.len() {
            Some(val)
        } else {
            Some(trimmed.to_owned())
        }
    })
}

fn parse_display_claims(raw: Option<&Value>) -> (Option<String>, Option<String>) {
    let Some(Value::Object(map)) = raw else {
        return (None, None);
    };

    let username = map
        .get("username")
        .and_then(|v| v.as_str())
        .map(|s| s.to_owned());
    let email = map
        .get("email")
        .and_then(|v| v.as_str())
        .map(|s| s.to_owned());

    (clean_claim_owned(username), clean_claim_owned(email))
}

pub(super) struct IdentityLogInfo {
    username: Option<String>,
    email: Option<String>,
    subject_hash: String,
}

impl IdentityLogInfo {
    pub(super) fn from_verified(identity: &ExternalIdentity) -> Self {
        Self {
            username: clean_claim_ref(identity.username.as_deref()),
            email: clean_claim_ref(identity.email.as_deref()),
            subject_hash: subject_hash(&identity.subject),
        }
    }

    pub(super) fn from_binding(binding: &DbExternalIdentity) -> Self {
        let (username, email) = parse_display_claims(binding.display_claims.as_ref());

        Self {
            username,
            email,
            subject_hash: subject_hash(&binding.subject),
        }
    }
}

impl fmt::Display for IdentityLogInfo {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let mut wrote = false;

        if let Some(username) = &self.username {
            write!(f, "username={username}")?;
            wrote = true;
        }

        if let Some(email) = &self.email {
            if wrote {
                write!(f, ", ")?;
            }
            write!(f, "email={email}")?;
            wrote = true;
        }

        if wrote {
            write!(f, ", ")?;
        }

        write!(f, "subject={}", self.subject_hash)
    }
}
