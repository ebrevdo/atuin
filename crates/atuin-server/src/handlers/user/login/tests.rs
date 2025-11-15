use super::login;
use super::service::{
    IdentityLogInfo, fallback_email, password_login, sanitize_username, username_candidates,
};
use crate::auth::{AuthRuntime, ExternalIdentity};
use crate::handlers::user::hash_secret;
use crate::router::AppState;
use crate::settings::{
    AuthFlow, AuthProvider, AuthProviderKind, AuthSettings, Mail, Metrics, Settings, Tls,
};
use async_trait::async_trait;
use atuin_common::{
    api::{AuthMethod, LoginRequest},
    record::{EncryptedData, HostId, Record, RecordIdx, RecordStatus},
};
use atuin_server_database::{
    Database, DbError, DbResult, DbSettings,
    calendar::{TimePeriod, TimePeriodInfo},
    models::{
        ExternalIdentity as DbExternalIdentity, History, NewExternalIdentity, NewHistory,
        NewSession, NewUser, Session, User,
    },
};
use atuin_server_sqlite::Sqlite;
use auth_test_support::MockUserinfoServer;
use axum::{Json, http::StatusCode};
use eyre::eyre;
use openidconnect::IssuerUrl;
use serde_json::json;
use std::{collections::HashMap, sync::Arc};
use time::{OffsetDateTime, UtcOffset};
use tokio::sync::Mutex;
use url::Url;

fn sample_provider(name: &str) -> AuthProvider {
    AuthProvider {
        name: name.into(),
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
        subject_claims: vec!["sub".into(), "id".into(), "user_id".into()],
        flows: vec![AuthFlow::DeviceCode],
        auto_provision: true,
        required_audience: Vec::new(),
        required_issuer: None,
        required_tenant: None,
        required_claims: HashMap::new(),
    }
}

fn mock_oauth_provider(base: &str, auto_provision: bool) -> AuthProvider {
    AuthProvider {
        name: "mock-oauth".into(),
        display_name: Some("Mock OAuth".into()),
        kind: AuthProviderKind::Oauth2,
        issuer: None,
        authorization_endpoint: Some(Url::parse("https://example.com/authorize").unwrap()),
        token_endpoint: Some(Url::parse("https://example.com/token").unwrap()),
        device_authorization_endpoint: None,
        jwks_uri: None,
        userinfo_endpoint: Some(Url::parse(&format!("{base}/userinfo")).unwrap()),
        client_id: Some("test-client".into()),
        client_secret: None,
        scopes: vec!["profile".into()],
        subject_claims: vec!["sub".into(), "id".into(), "user_id".into()],
        flows: vec![AuthFlow::AuthCodePkce],
        auto_provision,
        required_audience: Vec::new(),
        required_issuer: None,
        required_tenant: None,
        required_claims: HashMap::new(),
    }
}

fn identity(subject: &str, username: Option<&str>, email: Option<&str>) -> ExternalIdentity {
    ExternalIdentity {
        subject: subject.into(),
        username: username.map(|s| s.to_string()),
        email: email.map(|s| s.to_string()),
    }
}

#[test]
fn identity_log_includes_display_claims_and_hash() {
    let identity = identity(
        "super-secret",
        Some("Display-Name"),
        Some("user@example.com"),
    );
    let label = IdentityLogInfo::from_verified(&identity).to_string();

    assert!(label.contains("username=Display-Name"));
    assert!(label.contains("email=user@example.com"));
    assert!(label.contains("subject=sha256:"));
    assert!(
        !label.contains("super-secret"),
        "raw subject should never appear in logs"
    );
}

#[test]
fn stored_identity_log_uses_saved_claims() {
    let binding = DbExternalIdentity {
        id: 1,
        user_id: 99,
        provider: "mock".into(),
        subject: "raw-bound-subject".into(),
        display_claims: Some(json!({
            "username": "BoundUser",
            "email": "bound@example.com"
        })),
        created_at: OffsetDateTime::now_utc(),
        updated_at: OffsetDateTime::now_utc(),
    };

    let label = IdentityLogInfo::from_binding(&binding).to_string();

    assert!(label.contains("username=BoundUser"));
    assert!(label.contains("email=bound@example.com"));
    assert!(label.contains("subject=sha256:"));
    assert!(
        !label.contains("raw-bound-subject"),
        "raw subject should never appear in logs"
    );
}

#[test]
fn username_candidates_prefers_identity_fields() {
    let provider = sample_provider("azure-ad");
    let identity = identity("abc123", Some("Foo-Bar"), Some("alias@example.com"));

    let candidates = username_candidates(&provider, &identity);

    assert_eq!(
        candidates,
        vec![
            "Foo-Bar".to_string(),
            "alias".to_string(),
            "azure-ad-abc123".to_string()
        ]
    );
}

#[test]
fn username_candidates_dedupes_and_sanitizes() {
    let provider = sample_provider("oidc/provider");
    let identity = identity(
        "sub??",
        Some("bad!!!name!!!"),
        Some("bad!!!name!!!@example.com"),
    );

    let candidates = username_candidates(&provider, &identity);

    // bad!!!name!!! is sanitized to badname
    assert_eq!(
        candidates,
        vec!["badname".to_string(), "oidcprovider-sub".to_string()]
    );
}

#[test]
fn sanitize_username_handles_invalid_bytes() {
    assert_eq!(sanitize_username("abc-123"), Some("abc-123".into()));
    assert_eq!(sanitize_username(""), None);
    assert_eq!(sanitize_username("@@@"), None);
    assert_eq!(sanitize_username("hello world!"), Some("helloworld".into()));
    assert_eq!(sanitize_username("with.dots"), Some("withdots".into()));
    assert_eq!(
        sanitize_username("with_underscores"),
        Some("withunderscores".into())
    );
}

#[test]
fn fallback_email_masks_provider_name() {
    let provider = sample_provider("oidc/provider");
    let address = fallback_email("user", &provider);
    assert_eq!(address, "user@oidc-provider.oidc.local");
}

#[tokio::test]
async fn password_login_reuses_existing_session() {
    let auth_settings = AuthSettings {
        allow_password: true,
        default_provider: None,
        providers: vec![],
        cache_dir: None,
        cache_max_bytes: None,
    };

    let db_settings = DbSettings {
        db_uri: "sqlite://:memory:?cache=shared".into(),
    };

    let settings = Settings {
        host: "127.0.0.1".into(),
        port: 0,
        path: String::new(),
        open_registration: true,
        max_history_length: 8192,
        max_record_size: 1024 * 1024,
        page_size: 1000,
        register_webhook_url: None,
        register_webhook_username: String::new(),
        metrics: Metrics::default(),
        tls: Tls::default(),
        mail: Mail::default(),
        auth: auth_settings.clone(),
        fake_version: None,
        db_settings: db_settings.clone(),
    };

    let auth_runtime = AuthRuntime::from_settings(&auth_settings).expect("runtime");
    let database = Sqlite::new(&db_settings).await.expect("sqlite db");

    let hashed = hash_secret("correct-horse").expect("hash secret");
    let user_id = database
        .add_user(&NewUser {
            username: "test-user".into(),
            email: "test-user@example.com".into(),
            password: hashed,
        })
        .await
        .expect("user inserted");

    let app_state = AppState {
        database: database.clone(),
        settings,
        auth: auth_runtime,
    };

    let first = password_login(&app_state, "test-user".into(), "correct-horse".into())
        .await
        .expect("first login succeeds")
        .session;

    let second = password_login(&app_state, "test-user".into(), "correct-horse".into())
        .await
        .expect("second login succeeds")
        .session;

    assert_eq!(
        first, second,
        "subsequent logins should reuse the existing session token"
    );

    let row = database
        .get_session(&first)
        .await
        .expect("session persisted");
    assert_eq!(row.user_id, user_id);
}

#[tokio::test]
async fn oauth_login_auto_provisions_user() {
    let payload = json!({
        "login": "friendly-user",
        "email": "friendly@example.com",
        "sub": "external-subject",
    });
    let userinfo = MockUserinfoServer::start(payload).await;
    let provider = mock_oauth_provider(userinfo.uri(), true);

    let auth_settings = AuthSettings {
        allow_password: false,
        default_provider: Some(provider.name.clone()),
        providers: vec![provider.clone()],
        cache_dir: None,
        cache_max_bytes: None,
    };

    let db_settings = DbSettings {
        db_uri: "sqlite://:memory:?cache=shared".into(),
    };

    let settings = Settings {
        host: "127.0.0.1".into(),
        port: 0,
        path: String::new(),
        open_registration: true,
        max_history_length: 8192,
        max_record_size: 1024 * 1024,
        page_size: 1000,
        register_webhook_url: None,
        register_webhook_username: String::new(),
        metrics: Metrics::default(),
        tls: Tls::default(),
        mail: Mail::default(),
        auth: auth_settings.clone(),
        fake_version: None,
        db_settings: db_settings.clone(),
    };

    let auth_runtime = AuthRuntime::from_settings(&auth_settings).expect("runtime");
    let database = Sqlite::new(&db_settings).await.expect("sqlite db");

    let app_state = AppState {
        database: database.clone(),
        settings: settings.clone(),
        auth: auth_runtime,
    };

    let response = match login(
        axum::extract::State(app_state),
        Json(LoginRequest::Oauth {
            provider: provider.name.clone(),
            token: "dummy-token".into(),
        }),
    )
    .await
    {
        Ok(resp) => resp,
        Err(err) => panic!("oidc login failed: {}", err.error.reason),
    };

    assert_eq!(
        response.0.auth_method,
        AuthMethod::Oauth {
            provider: "mock-oauth".into()
        }
    );

    let user = database
        .get_user("friendly-user")
        .await
        .expect("provisioned user exists");
    assert_eq!(user.email, "friendly@example.com");

    let session = database
        .get_user_session(&user)
        .await
        .expect("session created");
    assert!(!session.token.is_empty());
}

#[tokio::test]
async fn oauth_login_requires_external_identity_link_when_manual() {
    let payload = json!({
        "login": "friendly-user",
        "email": "friendly@example.com",
        "sub": "external-subject",
    });
    let userinfo = MockUserinfoServer::start(payload).await;
    let provider = mock_oauth_provider(userinfo.uri(), false);

    let auth_settings = AuthSettings {
        allow_password: false,
        default_provider: Some(provider.name.clone()),
        providers: vec![provider.clone()],
        cache_dir: None,
        cache_max_bytes: None,
    };

    let db_settings = DbSettings {
        db_uri: "sqlite://:memory:?cache=shared".into(),
    };

    let settings = Settings {
        host: "127.0.0.1".into(),
        port: 0,
        path: String::new(),
        open_registration: true,
        max_history_length: 8192,
        max_record_size: 1024 * 1024,
        page_size: 1000,
        register_webhook_url: None,
        register_webhook_username: String::new(),
        metrics: Metrics::default(),
        tls: Tls::default(),
        mail: Mail::default(),
        auth: auth_settings.clone(),
        fake_version: None,
        db_settings: db_settings.clone(),
    };

    let auth_runtime = AuthRuntime::from_settings(&auth_settings).expect("runtime");
    let database = Sqlite::new(&db_settings).await.expect("sqlite db");

    let app_state = AppState {
        database: database.clone(),
        settings: settings.clone(),
        auth: auth_runtime,
    };

    let err = login(
        axum::extract::State(app_state),
        Json(LoginRequest::Oauth {
            provider: provider.name.clone(),
            token: "dummy-token".into(),
        }),
    )
    .await
    .expect_err("manual mode should reject unlinked identity");

    assert_eq!(err.status, StatusCode::FORBIDDEN);
    assert_eq!(err.error.reason, "external identity not linked");
}

#[tokio::test]
async fn oauth_login_auto_provision_creates_identity_binding() {
    let payload = json!({
        "login": "friendly-user",
        "email": "friendly@example.com",
        "sub": "external-subject",
    });
    let userinfo = MockUserinfoServer::start(payload).await;
    let provider = mock_oauth_provider(userinfo.uri(), true);

    let auth_settings = AuthSettings {
        allow_password: false,
        default_provider: Some(provider.name.clone()),
        providers: vec![provider.clone()],
        cache_dir: None,
        cache_max_bytes: None,
    };

    let db_settings = DbSettings {
        db_uri: "sqlite://:memory:?cache=shared".into(),
    };

    let settings = Settings {
        host: "127.0.0.1".into(),
        port: 0,
        path: String::new(),
        open_registration: true,
        max_history_length: 8192,
        max_record_size: 1024 * 1024,
        page_size: 1000,
        register_webhook_url: None,
        register_webhook_username: String::new(),
        metrics: Metrics::default(),
        tls: Tls::default(),
        mail: Mail::default(),
        auth: auth_settings.clone(),
        fake_version: None,
        db_settings: db_settings.clone(),
    };

    let auth_runtime = AuthRuntime::from_settings(&auth_settings).expect("runtime");
    let database = Sqlite::new(&db_settings).await.expect("sqlite db");

    let app_state = AppState {
        database: database.clone(),
        settings: settings.clone(),
        auth: auth_runtime,
    };

    let response = login(
        axum::extract::State(app_state),
        Json(LoginRequest::Oauth {
            provider: provider.name.clone(),
            token: "dummy-token".into(),
        }),
    )
    .await
    .expect("auto provisioning should succeed");

    assert_eq!(
        response.0.auth_method,
        AuthMethod::Oauth {
            provider: "mock-oauth".into()
        }
    );

    let user = database
        .get_user("friendly-user")
        .await
        .expect("provisioned user exists");

    let binding = database
        .get_external_identity(provider.name.as_str(), "external-subject")
        .await
        .expect("binding exists");

    assert_eq!(binding.user_id, user.id);
}

#[tokio::test]
async fn oauth_login_rejects_missing_subject() {
    let payload = json!({
        "login": "friendly-user",
        "email": "friendly@example.com"
    });
    let userinfo = MockUserinfoServer::start(payload).await;
    let provider = mock_oauth_provider(userinfo.uri(), true);

    let auth_settings = AuthSettings {
        allow_password: false,
        default_provider: Some(provider.name.clone()),
        providers: vec![provider.clone()],
        cache_dir: None,
        cache_max_bytes: None,
    };

    let db_settings = DbSettings {
        db_uri: "sqlite://:memory:?cache=shared".into(),
    };

    let settings = Settings {
        host: "127.0.0.1".into(),
        port: 0,
        path: String::new(),
        open_registration: true,
        max_history_length: 8192,
        max_record_size: 1024 * 1024,
        page_size: 1000,
        register_webhook_url: None,
        register_webhook_username: String::new(),
        metrics: Metrics::default(),
        tls: Tls::default(),
        mail: Mail::default(),
        auth: auth_settings.clone(),
        fake_version: None,
        db_settings: db_settings.clone(),
    };

    let auth_runtime = AuthRuntime::from_settings(&auth_settings).expect("runtime");
    let database = Sqlite::new(&db_settings).await.expect("sqlite db");

    let app_state = AppState {
        database,
        settings,
        auth: auth_runtime,
    };

    let err = login(
        axum::extract::State(app_state),
        Json(LoginRequest::Oauth {
            provider: provider.name.clone(),
            token: "dummy-token".into(),
        }),
    )
    .await
    .expect_err("missing subject should fail");

    assert_eq!(err.status, StatusCode::UNAUTHORIZED);
    assert_eq!(err.error.reason, "authentication failed");
}

#[tokio::test]
async fn oauth_login_accepts_custom_subject_claim() {
    let payload = json!({
        "login": "friendly-user",
        "email": "friendly@example.com"
    });
    let userinfo = MockUserinfoServer::start(payload).await;
    let mut provider = mock_oauth_provider(userinfo.uri(), true);
    provider.subject_claims = vec!["login".into()];

    let auth_settings = AuthSettings {
        allow_password: false,
        default_provider: Some(provider.name.clone()),
        providers: vec![provider.clone()],
        cache_dir: None,
        cache_max_bytes: None,
    };

    let db_settings = DbSettings {
        db_uri: "sqlite://:memory:?cache=shared".into(),
    };

    let settings = Settings {
        host: "127.0.0.1".into(),
        port: 0,
        path: String::new(),
        open_registration: true,
        max_history_length: 8192,
        max_record_size: 1024 * 1024,
        page_size: 1000,
        register_webhook_url: None,
        register_webhook_username: String::new(),
        metrics: Metrics::default(),
        tls: Tls::default(),
        mail: Mail::default(),
        auth: auth_settings.clone(),
        fake_version: None,
        db_settings: db_settings.clone(),
    };

    let auth_runtime = AuthRuntime::from_settings(&auth_settings).expect("runtime");
    let database = Sqlite::new(&db_settings).await.expect("sqlite db");

    let app_state = AppState {
        database: database.clone(),
        settings: settings.clone(),
        auth: auth_runtime,
    };

    let _ = login(
        axum::extract::State(app_state),
        Json(LoginRequest::Oauth {
            provider: provider.name.clone(),
            token: "dummy-token".into(),
        }),
    )
    .await
    .expect("custom subject claims should allow login");

    database
        .get_user("friendly-user")
        .await
        .expect("user provisioned");
}

#[tokio::test]
async fn linked_identity_allows_login_without_auto_provision() {
    let payload = json!({
        "login": "friendly-user",
        "email": "friendly@example.com",
        "sub": "external-subject",
    });
    let userinfo = MockUserinfoServer::start(payload).await;
    let provider = mock_oauth_provider(userinfo.uri(), false);

    let auth_settings = AuthSettings {
        allow_password: false,
        default_provider: Some(provider.name.clone()),
        providers: vec![provider.clone()],
        cache_dir: None,
        cache_max_bytes: None,
    };

    let db_settings = DbSettings {
        db_uri: "sqlite://:memory:?cache=shared".into(),
    };

    let settings = Settings {
        host: "127.0.0.1".into(),
        port: 0,
        path: String::new(),
        open_registration: true,
        max_history_length: 8192,
        max_record_size: 1024 * 1024,
        page_size: 1000,
        register_webhook_url: None,
        register_webhook_username: String::new(),
        metrics: Metrics::default(),
        tls: Tls::default(),
        mail: Mail::default(),
        auth: auth_settings.clone(),
        fake_version: None,
        db_settings: db_settings.clone(),
    };

    let auth_runtime = AuthRuntime::from_settings(&auth_settings).expect("runtime");
    let database = Sqlite::new(&db_settings).await.expect("sqlite db");

    let password = hash_secret("unused").expect("hash secret");
    let user_id = database
        .add_user(&NewUser {
            username: "linked-user".into(),
            email: "linked@example.com".into(),
            password,
        })
        .await
        .expect("manual user");

    database
        .link_external_identity(&NewExternalIdentity {
            user_id,
            provider: provider.name.clone(),
            subject: "external-subject".into(),
            display_claims: None,
        })
        .await
        .expect("link identity");

    let app_state = AppState {
        database: database.clone(),
        settings: settings.clone(),
        auth: auth_runtime,
    };

    let response = login(
        axum::extract::State(app_state),
        Json(LoginRequest::Oauth {
            provider: provider.name.clone(),
            token: "dummy-token".into(),
        }),
    )
    .await
    .expect("linked identity should allow login");

    assert_eq!(
        response.0.auth_method,
        AuthMethod::Oauth {
            provider: "mock-oauth".into()
        }
    );
}

#[tokio::test]
async fn password_login_succeeds_on_legacy_database() {
    let legacy_db = LegacyDb::default();
    let password_hash = hash_secret("correct-horse").expect("hash secret");
    legacy_db
        .add_user(&NewUser {
            username: "legacy-user".into(),
            email: "legacy@example.com".into(),
            password: password_hash,
        })
        .await
        .expect("insert legacy user");

    let auth_settings = AuthSettings {
        allow_password: true,
        default_provider: None,
        providers: Vec::new(),
        cache_dir: None,
        cache_max_bytes: None,
    };

    let db_settings = DbSettings {
        db_uri: "sqlite://legacy-db".into(),
    };

    let settings = Settings {
        host: "127.0.0.1".into(),
        port: 0,
        path: String::new(),
        open_registration: true,
        max_history_length: 8192,
        max_record_size: 1024 * 1024,
        page_size: 1000,
        register_webhook_url: None,
        register_webhook_username: String::new(),
        metrics: Metrics::default(),
        tls: Tls::default(),
        mail: Mail::default(),
        auth: auth_settings.clone(),
        fake_version: None,
        db_settings: db_settings.clone(),
    };

    let auth_runtime = AuthRuntime::from_settings(&auth_settings).expect("runtime");

    let app_state = AppState {
        database: legacy_db.clone(),
        settings,
        auth: auth_runtime,
    };

    let response = login(
        axum::extract::State(app_state),
        Json(LoginRequest::Password {
            username: "legacy-user".into(),
            password: "correct-horse".into(),
        }),
    )
    .await
    .expect("legacy password login succeeds");

    assert_eq!(response.0.auth_method, AuthMethod::Password);

    let user = legacy_db
        .get_user("legacy-user")
        .await
        .expect("legacy user exists");
    let session = legacy_db
        .get_user_session(&user)
        .await
        .expect("session created");
    assert!(
        !session.token.is_empty(),
        "session token should be persisted for legacy users"
    );
}

#[derive(Clone)]
struct LegacyDb {
    state: Arc<Mutex<LegacyDbState>>,
}

impl Default for LegacyDb {
    fn default() -> Self {
        Self {
            state: Arc::new(Mutex::new(LegacyDbState::default())),
        }
    }
}

#[derive(Default)]
struct LegacyDbState {
    next_user_id: i64,
    next_session_id: i64,
    users: HashMap<i64, StoredUser>,
    username_index: HashMap<String, i64>,
    sessions_by_user: HashMap<i64, StoredSession>,
    sessions_by_token: HashMap<String, StoredSession>,
}

#[derive(Clone)]
struct StoredUser {
    id: i64,
    username: String,
    email: String,
    password: String,
    verified: Option<OffsetDateTime>,
}

#[derive(Clone)]
struct StoredSession {
    id: i64,
    user_id: i64,
    token: String,
}

impl StoredUser {
    fn to_model(&self) -> User {
        User {
            id: self.id,
            username: self.username.clone(),
            email: self.email.clone(),
            password: self.password.clone(),
            verified: self.verified,
        }
    }
}

impl StoredSession {
    fn to_model(&self) -> Session {
        Session {
            id: self.id,
            user_id: self.user_id,
            token: self.token.clone(),
        }
    }
}

fn legacy_missing<T>(method: &str) -> DbResult<T> {
    Err(DbError::Other(eyre!(
        "legacy database does not support {method}"
    )))
}

#[async_trait]
impl Database for LegacyDb {
    async fn new(_settings: &DbSettings) -> DbResult<Self> {
        Ok(Self::default())
    }

    async fn get_session(&self, token: &str) -> DbResult<Session> {
        let state = self.state.lock().await;
        let entry = state
            .sessions_by_token
            .get(token)
            .ok_or(DbError::NotFound)?;
        Ok(entry.to_model())
    }

    async fn get_session_user(&self, token: &str) -> DbResult<User> {
        let state = self.state.lock().await;
        let session = state
            .sessions_by_token
            .get(token)
            .ok_or(DbError::NotFound)?;
        let user = state.users.get(&session.user_id).ok_or(DbError::NotFound)?;
        Ok(user.to_model())
    }

    async fn add_session(&self, session: &NewSession) -> DbResult<()> {
        let mut state = self.state.lock().await;
        let id = state.next_session_id;
        state.next_session_id += 1;
        let stored = StoredSession {
            id,
            user_id: session.user_id,
            token: session.token.clone(),
        };
        state
            .sessions_by_token
            .insert(stored.token.clone(), stored.clone());
        state.sessions_by_user.insert(stored.user_id, stored);
        Ok(())
    }

    async fn get_user(&self, username: &str) -> DbResult<User> {
        let state = self.state.lock().await;
        let id = state
            .username_index
            .get(username)
            .copied()
            .ok_or(DbError::NotFound)?;
        let user = state.users.get(&id).ok_or(DbError::NotFound)?;
        Ok(user.to_model())
    }

    async fn get_user_by_id(&self, id: i64) -> DbResult<User> {
        let state = self.state.lock().await;
        let user = state.users.get(&id).ok_or(DbError::NotFound)?;
        Ok(user.to_model())
    }

    async fn get_user_session(&self, user: &User) -> DbResult<Session> {
        let state = self.state.lock().await;
        let session = state
            .sessions_by_user
            .get(&user.id)
            .ok_or(DbError::NotFound)?;
        Ok(session.to_model())
    }

    async fn add_user(&self, user: &NewUser) -> DbResult<i64> {
        let mut state = self.state.lock().await;
        let id = state.next_user_id;
        state.next_user_id += 1;
        let stored = StoredUser {
            id,
            username: user.username.clone(),
            email: user.email.clone(),
            password: user.password.clone(),
            verified: None,
        };
        state.username_index.insert(stored.username.clone(), id);
        state.users.insert(id, stored);
        Ok(id)
    }

    async fn link_external_identity(&self, _identity: &NewExternalIdentity) -> DbResult<i64> {
        legacy_missing("link_external_identity")
    }

    async fn user_verified(&self, id: i64) -> DbResult<bool> {
        let state = self.state.lock().await;
        let user = state.users.get(&id).ok_or(DbError::NotFound)?;
        Ok(user.verified.is_some())
    }

    async fn verify_user(&self, id: i64) -> DbResult<()> {
        let mut state = self.state.lock().await;
        let user = state.users.get_mut(&id).ok_or(DbError::NotFound)?;
        user.verified = Some(OffsetDateTime::now_utc());
        Ok(())
    }

    async fn user_verification_token(&self, _id: i64) -> DbResult<String> {
        legacy_missing("user_verification_token")
    }

    async fn update_user_password(&self, user: &User) -> DbResult<()> {
        let mut state = self.state.lock().await;
        let stored = state.users.get_mut(&user.id).ok_or(DbError::NotFound)?;
        stored.password = user.password.clone();
        Ok(())
    }

    async fn total_history(&self) -> DbResult<i64> {
        Ok(0)
    }

    async fn count_history(&self, _user: &User) -> DbResult<i64> {
        Ok(0)
    }

    async fn count_history_cached(&self, _user: &User) -> DbResult<i64> {
        Ok(0)
    }

    async fn delete_user(&self, _u: &User) -> DbResult<()> {
        legacy_missing("delete_user")
    }

    async fn delete_history(&self, _user: &User, _id: String) -> DbResult<()> {
        legacy_missing("delete_history")
    }

    async fn deleted_history(&self, _user: &User) -> DbResult<Vec<String>> {
        legacy_missing("deleted_history")
    }

    async fn delete_store(&self, _user: &User) -> DbResult<()> {
        legacy_missing("delete_store")
    }

    async fn get_external_identity(
        &self,
        _provider: &str,
        _subject: &str,
    ) -> DbResult<DbExternalIdentity> {
        legacy_missing("get_external_identity")
    }

    async fn list_external_identities(&self, _user_id: i64) -> DbResult<Vec<DbExternalIdentity>> {
        legacy_missing("list_external_identities")
    }

    async fn unlink_external_identity(&self, _identity_id: i64) -> DbResult<()> {
        legacy_missing("unlink_external_identity")
    }

    async fn add_records(&self, _user: &User, _record: &[Record<EncryptedData>]) -> DbResult<()> {
        legacy_missing("add_records")
    }

    async fn next_records(
        &self,
        _user: &User,
        _host: HostId,
        _tag: String,
        _start: Option<RecordIdx>,
        _count: u64,
    ) -> DbResult<Vec<Record<EncryptedData>>> {
        legacy_missing("next_records")
    }

    async fn status(&self, _user: &User) -> DbResult<RecordStatus> {
        legacy_missing("status")
    }

    async fn count_history_range(
        &self,
        _user: &User,
        _range: std::ops::Range<OffsetDateTime>,
    ) -> DbResult<i64> {
        legacy_missing("count_history_range")
    }

    async fn list_history(
        &self,
        _user: &User,
        _created_after: OffsetDateTime,
        _since: OffsetDateTime,
        _host: &str,
        _page_size: i64,
    ) -> DbResult<Vec<History>> {
        legacy_missing("list_history")
    }

    async fn add_history(&self, _history: &[NewHistory]) -> DbResult<()> {
        legacy_missing("add_history")
    }

    async fn oldest_history(&self, _user: &User) -> DbResult<History> {
        legacy_missing("oldest_history")
    }

    async fn calendar(
        &self,
        _user: &User,
        _period: TimePeriod,
        _tz: UtcOffset,
    ) -> DbResult<HashMap<u64, TimePeriodInfo>> {
        legacy_missing("calendar")
    }
}
