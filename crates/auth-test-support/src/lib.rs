use std::{collections::VecDeque, sync::Arc};

use axum::{
    extract::State,
    routing::{get, post},
    Json, Router,
};
use http::StatusCode;
use serde_json::{json, Value};
use tokio::{
    net::TcpListener,
    sync::{oneshot, Mutex},
};

#[derive(Debug)]
struct TestServer {
    base_uri: String,
    shutdown: Option<oneshot::Sender<()>>,
}

impl TestServer {
    async fn serve(router: Router) -> Self {
        let listener = TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind test server");
        let addr = listener.local_addr().expect("read local addr");
        let (tx, rx) = oneshot::channel();

        tokio::spawn(async move {
            let server = axum::serve(listener, router).with_graceful_shutdown(async {
                let _ = rx.await;
            });
            if let Err(err) = server.await {
                eprintln!("test server error: {err:?}");
            }
        });

        Self {
            base_uri: format!("http://{addr}"),
            shutdown: Some(tx),
        }
    }

    fn uri(&self) -> &str {
        &self.base_uri
    }
}

impl Drop for TestServer {
    fn drop(&mut self) {
        if let Some(tx) = self.shutdown.take() {
            let _ = tx.send(());
        }
    }
}

pub struct MockOidcServer {
    inner: TestServer,
    issuer: String,
}

#[derive(Clone, Debug)]
pub struct OidcServerConfig {
    pub issuer: Option<String>,
    pub include_device_endpoint: bool,
}

impl Default for OidcServerConfig {
    fn default() -> Self {
        Self {
            issuer: None,
            include_device_endpoint: true,
        }
    }
}

impl MockOidcServer {
    pub async fn start(config: OidcServerConfig) -> Self {
        let listener = TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind oidc server");
        let addr = listener.local_addr().expect("local addr");
        let issuer = config.issuer.unwrap_or_else(|| format!("http://{addr}"));
        let discovery = Arc::new(build_discovery_document(
            &issuer,
            config.include_device_endpoint,
        ));
        let jwks = Arc::new(build_jwks());

        let app = Router::new()
            .route(
                "/.well-known/openid-configuration",
                get({
                    let discovery = discovery.clone();
                    move || {
                        let discovery = discovery.clone();
                        async move { Json((*discovery).clone()) }
                    }
                }),
            )
            .route(
                "/jwks",
                get({
                    let jwks = jwks.clone();
                    move || {
                        let jwks = jwks.clone();
                        async move { Json((*jwks).clone()) }
                    }
                }),
            );

        let (tx, rx) = oneshot::channel();
        tokio::spawn(async move {
            let server = axum::serve(listener, app).with_graceful_shutdown(async {
                let _ = rx.await;
            });
            if let Err(err) = server.await {
                eprintln!("mock oidc server error: {err:?}");
            }
        });

        MockOidcServer {
            inner: TestServer {
                base_uri: format!("http://{addr}"),
                shutdown: Some(tx),
            },
            issuer,
        }
    }

    pub fn issuer(&self) -> &str {
        &self.issuer
    }

    pub fn uri(&self) -> &str {
        self.inner.uri()
    }
}

fn build_discovery_document(issuer: &str, include_device: bool) -> Value {
    let mut document = json!({
        "issuer": issuer,
        "authorization_endpoint": format!("{issuer}/authorize"),
        "token_endpoint": format!("{issuer}/token"),
        "jwks_uri": format!("{issuer}/jwks"),
        "response_types_supported": ["code"],
        "subject_types_supported": ["public"],
        "id_token_signing_alg_values_supported": ["RS256"],
    });

    if include_device {
        document
            .as_object_mut()
            .expect("discovery json object")
            .insert(
                "device_authorization_endpoint".into(),
                Value::String(format!("{issuer}/device")),
            );
    }

    document
}

fn build_jwks() -> Value {
    json!({
        "keys": [{
            "kty": "RSA",
            "use": "sig",
            "kid": "test-key",
            "alg": "RS256",
            "n": "WK_TYieedXU1Tn98SEMvFZBRHLSjkEXtesRX2_Y2RqKKLMfRQtElykTNqOas7o23RDgo7e1XfYBhG3rYWSn-eNSAFwH8M_hMGKWUIEPDfNvjzXd4CILaGB1NNiaSWURFtGSAmUBaL6wjEwzSyEmzWypMNAibZnpDdf5qnVZQq5ghNS2dPbsBzlYB7lv__WFBa3-EvK-qJAJ49F1CNdU23oalILndar0QXyOFFiWLEYhRiEB7Hprjm6DWjo4pF7FQ3Bm82Hhcieg6DXSNmU9KKudv1Yxc0X1-MrRciTNIpzLVaO5GWjsCVyUn5ZV_O907l-0VZHsN1YBCBfBoFk9B8A",
            "e": "AQAB"
        }]
    })
}

pub struct MockUserinfoServer {
    inner: TestServer,
}

impl MockUserinfoServer {
    pub async fn start(body: Value) -> Self {
        let shared = Arc::new(body);
        let router = Router::new().route(
            "/userinfo",
            get({
                let shared = shared.clone();
                move || {
                    let shared = shared.clone();
                    async move { Json((*shared).clone()) }
                }
            }),
        );

        Self {
            inner: TestServer::serve(router).await,
        }
    }

    pub fn uri(&self) -> &str {
        self.inner.uri()
    }
}

#[derive(Clone, Debug)]
pub struct JsonResponse {
    pub status: StatusCode,
    pub body: Value,
}

impl JsonResponse {
    pub fn ok(body: Value) -> Self {
        Self {
            status: StatusCode::OK,
            body,
        }
    }

    pub fn with_status(status: StatusCode, body: Value) -> Self {
        Self { status, body }
    }

    fn into_parts(&self) -> (StatusCode, Json<Value>) {
        (self.status, Json(self.body.clone()))
    }
}

pub struct OAuthFlowConfig {
    pub device_response: Option<JsonResponse>,
    pub token_responses: Vec<JsonResponse>,
}

impl OAuthFlowConfig {
    pub fn token_only(token: JsonResponse) -> Self {
        Self {
            device_response: None,
            token_responses: vec![token],
        }
    }

    pub fn device_and_token(device: JsonResponse, token: JsonResponse) -> Self {
        Self {
            device_response: Some(device),
            token_responses: vec![token],
        }
    }
}

#[derive(Clone)]
struct ResponseQueue {
    responses: Arc<Mutex<VecDeque<JsonResponse>>>,
    fallback: Arc<JsonResponse>,
}

impl ResponseQueue {
    fn new(responses: Vec<JsonResponse>) -> Self {
        assert!(!responses.is_empty(), "token response required");
        let fallback = responses.last().cloned().unwrap();
        Self {
            responses: Arc::new(Mutex::new(VecDeque::from(responses))),
            fallback: Arc::new(fallback),
        }
    }

    async fn next(&self) -> JsonResponse {
        let mut guard = self.responses.lock().await;
        guard
            .pop_front()
            .unwrap_or_else(|| (*self.fallback).clone())
    }
}

pub struct MockOauthFlowServer {
    inner: TestServer,
}

impl MockOauthFlowServer {
    pub async fn start(config: OAuthFlowConfig) -> Self {
        let mut router = Router::new();

        if let Some(device) = config.device_response.clone() {
            router = router.route(
                "/device",
                post({
                    move || {
                        let response = device.clone();
                        async move { response.into_parts() }
                    }
                }),
            );
        }

        let queue = ResponseQueue::new(config.token_responses);
        router = router.route(
            "/token",
            post({
                move |State(queue): State<ResponseQueue>| async move {
                    let response = queue.next().await;
                    response.into_parts()
                }
            })
            .with_state(queue),
        );

        Self {
            inner: TestServer::serve(router).await,
        }
    }

    pub fn uri(&self) -> &str {
        self.inner.uri()
    }
}
