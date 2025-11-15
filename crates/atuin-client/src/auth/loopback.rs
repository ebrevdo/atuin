use std::{
    convert::Infallible,
    sync::{Arc, Mutex},
    time::Duration,
};

use super::flows::{AuthFlowError, FlowResult};
use hyper::{Body, Request, Response, StatusCode, server::conn::Http, service::service_fn};
use log::warn;
use oauth2::{AuthorizationCode, CsrfToken};
use reqwest::Url;
use tokio::{
    net::TcpListener,
    sync::oneshot,
    task::{self, JoinHandle},
    time,
};
use tokio_util::sync::CancellationToken;

pub(crate) struct LoopbackConfig {
    pub redirect_port: Option<u16>,
    pub cancellation: CancellationToken,
    pub lifetime: Duration,
}

pub(crate) struct LoopbackListener {
    redirect_uri: String,
    state: Arc<LoopbackState>,
    handle: Option<JoinHandle<FlowResult<(AuthorizationCode, CsrfToken)>>>,
}

impl LoopbackListener {
    pub fn redirect_uri(&self) -> &str {
        &self.redirect_uri
    }

    pub fn expect_state(&self, state: &CsrfToken) {
        self.state.set_expected_state(state);
    }

    pub async fn wait(mut self) -> FlowResult<(AuthorizationCode, CsrfToken)> {
        let handle = self
            .handle
            .take()
            .ok_or_else(|| AuthFlowError::loopback("loopback listener already completed"))?;

        handle
            .await
            .map_err(|err| AuthFlowError::loopback(format!("loopback task failed: {err}")))?
    }
}

impl Drop for LoopbackListener {
    fn drop(&mut self) {
        if let Some(handle) = self.handle.take() {
            handle.abort();
        }
    }
}

pub(crate) async fn spawn_loopback_listener(
    config: LoopbackConfig,
) -> FlowResult<LoopbackListener> {
    let port = config.redirect_port.unwrap_or(0);
    let (listener, redirect_uri) = match TcpListener::bind(("::1", port)).await {
        Ok(listener) => {
            let address = listener.local_addr().map_err(|err| {
                AuthFlowError::network(format!("failed to read listener address: {err}"))
            })?;
            let uri = format!("http://[{}]:{}", address.ip(), address.port());
            (listener, uri)
        }
        Err(_) => {
            let listener = TcpListener::bind(("127.0.0.1", port))
                .await
                .map_err(|err| {
                    AuthFlowError::network(format!(
                        "failed to bind loopback listener on port {port}: {err}"
                    ))
                })?;
            let address = listener.local_addr().map_err(|err| {
                AuthFlowError::network(format!("failed to read listener address: {err}"))
            })?;
            let uri = format!("http://{}:{}", address.ip(), address.port());
            (listener, uri)
        }
    };

    let state = Arc::new(LoopbackState::new(
        Url::parse(&redirect_uri).expect("loopback redirect uri must be valid"),
    ));
    let handle = task::spawn(wait_for_callback(
        listener,
        state.clone(),
        config.cancellation.clone(),
        config.lifetime,
    ));

    Ok(LoopbackListener {
        redirect_uri,
        state,
        handle: Some(handle),
    })
}

async fn wait_for_callback(
    listener: TcpListener,
    state: Arc<LoopbackState>,
    cancellation: CancellationToken,
    lifetime: Duration,
) -> FlowResult<(AuthorizationCode, CsrfToken)> {
    let timeout = time::sleep(lifetime);
    tokio::pin!(timeout);

    tokio::select! {
        _ = cancellation.cancelled() => Err(AuthFlowError::Cancelled),
        _ = timeout.as_mut() => Err(AuthFlowError::TimedOut { stage: "loopback callback", after: lifetime }),
        result = async {
            let (stream, _) = listener
                .accept()
                .await
                .map_err(|err| AuthFlowError::network(format!("loopback accept failed: {err}")))?;
            let (sender, receiver) = oneshot::channel();
            state.set_sender(sender);

            let service_state = state.clone();
            let service = service_fn(move |req: Request<Body>| {
                let state = service_state.clone();
                async move { Ok::<_, Infallible>(handle_loopback_request(state, req)) }
            });

            Http::new()
                .http1_only(true)
                .http1_keep_alive(false)
                .serve_connection(stream, service)
                .await
                .map_err(|err| AuthFlowError::loopback(format!("loopback HTTP server error: {err}")))?;

            match receiver.await {
                Ok(result) => result,
                Err(_) => Err(AuthFlowError::loopback(
                    "authorization callback closed before completing",
                )),
            }
        } => result,
    }
}

struct LoopbackState {
    redirect_uri: Url,
    result: Mutex<Option<oneshot::Sender<FlowResult<(AuthorizationCode, CsrfToken)>>>>,
    expected_state: Mutex<Option<String>>,
}

impl LoopbackState {
    fn new(redirect_uri: Url) -> Self {
        Self {
            redirect_uri,
            result: Mutex::new(None),
            expected_state: Mutex::new(None),
        }
    }

    fn set_sender(&self, sender: oneshot::Sender<FlowResult<(AuthorizationCode, CsrfToken)>>) {
        if let Ok(mut guard) = self.result.lock() {
            *guard = Some(sender);
        }
    }

    fn take_sender(&self) -> Option<oneshot::Sender<FlowResult<(AuthorizationCode, CsrfToken)>>> {
        self.result.lock().ok().and_then(|mut guard| guard.take())
    }

    fn clone_redirect_uri(&self) -> Url {
        self.redirect_uri.clone()
    }

    fn set_expected_state(&self, state: &CsrfToken) {
        if let Ok(mut guard) = self.expected_state.lock() {
            guard.replace(state.secret().to_string());
        }
    }

    fn verify_state(&self, state: &CsrfToken) -> FlowResult<()> {
        if let Ok(guard) = self.expected_state.lock() {
            if let Some(expected) = guard.as_ref() {
                if expected != state.secret() {
                    return Err(AuthFlowError::loopback("authorization state mismatch"));
                }
            }
        }
        Ok(())
    }
}

fn handle_loopback_request(state: Arc<LoopbackState>, req: Request<Body>) -> Response<Body> {
    if let Some(sender) = state.take_sender() {
        let outcome = parse_callback_request(&state, &req);
        let response = match &outcome {
            Ok(_) => success_response("Login completed. You may close this window."),
            Err(err) => {
                warn!("authorization callback failed: {err:?}");
                error_response(
                    StatusCode::BAD_REQUEST,
                    "Authentication failed. Please return to the CLI for details.",
                )
            }
        };
        let _ = sender.send(outcome);
        response
    } else {
        error_response(
            StatusCode::GONE,
            "Login was already processed. You may close this window.",
        )
    }
}

fn parse_callback_request(
    state: &LoopbackState,
    req: &Request<Body>,
) -> FlowResult<(AuthorizationCode, CsrfToken)> {
    if req.uri().scheme().is_some() || req.uri().authority().is_some() {
        return Err(AuthFlowError::loopback(
            "authorization callback must use origin-form request target",
        ));
    }

    let path = req.uri().path();
    if !path.starts_with('/') {
        return Err(AuthFlowError::loopback(
            "authorization callback path malformed",
        ));
    }

    let mut callback_url = state.clone_redirect_uri();
    callback_url.set_path(path);
    callback_url.set_query(req.uri().query());

    let mut code = None;
    let mut state_param = None;
    let mut error = None;

    for (key, value) in callback_url.query_pairs() {
        match key.as_ref() {
            "code" => code = Some(AuthorizationCode::new(value.into_owned())),
            "state" => state_param = Some(CsrfToken::new(value.into_owned())),
            "error" => error = Some(value.into_owned()),
            _ => {}
        }
    }

    if let Some(err) = error {
        return Err(AuthFlowError::loopback(format!(
            "authorization server returned error: {err}"
        )));
    }

    let code =
        code.ok_or_else(|| AuthFlowError::loopback("authorization server did not return a code"))?;
    let state_value = state_param
        .ok_or_else(|| AuthFlowError::loopback("authorization server did not return state"))?;

    state.verify_state(&state_value)?;

    Ok((code, state_value))
}

fn success_response(body: &str) -> Response<Body> {
    Response::builder()
        .status(StatusCode::OK)
        .header("Content-Type", "text/plain; charset=utf-8")
        .header("Connection", "close")
        .body(Body::from(body.to_owned()))
        .expect("success response builds")
}

fn error_response(status: StatusCode, body: &str) -> Response<Body> {
    Response::builder()
        .status(status)
        .header("Content-Type", "text/plain; charset=utf-8")
        .header("Connection", "close")
        .body(Body::from(body.to_owned()))
        .expect("error response builds")
}

#[cfg(test)]
mod tests {
    use super::*;
    use reqwest::{Client, StatusCode as HttpStatus};
    use std::net::TcpListener as StdTcpListener;

    #[tokio::test]
    async fn loopback_listener_respects_configured_port() {
        let port = reserve_loopback_port();
        let listener = spawn_loopback_listener(LoopbackConfig {
            redirect_port: Some(port),
            cancellation: CancellationToken::new(),
            lifetime: Duration::from_secs(5),
        })
        .await
        .expect("listener binds");

        assert!(
            listener.redirect_uri().ends_with(&port.to_string()),
            "redirect uri {} should reflect configured port {}",
            listener.redirect_uri(),
            port
        );

        drop(listener);
    }

    #[tokio::test]
    async fn loopback_listener_round_trips_code_and_state() {
        let token = CancellationToken::new();
        let listener = spawn_loopback_listener(LoopbackConfig {
            redirect_port: Some(reserve_loopback_port()),
            cancellation: token.clone(),
            lifetime: Duration::from_secs(5),
        })
        .await
        .expect("listener binds");

        let expected_state = CsrfToken::new("test-state".into());
        listener.expect_state(&expected_state);
        let uri = listener.redirect_uri().to_string();

        let response = Client::new()
            .get(format!("{uri}/?code=test-code&state=test-state"))
            .send()
            .await
            .expect("callback request succeeds");

        assert_eq!(response.status(), HttpStatus::OK);
        let body = response.text().await.expect("body reads");
        assert!(
            body.contains("Login completed"),
            "response body should confirm success"
        );

        let (code, state) = listener.wait().await.expect("loopback result ok");
        assert_eq!(code.secret(), "test-code");
        assert_eq!(state.secret(), "test-state");

        token.cancel();
    }

    #[tokio::test]
    async fn loopback_listener_rejects_wrong_state() {
        let listener = spawn_loopback_listener(LoopbackConfig {
            redirect_port: Some(reserve_loopback_port()),
            cancellation: CancellationToken::new(),
            lifetime: Duration::from_secs(5),
        })
        .await
        .expect("listener binds");

        let expected_state = CsrfToken::new("expected".into());
        listener.expect_state(&expected_state);
        let uri = listener.redirect_uri().to_string();

        let response = Client::new()
            .get(format!("{uri}/?code=test-code&state=wrong"))
            .send()
            .await
            .expect("callback request succeeds");

        assert_eq!(response.status(), HttpStatus::BAD_REQUEST);

        let error = listener
            .wait()
            .await
            .expect_err("state mismatch should fail");
        assert!(matches!(error, AuthFlowError::Loopback(_)));
    }

    #[tokio::test]
    async fn loopback_listener_times_out_without_callback() {
        let listener = spawn_loopback_listener(LoopbackConfig {
            redirect_port: Some(reserve_loopback_port()),
            cancellation: CancellationToken::new(),
            lifetime: Duration::from_millis(100),
        })
        .await
        .expect("listener binds");

        let error = listener.wait().await.expect_err("timeout expected");
        assert!(matches!(
            error,
            AuthFlowError::TimedOut {
                stage: "loopback callback",
                ..
            }
        ));
    }

    fn reserve_loopback_port() -> u16 {
        let listener = StdTcpListener::bind("127.0.0.1:0").expect("bind ephemeral port");
        let port = listener.local_addr().expect("local addr").port();
        drop(listener);
        port
    }
}
