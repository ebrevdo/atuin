use atuin_common::api::AuthProvidersResponse;
use atuin_server_database::Database;
use axum::{Json, extract::State};

use crate::router::AppState;

pub async fn providers<DB: Database>(state: State<AppState<DB>>) -> Json<AuthProvidersResponse> {
    Json(state.auth.providers_response().await)
}
