mod service;

#[cfg(test)]
mod tests;

use axum::{Json, extract::State, http::StatusCode};
use tracing::instrument;

use atuin_common::api::{LoginRequest, LoginResponse};
use atuin_server_database::Database;

use self::service::{LoginError, LoginSuccess};
use crate::{
    auth::IdentityError,
    handlers::{ErrorResponse, ErrorResponseStatus, RespExt},
    router::AppState,
};

#[instrument(
    skip_all,
    fields(
        auth.method = tracing::field::Empty,
        auth.provider = tracing::field::Empty,
        user.id = tracing::field::Empty
    )
)]
pub async fn login<DB: Database>(
    state: State<AppState<DB>>,
    Json(login): Json<LoginRequest>,
) -> Result<Json<LoginResponse>, ErrorResponseStatus<'static>> {
    match service::handle_login(&state.0, login).await {
        Ok(success) => Ok(render_login_response(success)),
        Err(error) => Err(map_login_error(error)),
    }
}

fn render_login_response(result: LoginSuccess) -> Json<LoginResponse> {
    Json(LoginResponse {
        session: result.session,
        auth_method: result.auth_method,
    })
}

fn map_login_error(error: LoginError) -> ErrorResponseStatus<'static> {
    match error {
        LoginError::PasswordLoginDisabled => {
            ErrorResponse::reply("password login disabled").with_status(StatusCode::FORBIDDEN)
        }
        LoginError::UserNotFound => {
            ErrorResponse::reply("user not found").with_status(StatusCode::NOT_FOUND)
        }
        LoginError::PasswordIncorrect => {
            ErrorResponse::reply("password is not correct").with_status(StatusCode::UNAUTHORIZED)
        }
        LoginError::ProviderNotEnabled => {
            ErrorResponse::reply("provider not enabled").with_status(StatusCode::BAD_REQUEST)
        }
        LoginError::IdentityVerification(error) => identity_error_response(error),
        LoginError::UsernameDerivationFailed => {
            ErrorResponse::reply("could not derive username from identity")
                .with_status(StatusCode::BAD_REQUEST)
        }
        LoginError::IdentityNotLinked => {
            ErrorResponse::reply("external identity not linked").with_status(StatusCode::FORBIDDEN)
        }
        LoginError::IdentityBindingInvalid => ErrorResponse::reply("identity binding invalid")
            .with_status(StatusCode::INTERNAL_SERVER_ERROR),
        LoginError::Database => {
            ErrorResponse::reply("database error").with_status(StatusCode::INTERNAL_SERVER_ERROR)
        }
        LoginError::SessionLoad => ErrorResponse::reply("failed to load session")
            .with_status(StatusCode::INTERNAL_SERVER_ERROR),
        LoginError::SessionCreate => ErrorResponse::reply("failed to create session")
            .with_status(StatusCode::INTERNAL_SERVER_ERROR),
        LoginError::Provisioning => ErrorResponse::reply("failed to provision user")
            .with_status(StatusCode::INTERNAL_SERVER_ERROR),
    }
}

fn identity_error_response(error: IdentityError) -> ErrorResponseStatus<'static> {
    match error {
        IdentityError::UnknownProvider(_) => {
            ErrorResponse::reply("provider not enabled").with_status(StatusCode::BAD_REQUEST)
        }
        IdentityError::MissingField { .. } => {
            ErrorResponse::reply("authentication temporarily unavailable")
                .with_status(StatusCode::INTERNAL_SERVER_ERROR)
        }
        IdentityError::Metadata { .. } => {
            ErrorResponse::reply("authentication temporarily unavailable")
                .with_status(StatusCode::SERVICE_UNAVAILABLE)
        }
        IdentityError::UserinfoRequest { .. } | IdentityError::UserinfoStatus { .. } => {
            ErrorResponse::reply("authentication failed").with_status(StatusCode::BAD_GATEWAY)
        }
        IdentityError::MissingSubject { .. }
        | IdentityError::MissingClaim { .. }
        | IdentityError::ClaimRejected { .. }
        | IdentityError::VerificationFailed { .. } => {
            ErrorResponse::reply("authentication failed").with_status(StatusCode::UNAUTHORIZED)
        }
    }
}
