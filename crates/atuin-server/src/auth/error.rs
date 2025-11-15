use std::path::PathBuf;

use openidconnect::{DiscoveryError, HttpClientError, url::ParseError};
use reqwest::{Error as ReqwestError, StatusCode};
use thiserror::Error;

#[derive(Debug, Error)]
pub enum AuthRuntimeError {
    #[error("failed to build metadata http client")]
    MetadataHttpClient(#[source] ReqwestError),
    #[error("failed to build auth http client")]
    HttpClient(#[source] ReqwestError),
    #[error("failed to create auth cache directory '{path}'")]
    CacheDir {
        path: PathBuf,
        #[source]
        source: std::io::Error,
    },
}

#[derive(Debug, Error)]
pub enum CacheError {
    #[error("provider snapshot exceeds {limit} bytes (received {actual})")]
    SnapshotTooLarge { limit: usize, actual: usize },
    #[error("failed to create auth cache directory '{path}'")]
    CreateCacheDir {
        path: PathBuf,
        #[source]
        source: std::io::Error,
    },
    #[error("failed to serialize provider snapshot")]
    SerializeSnapshot(#[source] serde_json::Error),
    #[error("failed to create snapshot file '{path}'")]
    CreateSnapshot {
        path: PathBuf,
        #[source]
        source: std::io::Error,
    },
    #[error("failed to write snapshot file '{path}'")]
    WriteSnapshot {
        path: PathBuf,
        #[source]
        source: std::io::Error,
    },
    #[error("failed to sync snapshot file '{path}'")]
    SyncSnapshot {
        path: PathBuf,
        #[source]
        source: std::io::Error,
    },
    #[error("failed to finalize snapshot file '{from}' -> '{to}'")]
    FinalizeSnapshot {
        from: PathBuf,
        to: PathBuf,
        #[source]
        source: std::io::Error,
    },
    #[error("invalid cached issuer '{issuer}'")]
    InvalidIssuer {
        issuer: String,
        #[source]
        source: ParseError,
    },
    #[error("failed to deserialize provider snapshot '{path}'")]
    DeserializeSnapshot {
        path: PathBuf,
        #[source]
        source: serde_json::Error,
    },
}

#[derive(Debug, Error)]
pub enum MetadataError {
    #[error("provider '{provider}' missing issuer")]
    MissingIssuer { provider: String },
    #[error("failed to fetch provider '{provider}' metadata")]
    Discovery {
        provider: String,
        #[source]
        source: DiscoError,
    },
    #[error(
        "provider '{provider}' enables device_code flow but missing device_authorization_endpoint"
    )]
    MissingDeviceEndpoint { provider: String },
}

#[derive(Debug, Error)]
pub enum IdentityError {
    #[error("unknown auth provider '{0}'")]
    UnknownProvider(String),

    #[error("provider '{provider}' is missing required field '{field}'")]
    MissingField {
        provider: String,
        field: &'static str,
    },

    #[error("provider '{provider}' metadata is unavailable")]
    Metadata {
        provider: String,
        #[source]
        source: MetadataError,
    },

    #[error("failed to contact userinfo endpoint for '{provider}'")]
    UserinfoRequest {
        provider: String,
        #[source]
        source: reqwest::Error,
    },

    #[error("userinfo endpoint for '{provider}' returned unexpected status {status}")]
    UserinfoStatus {
        provider: String,
        status: StatusCode,
    },

    #[error("provider '{provider}' userinfo response missing stable subject claims {claims:?}")]
    MissingSubject {
        provider: String,
        claims: Vec<String>,
    },

    #[error("provider '{provider}' missing claim '{claim}'")]
    MissingClaim { provider: String, claim: String },

    #[error("provider '{provider}' rejected claim '{claim}'")]
    ClaimRejected { provider: String, claim: String },

    #[error("provider '{provider}' rejected the identity: {reason}")]
    VerificationFailed { provider: String, reason: String },
}

type DiscoError = DiscoveryError<HttpClientError<ReqwestError>>;
