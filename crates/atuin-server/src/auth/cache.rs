use std::{
    io::Write,
    path::{Path, PathBuf},
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};

use atuin_common::utils;
use fs_err::{File, create_dir_all, metadata, read_to_string, rename};
use openidconnect::{IssuerUrl, core::CoreJsonWebKeySet};
use serde::{Deserialize, Serialize};

use super::{error::CacheError, runtime::ResolvedProvider};

pub(super) const DEFAULT_MAX_SNAPSHOT_BYTES: usize = 8 * 1024 * 1024; // 8 MiB

#[derive(Clone, Debug, Serialize, Deserialize)]
struct ProviderSnapshot {
    issuer: Option<String>,
    authorization_endpoint: Option<String>,
    token_endpoint: Option<String>,
    device_authorization_endpoint: Option<String>,
    userinfo_endpoint: Option<String>,
    jwks_uri: Option<String>,
    jwks: Option<CoreJsonWebKeySet>,
    fetched_at: i64,
}

impl From<&ResolvedProvider> for ProviderSnapshot {
    fn from(value: &ResolvedProvider) -> Self {
        Self {
            issuer: value.issuer.as_ref().map(|issuer| issuer.url().to_string()),
            authorization_endpoint: value.authorization_endpoint.clone(),
            token_endpoint: value.token_endpoint.clone(),
            device_authorization_endpoint: value.device_authorization_endpoint.clone(),
            userinfo_endpoint: value.userinfo_endpoint.clone(),
            jwks_uri: value.jwks_uri.clone(),
            jwks: value.jwks.clone(),
            fetched_at: instant_to_unix(value.fetched_at),
        }
    }
}

impl TryFrom<ProviderSnapshot> for ResolvedProvider {
    type Error = CacheError;

    fn try_from(value: ProviderSnapshot) -> Result<Self, CacheError> {
        Ok(Self {
            issuer: match value.issuer {
                Some(issuer) => {
                    let parsed = IssuerUrl::new(issuer.clone()).map_err(|error| {
                        CacheError::InvalidIssuer {
                            issuer,
                            source: error,
                        }
                    })?;
                    Some(parsed)
                }
                None => None,
            },
            authorization_endpoint: value.authorization_endpoint,
            token_endpoint: value.token_endpoint,
            device_authorization_endpoint: value.device_authorization_endpoint,
            userinfo_endpoint: value.userinfo_endpoint,
            jwks_uri: value.jwks_uri,
            jwks: value.jwks,
            fetched_at: instant_from_unix(value.fetched_at),
        })
    }
}

pub(super) fn default_cache_dir() -> PathBuf {
    utils::data_dir().join("auth-cache")
}

pub(super) fn provider_cache_path(base: &Path, provider: &str) -> PathBuf {
    let sanitized = sanitize_provider_name(provider);
    base.join(format!("{sanitized}.json"))
}

pub(super) fn persist_provider_snapshot(
    path: &Path,
    resolved: &ResolvedProvider,
    max_bytes: usize,
) -> Result<(), CacheError> {
    if let Some(parent) = path.parent() {
        create_dir_all(parent).map_err(|error| CacheError::CreateCacheDir {
            path: parent.to_path_buf(),
            source: error,
        })?;
    }

    let snapshot = ProviderSnapshot::from(resolved);
    let data = serde_json::to_vec_pretty(&snapshot).map_err(CacheError::SerializeSnapshot)?;
    if data.len() > max_bytes {
        return Err(CacheError::SnapshotTooLarge {
            limit: max_bytes,
            actual: data.len(),
        });
    }

    let tmp_path = path.with_extension("json.tmp");
    {
        let mut file = File::create(&tmp_path).map_err(|error| CacheError::CreateSnapshot {
            path: tmp_path.clone(),
            source: error,
        })?;
        file.write_all(&data)
            .map_err(|error| CacheError::WriteSnapshot {
                path: tmp_path.clone(),
                source: error,
            })?;
        file.sync_all().map_err(|error| CacheError::SyncSnapshot {
            path: tmp_path.clone(),
            source: error,
        })?;
    }

    rename(&tmp_path, path).map_err(|error| CacheError::FinalizeSnapshot {
        from: tmp_path,
        to: path.to_path_buf(),
        source: error,
    })?;
    Ok(())
}

pub(super) fn load_provider_snapshot(
    name: &str,
    path: &Path,
    max_bytes: usize,
) -> Option<ResolvedProvider> {
    if let Ok(meta) = metadata(path) {
        if meta.len() > max_bytes as u64 {
            tracing::warn!(
                target = "atuin::auth",
                provider = name,
                snapshot = %path.display(),
                size = meta.len(),
                "provider snapshot exceeds size limit; ignoring"
            );
            return None;
        }
    }

    let data = read_to_string(path).ok()?;
    let snapshot: ProviderSnapshot = match serde_json::from_str(&data) {
        Ok(snapshot) => snapshot,
        Err(error) => {
            warn_failed_snapshot(
                name,
                path,
                CacheError::DeserializeSnapshot {
                    path: path.to_path_buf(),
                    source: error,
                },
            );
            return None;
        }
    };

    match ResolvedProvider::try_from(snapshot) {
        Ok(resolved) if resolved.is_fresh() => Some(resolved),
        Ok(_) => None,
        Err(error) => {
            warn_failed_snapshot(name, path, error);
            None
        }
    }
}

fn warn_failed_snapshot(name: &str, path: &Path, error: CacheError) {
    tracing::warn!(
        target = "atuin::auth",
        provider = name,
        snapshot = %path.display(),
        ?error,
        "failed to load provider snapshot"
    );
}

fn sanitize_provider_name(name: &str) -> String {
    let sanitized: String = name
        .chars()
        .map(|c| match c {
            'a'..='z' | 'A'..='Z' | '0'..='9' | '-' | '_' | '.' => c,
            _ => '_',
        })
        .collect();

    if sanitized.is_empty() {
        "_".into()
    } else {
        sanitized
    }
}

fn instant_to_unix(instant: Instant) -> i64 {
    let now = Instant::now();
    let system_now = SystemTime::now();

    if instant >= now {
        return system_now
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs() as i64;
    }

    let age = now.duration_since(instant);
    let fetched_system = system_now.checked_sub(age).unwrap_or(system_now);
    fetched_system
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs() as i64
}

fn instant_from_unix(timestamp: i64) -> Instant {
    if timestamp <= 0 {
        return Instant::now();
    }

    let stored = UNIX_EPOCH + Duration::from_secs(timestamp as u64);
    match SystemTime::now().duration_since(stored) {
        Ok(elapsed) => Instant::now()
            .checked_sub(elapsed)
            .unwrap_or_else(Instant::now),
        Err(_) => Instant::now(),
    }
}
