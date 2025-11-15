use atuin_server::{Settings, settings::AuthProvider};
use atuin_server_database::{
    Database, DbError, DbType,
    models::{ExternalIdentity, NewExternalIdentity},
};
use atuin_server_postgres::Postgres;
use atuin_server_sqlite::Sqlite;
use clap::{Args, Subcommand};
use eyre::{Result, WrapErr, eyre};
use serde_json::Value;
use time::{OffsetDateTime, format_description::well_known::Rfc3339};

use crate::runtime::CliRuntime;

#[derive(Subcommand, Debug)]
#[command(infer_subcommands = true)]
pub enum Cmd {
    /// Manage external identity bindings
    #[command(subcommand)]
    Identities(IdentitiesCmd),
}

#[derive(Subcommand, Debug)]
pub enum IdentitiesCmd {
    /// Link an identity provider subject to an existing user
    Link(LinkIdentity),
    /// List identity bindings for an existing user
    List(ListIdentities),
    /// Unlink an identity binding by id
    Unlink(UnlinkIdentity),
}

#[derive(Args, Debug)]
pub struct LinkIdentity {
    #[arg(long)]
    pub provider: String,
    #[arg(long)]
    pub subject: String,
    #[arg(long)]
    pub username: String,
    #[arg(long)]
    pub display_claims: Option<String>,
}

#[derive(Args, Debug)]
pub struct ListIdentities {
    #[arg(long)]
    pub username: String,
}

#[derive(Args, Debug)]
pub struct UnlinkIdentity {
    #[arg(long)]
    pub identity_id: i64,
}

impl Cmd {
    pub fn run(self) -> Result<()> {
        let runtime = CliRuntime::new_current_thread()?;
        let settings = Settings::new().wrap_err("could not load server settings")?;
        runtime.block_on(async { self.run_inner(settings).await })
    }

    async fn run_inner(self, settings: Settings) -> Result<()> {
        match self {
            Cmd::Identities(cmd) => cmd.run(settings).await,
        }
    }
}

impl IdentitiesCmd {
    async fn run(self, settings: Settings) -> Result<()> {
        match self {
            IdentitiesCmd::Link(link) => link.execute(settings).await,
            IdentitiesCmd::List(list) => list.execute(settings).await,
            IdentitiesCmd::Unlink(unlink) => unlink.execute(settings).await,
        }
    }
}

impl LinkIdentity {
    async fn execute(self, settings: Settings) -> Result<()> {
        ensure_external_auth_enabled(&settings)?;

        let provider_cfg = settings
            .auth
            .provider(self.provider.as_str())
            .ok_or_else(|| eyre!("provider '{}' is not configured", self.provider))?;

        match settings.db_settings.db_type() {
            DbType::Sqlite => {
                let db = Sqlite::new(&settings.db_settings)
                    .await
                    .wrap_err("failed to connect to sqlite")?;
                self.link_with_db(&db, provider_cfg).await?
            }
            DbType::Postgres => {
                let db = Postgres::new(&settings.db_settings)
                    .await
                    .wrap_err("failed to connect to postgres")?;
                self.link_with_db(&db, provider_cfg).await?
            }
            DbType::Unknown => {
                return Err(eyre!("db_uri must start with postgres:// or sqlite://"));
            }
        }

        println!(
            "linked subject '{}' from provider '{}' to user '{}'",
            self.subject, self.provider, self.username
        );

        Ok(())
    }

    async fn link_with_db<DB: Database>(&self, db: &DB, provider: &AuthProvider) -> Result<()> {
        let user = db.get_user(&self.username).await.map_err(|err| match err {
            DbError::NotFound => eyre!("user '{}' not found", self.username),
            DbError::Other(e) => eyre!("failed to load user: {e}"),
        })?;

        match db
            .get_external_identity(provider.name.as_str(), &self.subject)
            .await
        {
            Ok(existing) => {
                return Err(eyre!(
                    "subject already linked to user id {}",
                    existing.user_id
                ));
            }
            Err(DbError::NotFound) => {}
            Err(DbError::Other(e)) => {
                return Err(eyre!("failed to query existing bindings: {e}"));
            }
        }

        let new_identity = NewExternalIdentity {
            user_id: user.id,
            provider: provider.name.clone(),
            subject: self.subject.clone(),
            display_claims: match self.display_claims.as_ref() {
                Some(raw) => Some(serde_json::from_str::<Value>(raw)?),
                None => None,
            },
        };

        db.link_external_identity(&new_identity)
            .await
            .map_err(|err| match err {
                DbError::NotFound => eyre!("failed to link identity"),
                DbError::Other(e) => eyre!("failed to link identity: {e}"),
            })?;

        Ok(())
    }
}

impl ListIdentities {
    async fn execute(self, settings: Settings) -> Result<()> {
        ensure_external_auth_enabled(&settings)?;

        let identities = match settings.db_settings.db_type() {
            DbType::Sqlite => {
                let db = Sqlite::new(&settings.db_settings)
                    .await
                    .wrap_err("failed to connect to sqlite")?;
                self.list_with_db(&db).await?
            }
            DbType::Postgres => {
                let db = Postgres::new(&settings.db_settings)
                    .await
                    .wrap_err("failed to connect to postgres")?;
                self.list_with_db(&db).await?
            }
            DbType::Unknown => {
                return Err(eyre!("db_uri must start with postgres:// or sqlite://"));
            }
        };

        self.print(&identities);
        Ok(())
    }

    pub(crate) async fn list_with_db<DB: Database>(
        &self,
        db: &DB,
    ) -> Result<Vec<ExternalIdentity>> {
        let user = db.get_user(&self.username).await.map_err(|err| match err {
            DbError::NotFound => eyre!("user '{}' not found", self.username),
            DbError::Other(e) => eyre!("failed to load user: {e}"),
        })?;

        db.list_external_identities(user.id)
            .await
            .map_err(|err| match err {
                DbError::NotFound => eyre!("no identities for '{}'", self.username),
                DbError::Other(e) => eyre!("failed to list identities: {e}"),
            })
    }

    fn print(&self, identities: &[ExternalIdentity]) {
        if identities.is_empty() {
            println!("no external identities linked to '{}'", self.username);
            return;
        }

        println!("external identities for '{}':", self.username);
        for identity in identities {
            let claims = identity
                .display_claims
                .as_ref()
                .map(|v| serde_json::to_string(v).unwrap_or_else(|_| "<invalid>".into()))
                .unwrap_or_else(|| "-".into());

            println!(
                "- id={id} provider={provider} subject={subject} created={created} updated={updated} claims={claims}",
                id = identity.id,
                provider = identity.provider,
                subject = identity.subject,
                created = format_timestamp(identity.created_at),
                updated = format_timestamp(identity.updated_at),
                claims = claims,
            );
        }
    }
}

impl UnlinkIdentity {
    async fn execute(self, settings: Settings) -> Result<()> {
        ensure_external_auth_enabled(&settings)?;

        match settings.db_settings.db_type() {
            DbType::Sqlite => {
                let db = Sqlite::new(&settings.db_settings)
                    .await
                    .wrap_err("failed to connect to sqlite")?;
                self.unlink_with_db(&db).await?
            }
            DbType::Postgres => {
                let db = Postgres::new(&settings.db_settings)
                    .await
                    .wrap_err("failed to connect to postgres")?;
                self.unlink_with_db(&db).await?
            }
            DbType::Unknown => {
                return Err(eyre!("db_uri must start with postgres:// or sqlite://"));
            }
        }

        println!("removed identity id {}", self.identity_id);
        Ok(())
    }

    pub(crate) async fn unlink_with_db<DB: Database>(&self, db: &DB) -> Result<()> {
        db.unlink_external_identity(self.identity_id)
            .await
            .map_err(|err| match err {
                DbError::NotFound => eyre!(
                    "identity id {} not found (already removed?)",
                    self.identity_id
                ),
                DbError::Other(e) => eyre!("failed to unlink identity: {e}"),
            })
    }
}

fn ensure_external_auth_enabled(settings: &Settings) -> Result<()> {
    if settings.auth.allow_password {
        Err(eyre!(
            "external auth admin commands require auth.allow_password=false"
        ))
    } else {
        Ok(())
    }
}

fn format_timestamp(ts: OffsetDateTime) -> String {
    ts.format(&Rfc3339).unwrap_or_else(|_| ts.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;
    use atuin_server_database::{DbSettings, models::NewUser};
    use serde_json::json;
    use tempfile::NamedTempFile;

    fn temp_db() -> (DbSettings, NamedTempFile) {
        let file = NamedTempFile::new().expect("temp db file");
        let uri = format!("sqlite://{}", file.path().to_string_lossy());
        (DbSettings { db_uri: uri }, file)
    }

    fn sample_user(username: &str) -> NewUser {
        NewUser {
            username: username.to_string(),
            email: format!("{username}@example.com"),
            password: "irrelevant".into(),
        }
    }

    async fn seed_identities(db: &Sqlite, username: &str) -> Vec<ExternalIdentity> {
        let user_id = db.add_user(&sample_user(username)).await.expect("user id");

        let links = [
            NewExternalIdentity {
                user_id,
                provider: "mock".into(),
                subject: "subject-1".into(),
                display_claims: Some(json!({"username": "user1"})),
            },
            NewExternalIdentity {
                user_id,
                provider: "mock".into(),
                subject: "subject-2".into(),
                display_claims: None,
            },
        ];

        for link in &links {
            db.link_external_identity(link)
                .await
                .expect("link identity");
        }

        db.list_external_identities(user_id)
            .await
            .expect("list identities")
    }

    #[tokio::test]
    async fn list_with_db_returns_identities() {
        let (settings, _file) = temp_db();
        let db = Sqlite::new(&settings).await.expect("sqlite db");
        let existing = seed_identities(&db, "list-user").await;

        let cmd = ListIdentities {
            username: "list-user".into(),
        };

        let listed = cmd.list_with_db(&db).await.expect("list identities");
        assert_eq!(listed.len(), existing.len());
        assert_eq!(listed[0].subject, "subject-1");
        assert_eq!(listed[1].subject, "subject-2");
    }

    #[tokio::test]
    async fn unlink_with_db_removes_identity() {
        let (settings, _file) = temp_db();
        let db = Sqlite::new(&settings).await.expect("sqlite db");
        let existing = seed_identities(&db, "unlink-user").await;
        let target_id = existing[0].id;

        let cmd = UnlinkIdentity {
            identity_id: target_id,
        };

        cmd.unlink_with_db(&db).await.expect("unlink identity");

        let err = db
            .get_external_identity("mock", "subject-1")
            .await
            .err()
            .expect("identity should be gone");
        assert!(matches!(err, DbError::NotFound));
    }
}
