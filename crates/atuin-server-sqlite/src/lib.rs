use std::str::FromStr;

use async_trait::async_trait;
use atuin_common::{
    record::{EncryptedData, HostId, Record, RecordIdx, RecordStatus},
    utils::crypto_random_string,
};
use atuin_server_database::{
    Database, DbError, DbResult, DbSettings,
    models::{
        ExternalIdentity, History, NewExternalIdentity, NewHistory, NewSession, NewUser, Session,
        User,
    },
};
use futures_util::TryStreamExt;
use sqlx::{
    Row,
    sqlite::{SqliteConnectOptions, SqliteJournalMode, SqlitePoolOptions},
    types::{Json, Uuid},
};
use time::{OffsetDateTime, PrimitiveDateTime, UtcOffset};
use tracing::instrument;
use wrappers::{DbExternalIdentity, DbHistory, DbRecord, DbSession, DbUser};

mod wrappers;

#[derive(Clone)]
pub struct Sqlite {
    pool: sqlx::Pool<sqlx::sqlite::Sqlite>,
}

fn fix_error(error: sqlx::Error) -> DbError {
    match error {
        sqlx::Error::RowNotFound => DbError::NotFound,
        error => DbError::Other(error.into()),
    }
}

#[async_trait]
impl Database for Sqlite {
    async fn new(settings: &DbSettings) -> DbResult<Self> {
        let opts = SqliteConnectOptions::from_str(&settings.db_uri)
            .map_err(fix_error)?
            .journal_mode(SqliteJournalMode::Wal)
            .create_if_missing(true);

        let pool = SqlitePoolOptions::new()
            .connect_with(opts)
            .await
            .map_err(fix_error)?;

        sqlx::migrate!("./migrations")
            .run(&pool)
            .await
            .map_err(|error| DbError::Other(error.into()))?;

        Ok(Self { pool })
    }

    #[instrument(skip_all)]
    async fn get_session(&self, token: &str) -> DbResult<Session> {
        sqlx::query_as("select id, user_id, token from sessions where token = $1")
            .bind(token)
            .fetch_one(&self.pool)
            .await
            .map_err(fix_error)
            .map(|DbSession(session)| session)
    }

    #[instrument(skip_all)]
    async fn get_session_user(&self, token: &str) -> DbResult<User> {
        sqlx::query_as(
            "select users.id, users.username, users.email, users.password, users.verified_at from users 
            inner join sessions 
            on users.id = sessions.user_id 
            and sessions.token = $1",
        )
        .bind(token)
        .fetch_one(&self.pool)
        .await
        .map_err(fix_error)
        .map(|DbUser(user)| user)
    }

    #[instrument(skip_all)]
    async fn add_session(&self, session: &NewSession) -> DbResult<()> {
        let token: &str = &session.token;

        sqlx::query(
            "insert into sessions
                (user_id, token)
            values($1, $2)",
        )
        .bind(session.user_id)
        .bind(token)
        .execute(&self.pool)
        .await
        .map_err(fix_error)?;

        Ok(())
    }

    #[instrument(skip_all)]
    async fn get_user(&self, username: &str) -> DbResult<User> {
        sqlx::query_as(
            "select id, username, email, password, verified_at from users where username = $1",
        )
        .bind(username)
        .fetch_one(&self.pool)
        .await
        .map_err(fix_error)
        .map(|DbUser(user)| user)
    }

    #[instrument(skip_all)]
    async fn get_user_by_id(&self, id: i64) -> DbResult<User> {
        sqlx::query_as("select id, username, email, password, verified_at from users where id = $1")
            .bind(id)
            .fetch_one(&self.pool)
            .await
            .map_err(fix_error)
            .map(|DbUser(user)| user)
    }

    #[instrument(skip_all)]
    async fn get_user_session(&self, u: &User) -> DbResult<Session> {
        sqlx::query_as("select id, user_id, token from sessions where user_id = $1")
            .bind(u.id)
            .fetch_one(&self.pool)
            .await
            .map_err(fix_error)
            .map(|DbSession(session)| session)
    }

    #[instrument(skip_all)]
    async fn add_user(&self, user: &NewUser) -> DbResult<i64> {
        let email: &str = &user.email;
        let username: &str = &user.username;
        let password: &str = &user.password;

        let res: (i64,) = sqlx::query_as(
            "insert into users
                (username, email, password)
            values($1, $2, $3)
            returning id",
        )
        .bind(username)
        .bind(email)
        .bind(password)
        .fetch_one(&self.pool)
        .await
        .map_err(fix_error)?;

        Ok(res.0)
    }

    #[instrument(skip_all)]
    async fn link_external_identity(&self, identity: &NewExternalIdentity) -> DbResult<i64> {
        let claims = identity.display_claims.clone().map(Json);

        let res: (i64,) = sqlx::query_as(
            "insert into external_identities
                (user_id, provider, subject, display_claims)
            values ($1, $2, $3, $4)
            returning id",
        )
        .bind(identity.user_id)
        .bind(identity.provider.as_str())
        .bind(identity.subject.as_str())
        .bind(claims)
        .fetch_one(&self.pool)
        .await
        .map_err(fix_error)?;

        Ok(res.0)
    }

    #[instrument(skip_all)]
    async fn user_verified(&self, id: i64) -> DbResult<bool> {
        let res: (bool,) =
            sqlx::query_as("select verified_at is not null from users where id = $1")
                .bind(id)
                .fetch_one(&self.pool)
                .await
                .map_err(fix_error)?;

        Ok(res.0)
    }

    #[instrument(skip_all)]
    async fn verify_user(&self, id: i64) -> DbResult<()> {
        sqlx::query(
            "update users set verified_at = (current_timestamp at time zone 'utc') where id=$1",
        )
        .bind(id)
        .execute(&self.pool)
        .await
        .map_err(fix_error)?;

        Ok(())
    }

    #[instrument(skip_all)]
    async fn user_verification_token(&self, id: i64) -> DbResult<String> {
        const TOKEN_VALID_MINUTES: i64 = 15;

        // First we check if there is a verification token
        let token: Option<(String, sqlx::types::time::OffsetDateTime)> = sqlx::query_as(
            "select token, valid_until from user_verification_token where user_id = $1",
        )
        .bind(id)
        .fetch_optional(&self.pool)
        .await
        .map_err(fix_error)?;

        let token = if let Some((token, valid_until)) = token {
            // We have a token, AND it's still valid
            if valid_until > time::OffsetDateTime::now_utc() {
                token
            } else {
                // token has expired. generate a new one, return it
                let token = crypto_random_string::<24>();

                sqlx::query("update user_verification_token set token = $2, valid_until = $3 where user_id=$1")
                    .bind(id)
                    .bind(&token)
                    .bind(time::OffsetDateTime::now_utc() + time::Duration::minutes(TOKEN_VALID_MINUTES))
                    .execute(&self.pool)
                    .await
                    .map_err(fix_error)?;

                token
            }
        } else {
            // No token in the database! Generate one, insert it
            let token = crypto_random_string::<24>();

            sqlx::query("insert into user_verification_token (user_id, token, valid_until) values ($1, $2, $3)")
                .bind(id)
                .bind(&token)
                .bind(time::OffsetDateTime::now_utc() + time::Duration::minutes(TOKEN_VALID_MINUTES))
                .execute(&self.pool)
                .await
                .map_err(fix_error)?;

            token
        };

        Ok(token)
    }

    #[instrument(skip_all)]
    async fn update_user_password(&self, user: &User) -> DbResult<()> {
        sqlx::query(
            "update users
            set password = $1
            where id = $2",
        )
        .bind(&user.password)
        .bind(user.id)
        .execute(&self.pool)
        .await
        .map_err(fix_error)?;

        Ok(())
    }

    #[instrument(skip_all)]
    async fn total_history(&self) -> DbResult<i64> {
        let res: (i64,) = sqlx::query_as("select count(1) from history")
            .fetch_optional(&self.pool)
            .await
            .map_err(fix_error)?
            .unwrap_or((0,));

        Ok(res.0)
    }

    #[instrument(skip_all)]
    async fn count_history(&self, user: &User) -> DbResult<i64> {
        // The cache is new, and the user might not yet have a cache value.
        // They will have one as soon as they post up some new history, but handle that
        // edge case.

        let res: (i64,) = sqlx::query_as(
            "select count(1) from history
            where user_id = $1",
        )
        .bind(user.id)
        .fetch_one(&self.pool)
        .await
        .map_err(fix_error)?;

        Ok(res.0)
    }

    #[instrument(skip_all)]
    async fn count_history_cached(&self, _user: &User) -> DbResult<i64> {
        Err(DbError::NotFound)
    }

    #[instrument(skip_all)]
    async fn delete_user(&self, u: &User) -> DbResult<()> {
        sqlx::query("delete from sessions where user_id = $1")
            .bind(u.id)
            .execute(&self.pool)
            .await
            .map_err(fix_error)?;

        sqlx::query("delete from users where id = $1")
            .bind(u.id)
            .execute(&self.pool)
            .await
            .map_err(fix_error)?;

        sqlx::query("delete from history where user_id = $1")
            .bind(u.id)
            .execute(&self.pool)
            .await
            .map_err(fix_error)?;

        Ok(())
    }

    async fn delete_history(&self, user: &User, id: String) -> DbResult<()> {
        sqlx::query(
            "update history
            set deleted_at = $3
            where user_id = $1
            and client_id = $2
            and deleted_at is null", // don't just keep setting it
        )
        .bind(user.id)
        .bind(id)
        .bind(time::OffsetDateTime::now_utc())
        .fetch_all(&self.pool)
        .await
        .map_err(fix_error)?;

        Ok(())
    }

    #[instrument(skip_all)]
    async fn deleted_history(&self, user: &User) -> DbResult<Vec<String>> {
        // The cache is new, and the user might not yet have a cache value.
        // They will have one as soon as they post up some new history, but handle that
        // edge case.

        let res = sqlx::query(
            "select client_id from history 
            where user_id = $1
            and deleted_at is not null",
        )
        .bind(user.id)
        .fetch_all(&self.pool)
        .await
        .map_err(fix_error)?;

        let res = res.iter().map(|row| row.get("client_id")).collect();

        Ok(res)
    }

    async fn delete_store(&self, user: &User) -> DbResult<()> {
        sqlx::query(
            "delete from store
            where user_id = $1",
        )
        .bind(user.id)
        .execute(&self.pool)
        .await
        .map_err(fix_error)?;

        Ok(())
    }

    async fn get_external_identity(
        &self,
        provider: &str,
        subject: &str,
    ) -> DbResult<ExternalIdentity> {
        sqlx::query_as(
            "select id, user_id, provider, subject, display_claims, created_at, updated_at
            from external_identities where provider = $1 and subject = $2",
        )
        .bind(provider)
        .bind(subject)
        .fetch_one(&self.pool)
        .await
        .map_err(fix_error)
        .map(|DbExternalIdentity(identity)| identity)
    }

    async fn list_external_identities(&self, user_id: i64) -> DbResult<Vec<ExternalIdentity>> {
        sqlx::query_as(
            "select id, user_id, provider, subject, display_claims, created_at, updated_at
            from external_identities where user_id = $1 order by created_at asc",
        )
        .bind(user_id)
        .fetch_all(&self.pool)
        .await
        .map_err(fix_error)
        .map(|rows| {
            rows.into_iter()
                .map(|DbExternalIdentity(identity)| identity)
                .collect()
        })
    }

    async fn unlink_external_identity(&self, identity_id: i64) -> DbResult<()> {
        let result = sqlx::query("delete from external_identities where id = $1")
            .bind(identity_id)
            .execute(&self.pool)
            .await
            .map_err(fix_error)?;

        if result.rows_affected() == 0 {
            Err(DbError::NotFound)
        } else {
            Ok(())
        }
    }

    #[instrument(skip_all)]
    async fn add_records(&self, user: &User, records: &[Record<EncryptedData>]) -> DbResult<()> {
        let mut tx = self.pool.begin().await.map_err(fix_error)?;

        for i in records {
            let id = atuin_common::utils::uuid_v7();

            sqlx::query(
                "insert into store
                    (id, client_id, host, idx, timestamp, version, tag, data, cek, user_id) 
                values ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10)
                on conflict do nothing
                ",
            )
            .bind(id)
            .bind(i.id)
            .bind(i.host.id)
            .bind(i.idx as i64)
            .bind(i.timestamp as i64) // throwing away some data, but i64 is still big in terms of time
            .bind(&i.version)
            .bind(&i.tag)
            .bind(&i.data.data)
            .bind(&i.data.content_encryption_key)
            .bind(user.id)
            .execute(&mut *tx)
            .await
            .map_err(fix_error)?;
        }

        tx.commit().await.map_err(fix_error)?;

        Ok(())
    }

    #[instrument(skip_all)]
    async fn next_records(
        &self,
        user: &User,
        host: HostId,
        tag: String,
        start: Option<RecordIdx>,
        count: u64,
    ) -> DbResult<Vec<Record<EncryptedData>>> {
        tracing::debug!("{:?} - {:?} - {:?}", host, tag, start);
        let start = start.unwrap_or(0);

        let records: Result<Vec<DbRecord>, DbError> = sqlx::query_as(
            "select client_id, host, idx, timestamp, version, tag, data, cek from store
                    where user_id = $1
                    and tag = $2
                    and host = $3
                    and idx >= $4
                    order by idx asc
                    limit $5",
        )
        .bind(user.id)
        .bind(tag.clone())
        .bind(host)
        .bind(start as i64)
        .bind(count as i64)
        .fetch_all(&self.pool)
        .await
        .map_err(fix_error);

        let ret = match records {
            Ok(records) => {
                let records: Vec<Record<EncryptedData>> = records
                    .into_iter()
                    .map(|f| {
                        let record: Record<EncryptedData> = f.into();
                        record
                    })
                    .collect();

                records
            }
            Err(DbError::NotFound) => {
                tracing::debug!("no records found in store: {:?}/{}", host, tag);
                return Ok(vec![]);
            }
            Err(e) => return Err(e),
        };

        Ok(ret)
    }

    async fn status(&self, user: &User) -> DbResult<RecordStatus> {
        const STATUS_SQL: &str =
            "select host, tag, max(idx) from store where user_id = $1 group by host, tag";

        let res: Vec<(Uuid, String, i64)> = sqlx::query_as(STATUS_SQL)
            .bind(user.id)
            .fetch_all(&self.pool)
            .await
            .map_err(fix_error)?;

        let mut status = RecordStatus::new();

        for i in res {
            status.set_raw(HostId(i.0), i.1, i.2 as u64);
        }

        Ok(status)
    }

    #[instrument(skip_all)]
    async fn count_history_range(
        &self,
        user: &User,
        range: std::ops::Range<time::OffsetDateTime>,
    ) -> DbResult<i64> {
        let res: (i64,) = sqlx::query_as(
            "select count(1) from history
            where user_id = $1
            and timestamp >= $2::date
            and timestamp < $3::date",
        )
        .bind(user.id)
        .bind(into_utc(range.start))
        .bind(into_utc(range.end))
        .fetch_one(&self.pool)
        .await
        .map_err(fix_error)?;

        Ok(res.0)
    }

    #[instrument(skip_all)]
    async fn list_history(
        &self,
        user: &User,
        created_after: time::OffsetDateTime,
        since: time::OffsetDateTime,
        host: &str,
        page_size: i64,
    ) -> DbResult<Vec<History>> {
        let res = sqlx::query_as(
            "select id, client_id, user_id, hostname, timestamp, data, created_at from history
            where user_id = $1
            and hostname != $2
            and created_at >= $3
            and timestamp >= $4
            order by timestamp asc
            limit $5",
        )
        .bind(user.id)
        .bind(host)
        .bind(into_utc(created_after))
        .bind(into_utc(since))
        .bind(page_size)
        .fetch(&self.pool)
        .map_ok(|DbHistory(h)| h)
        .try_collect()
        .await
        .map_err(fix_error)?;

        Ok(res)
    }

    #[instrument(skip_all)]
    async fn add_history(&self, history: &[NewHistory]) -> DbResult<()> {
        let mut tx = self.pool.begin().await.map_err(fix_error)?;

        for i in history {
            let client_id: &str = &i.client_id;
            let hostname: &str = &i.hostname;
            let data: &str = &i.data;

            sqlx::query(
                "insert into history
                    (client_id, user_id, hostname, timestamp, data) 
                values ($1, $2, $3, $4, $5)
                on conflict do nothing
                ",
            )
            .bind(client_id)
            .bind(i.user_id)
            .bind(hostname)
            .bind(i.timestamp)
            .bind(data)
            .execute(&mut *tx)
            .await
            .map_err(fix_error)?;
        }

        tx.commit().await.map_err(fix_error)?;

        Ok(())
    }

    #[instrument(skip_all)]
    async fn oldest_history(&self, user: &User) -> DbResult<History> {
        sqlx::query_as(
            "select id, client_id, user_id, hostname, timestamp, data, created_at from history 
            where user_id = $1
            order by timestamp asc
            limit 1",
        )
        .bind(user.id)
        .fetch_one(&self.pool)
        .await
        .map_err(fix_error)
        .map(|DbHistory(h)| h)
    }
}

fn into_utc(x: OffsetDateTime) -> PrimitiveDateTime {
    let x = x.to_offset(UtcOffset::UTC);
    PrimitiveDateTime::new(x.date(), x.time())
}

#[cfg(test)]
mod tests {
    use super::*;
    use atuin_server_database::{
        DbSettings,
        models::{NewExternalIdentity, NewUser},
    };
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

    #[tokio::test]
    async fn link_and_fetch_identity_round_trip() {
        let (settings, _file) = temp_db();
        let db = Sqlite::new(&settings).await.expect("sqlite db");
        let user_id = db
            .add_user(&sample_user("linked-user"))
            .await
            .expect("user id");

        let link = NewExternalIdentity {
            user_id,
            provider: "mock".into(),
            subject: "subject-123".into(),
            display_claims: None,
        };

        db.link_external_identity(&link)
            .await
            .expect("link identity");

        let stored = db
            .get_external_identity("mock", "subject-123")
            .await
            .expect("stored identity");

        assert_eq!(stored.user_id, user_id);
        assert_eq!(stored.provider, "mock");
        assert_eq!(stored.subject, "subject-123");
    }

    #[tokio::test]
    async fn duplicate_identity_for_same_provider_fails() {
        let (settings, _file) = temp_db();
        let db = Sqlite::new(&settings).await.expect("sqlite db");
        let user_id = db
            .add_user(&sample_user("linked-user"))
            .await
            .expect("user id");

        let link = NewExternalIdentity {
            user_id,
            provider: "mock".into(),
            subject: "subject-123".into(),
            display_claims: None,
        };

        db.link_external_identity(&link)
            .await
            .expect("link identity");

        let err = db
            .link_external_identity(&link)
            .await
            .expect_err("duplicate subject should fail");

        match err {
            DbError::Other(_) | DbError::NotFound => {}
        }
    }

    #[tokio::test]
    async fn list_external_identities_returns_all_rows() {
        let (settings, _file) = temp_db();
        let db = Sqlite::new(&settings).await.expect("sqlite db");
        let user_id = db
            .add_user(&sample_user("list-user"))
            .await
            .expect("user id");

        let first = NewExternalIdentity {
            user_id,
            provider: "mock".into(),
            subject: "subject-1".into(),
            display_claims: Some(json!({"username": "user1"})),
        };

        let second = NewExternalIdentity {
            user_id,
            provider: "mock".into(),
            subject: "subject-2".into(),
            display_claims: None,
        };

        db.link_external_identity(&first)
            .await
            .expect("link first identity");
        db.link_external_identity(&second)
            .await
            .expect("link second identity");

        let linked = db
            .list_external_identities(user_id)
            .await
            .expect("list identities");

        assert_eq!(linked.len(), 2);
        assert_eq!(linked[0].subject, "subject-1");
        assert_eq!(linked[1].subject, "subject-2");
    }

    #[tokio::test]
    async fn unlink_external_identity_removes_row() {
        let (settings, _file) = temp_db();
        let db = Sqlite::new(&settings).await.expect("sqlite db");
        let user_id = db
            .add_user(&sample_user("unlink-user"))
            .await
            .expect("user id");

        let record = NewExternalIdentity {
            user_id,
            provider: "mock".into(),
            subject: "subject-removable".into(),
            display_claims: None,
        };

        db.link_external_identity(&record)
            .await
            .expect("link identity");

        let stored = db
            .get_external_identity("mock", "subject-removable")
            .await
            .expect("stored identity");

        db.unlink_external_identity(stored.id)
            .await
            .expect("unlink identity");

        let err = db
            .get_external_identity("mock", "subject-removable")
            .await
            .err()
            .expect("identity should be removed");

        assert!(matches!(err, DbError::NotFound));
    }
}
