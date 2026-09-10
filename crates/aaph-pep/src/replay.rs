use sqlx::sqlite::{SqliteConnectOptions, SqlitePoolOptions};
use sqlx::{Row, SqlitePool};
use std::str::FromStr;

static MIGRATOR: sqlx::migrate::Migrator = sqlx::migrate!("./migrations");

#[derive(Clone)]
pub struct PepStore {
    pool: SqlitePool,
}
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ApplyResult {
    Applied,
    AlreadyApplied,
    Regressive,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OperationState {
    Received,
    Started,
    Completed,
    Failed,
    Ambiguous,
}

#[derive(Debug, PartialEq, Eq)]
pub enum ReceiveOperation {
    Ready,
    Completed(String),
    Conflict,
    Replay,
    Ambiguous,
}

pub struct ReceiveOperationInput<'a> {
    pub operation_id: &'a str,
    pub permit_id: &'a str,
    pub jti: &'a str,
    pub nonce: &'a str,
    pub idempotency_key: &'a str,
    pub request_digest: &'a str,
    pub expires_at: i64,
    pub now: i64,
}

impl PepStore {
    /// Opens the PEP state store and installs its schema.
    ///
    /// # Errors
    /// Returns the underlying `SQLite` error.
    pub async fn connect(url: &str) -> Result<Self, sqlx::Error> {
        let options = SqliteConnectOptions::from_str(url)?.create_if_missing(true);
        let pool = SqlitePoolOptions::new()
            .max_connections(8)
            .connect_with(options)
            .await?;
        MIGRATOR
            .run(&pool)
            .await
            .map_err(|error| sqlx::Error::Migrate(Box::new(error)))?;
        sqlx::query("UPDATE effect_operations SET state='AMBIGUOUS',updated_at=MAX(updated_at,created_at) WHERE state='STARTED'")
            .execute(&pool)
            .await?;
        Ok(Self { pool })
    }

    /// Atomically consumes credential replay values and persists `RECEIVED`.
    ///
    /// `idempotency_key := request_id` in the fixed `NON_PRODUCTION_DEMO` tenant.
    ///
    /// # Errors
    /// Returns the underlying `SQLite` error.
    pub async fn receive_operation(
        &self,
        input: &ReceiveOperationInput<'_>,
    ) -> Result<ReceiveOperation, sqlx::Error> {
        let mut tx = self.pool.begin().await?;
        if let Some(row) = sqlx::query(
            "SELECT request_digest,state,result_json FROM effect_operations WHERE idempotency_key=? AND tenant='NON_PRODUCTION_DEMO'",
        )
        .bind(input.idempotency_key)
        .fetch_optional(&mut *tx)
        .await?
        {
            if row.try_get::<String, _>("request_digest")? != input.request_digest {
                return Ok(ReceiveOperation::Conflict);
            }
            let state: String = row.try_get("state")?;
            let result = match state.as_str() {
                "COMPLETED" => ReceiveOperation::Completed(row.try_get("result_json")?),
                "RECEIVED" => ReceiveOperation::Ready,
                "STARTED" | "FAILED" | "AMBIGUOUS" => ReceiveOperation::Ambiguous,
                _ => return Err(sqlx::Error::Protocol("unknown operation state".to_owned())),
            };
            tx.commit().await?;
            return Ok(result);
        }
        let jti_insert = sqlx::query(
            "INSERT INTO consumed_jtis(jti,expires_at) VALUES(?,?) ON CONFLICT(jti) DO NOTHING",
        )
        .bind(input.jti)
        .bind(input.expires_at)
        .execute(&mut *tx)
        .await?;
        let nonce_insert = sqlx::query("INSERT INTO consumed_nonces(nonce,expires_at) VALUES(?,?) ON CONFLICT(nonce) DO NOTHING")
            .bind(input.nonce).bind(input.expires_at).execute(&mut *tx).await?;
        if jti_insert.rows_affected() != 1 || nonce_insert.rows_affected() != 1 {
            tx.rollback().await?;
            return Ok(ReceiveOperation::Replay);
        }
        sqlx::query("INSERT INTO effect_operations(effect_operation_id,permit_id,jti,nonce,idempotency_key,tenant,request_digest,state,created_at,updated_at) VALUES(?,?,?,?,?,'NON_PRODUCTION_DEMO',?,'RECEIVED',?,?)")
            .bind(input.operation_id).bind(input.permit_id).bind(input.jti).bind(input.nonce).bind(input.idempotency_key)
            .bind(input.request_digest).bind(input.now).bind(input.now).execute(&mut *tx).await?;
        tx.commit().await?;
        Ok(ReceiveOperation::Ready)
    }

    /// Marks an operation `STARTED` before invoking its executor.
    ///
    /// # Errors
    /// Returns the underlying `SQLite` error or a protocol error for an invalid transition.
    pub async fn mark_started(&self, operation_id: &str, now: i64) -> Result<(), sqlx::Error> {
        let result = sqlx::query("UPDATE effect_operations SET state='STARTED',updated_at=? WHERE effect_operation_id=? AND state='RECEIVED'")
            .bind(now).bind(operation_id).execute(&self.pool).await?;
        if result.rows_affected() == 1 {
            Ok(())
        } else {
            Err(sqlx::Error::Protocol(
                "operation is not RECEIVED".to_owned(),
            ))
        }
    }

    /// Persists a certain result before it is returned to the caller.
    ///
    /// # Errors
    /// Returns the underlying `SQLite` error or a protocol error for an invalid transition.
    pub async fn complete_operation(
        &self,
        operation_id: &str,
        digest: &str,
        result_json: &str,
        now: i64,
    ) -> Result<(), sqlx::Error> {
        let result = sqlx::query("UPDATE effect_operations SET state='COMPLETED',result_digest=?,result_json=?,updated_at=? WHERE effect_operation_id=? AND state='STARTED'")
            .bind(digest).bind(result_json).bind(now).bind(operation_id).execute(&self.pool).await?;
        if result.rows_affected() == 1 {
            Ok(())
        } else {
            Err(sqlx::Error::Protocol("operation is not STARTED".to_owned()))
        }
    }

    /// Persists a certain executor failure without replaying it.
    ///
    /// # Errors
    /// Returns the underlying `SQLite` error.
    pub async fn fail_operation(&self, operation_id: &str, now: i64) -> Result<(), sqlx::Error> {
        sqlx::query("UPDATE effect_operations SET state='FAILED',updated_at=? WHERE effect_operation_id=? AND state='STARTED'")
            .bind(now).bind(operation_id).execute(&self.pool).await?;
        Ok(())
    }

    /// Reads the closed state of an operation.
    ///
    /// # Errors
    /// Returns the underlying `SQLite` error or a protocol error for unknown stored state.
    pub async fn operation_state(
        &self,
        operation_id: &str,
    ) -> Result<Option<OperationState>, sqlx::Error> {
        let state: Option<String> =
            sqlx::query_scalar("SELECT state FROM effect_operations WHERE effect_operation_id=?")
                .bind(operation_id)
                .fetch_optional(&self.pool)
                .await?;
        state
            .map(|value| match value.as_str() {
                "RECEIVED" => Ok(OperationState::Received),
                "STARTED" => Ok(OperationState::Started),
                "COMPLETED" => Ok(OperationState::Completed),
                "FAILED" => Ok(OperationState::Failed),
                "AMBIGUOUS" => Ok(OperationState::Ambiguous),
                _ => Err(sqlx::Error::Protocol("unknown operation state".to_owned())),
            })
            .transpose()
    }
    /// Persists the current epochs for an instance.
    ///
    /// # Errors
    /// Returns the underlying `SQLite` error.
    pub async fn set_epoch(
        &self,
        instance: &str,
        session: u64,
        containment: u64,
    ) -> Result<(), sqlx::Error> {
        sqlx::query("INSERT INTO instance_epochs VALUES(?,?,?) ON CONFLICT(instance_id) DO UPDATE SET session_epoch=excluded.session_epoch,containment_epoch=MAX(containment_epoch,excluded.containment_epoch)")
            .bind(instance).bind(i64::try_from(session).map_err(numeric)?).bind(i64::try_from(containment).map_err(numeric)?).execute(&self.pool).await?;
        Ok(())
    }
    /// Loads the current epochs for an instance.
    ///
    /// # Errors
    /// Returns the underlying `SQLite` error.
    pub async fn epochs(&self, instance: &str) -> Result<Option<(u64, u64)>, sqlx::Error> {
        let row = sqlx::query(
            "SELECT session_epoch,containment_epoch FROM instance_epochs WHERE instance_id=?",
        )
        .bind(instance)
        .fetch_optional(&self.pool)
        .await?;
        row.map(|r| {
            Ok((
                u64::try_from(r.try_get::<i64, _>(0)?).map_err(numeric)?,
                u64::try_from(r.try_get::<i64, _>(1)?).map_err(numeric)?,
            ))
        })
        .transpose()
    }
    /// Atomically records a nonce if it has not already been consumed.
    ///
    /// # Errors
    /// Returns the underlying `SQLite` error.
    pub async fn consume_nonce(&self, nonce: &str, expires: i64) -> Result<bool, sqlx::Error> {
        let result = sqlx::query("INSERT OR IGNORE INTO consumed_nonces VALUES(?,?)")
            .bind(nonce)
            .bind(expires)
            .execute(&self.pool)
            .await?;
        Ok(result.rows_affected() == 1)
    }
    /// Applies a monotonic containment epoch.
    ///
    /// # Errors
    /// Returns the underlying `SQLite` error.
    pub async fn apply_containment(
        &self,
        instance: &str,
        epoch: u64,
        digest: &str,
    ) -> Result<ApplyResult, sqlx::Error> {
        let epoch = i64::try_from(epoch).map_err(numeric)?;
        let mut tx = self.pool.begin().await?;
        let current: Option<i64> =
            sqlx::query_scalar("SELECT containment_epoch FROM instance_epochs WHERE instance_id=?")
                .bind(instance)
                .fetch_optional(&mut *tx)
                .await?;
        if current.is_some_and(|value| epoch < value) {
            return Ok(ApplyResult::Regressive);
        }
        if current == Some(epoch) {
            return Ok(ApplyResult::AlreadyApplied);
        }
        sqlx::query("INSERT INTO instance_epochs VALUES(?,0,?) ON CONFLICT(instance_id) DO UPDATE SET containment_epoch=excluded.containment_epoch").bind(instance).bind(epoch).execute(&mut *tx).await?;
        sqlx::query("INSERT INTO containment_events VALUES(?,?,?)")
            .bind(instance)
            .bind(epoch)
            .bind(digest)
            .execute(&mut *tx)
            .await?;
        tx.commit().await?;
        Ok(ApplyResult::Applied)
    }
    /// Records the digest of an executed result.
    ///
    /// # Errors
    /// Returns the underlying `SQLite` error.
    pub async fn record_result(
        &self,
        nonce: &str,
        digest: &str,
        now: i64,
    ) -> Result<(), sqlx::Error> {
        sqlx::query("INSERT INTO result_digests VALUES(?,?,?)")
            .bind(nonce)
            .bind(digest)
            .bind(now)
            .execute(&self.pool)
            .await?;
        Ok(())
    }
}
fn numeric(_: std::num::TryFromIntError) -> sqlx::Error {
    sqlx::Error::Protocol("numeric range error".to_owned())
}

#[cfg(test)]
mod tests {
    use super::{OperationState, PepStore, ReceiveOperation, ReceiveOperationInput};
    use std::str::FromStr;

    fn operation<'a>(
        id: &'a str,
        jti: &'a str,
        nonce: &'a str,
        key: &'a str,
    ) -> ReceiveOperationInput<'a> {
        ReceiveOperationInput {
            operation_id: id,
            permit_id: id,
            jti,
            nonce,
            idempotency_key: key,
            request_digest: "digest",
            expires_at: 2_000,
            now: 1_000,
        }
    }

    #[tokio::test]
    async fn jti_registry_replay_rejected_after_restart() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("pep.db");
        let url = format!("sqlite://{}", path.display());
        let first = PepStore::connect(&url).await.unwrap();
        assert_eq!(
            first
                .receive_operation(&operation("op-1", "persistent-jti", "nonce-1", "request-1"))
                .await
                .unwrap(),
            ReceiveOperation::Ready
        );
        drop(first);
        let restarted = PepStore::connect(&url).await.unwrap();
        assert_eq!(
            restarted
                .receive_operation(&operation("op-2", "persistent-jti", "nonce-2", "request-2"))
                .await
                .unwrap(),
            ReceiveOperation::Replay
        );
    }

    #[tokio::test]
    async fn nonce_replay_rejected_after_restart() {
        let directory = tempfile::tempdir().unwrap();
        let url = format!("sqlite://{}", directory.path().join("nonce.db").display());
        let first = PepStore::connect(&url).await.unwrap();
        assert_eq!(
            first
                .receive_operation(&operation("op-1", "jti-1", "persistent-nonce", "request-1"))
                .await
                .unwrap(),
            ReceiveOperation::Ready
        );
        drop(first);
        let restarted = PepStore::connect(&url).await.unwrap();
        assert_eq!(
            restarted
                .receive_operation(&operation("op-2", "jti-2", "persistent-nonce", "request-2"))
                .await
                .unwrap(),
            ReceiveOperation::Replay
        );
    }

    #[tokio::test]
    async fn effect_operation_is_persisted_before_executor_call() {
        let store = PepStore::connect("sqlite::memory:").await.unwrap();
        assert_eq!(
            store
                .receive_operation(&operation("op", "jti", "nonce", "request"))
                .await
                .unwrap(),
            ReceiveOperation::Ready
        );
        assert_eq!(
            store.operation_state("op").await.unwrap(),
            Some(OperationState::Received)
        );
        store.mark_started("op", 1_001).await.unwrap();
        assert_eq!(
            store.operation_state("op").await.unwrap(),
            Some(OperationState::Started)
        );
    }

    #[tokio::test]
    async fn started_operation_becomes_ambiguous_after_restart() {
        let directory = tempfile::tempdir().unwrap();
        let url = format!("sqlite://{}", directory.path().join("started.db").display());
        let first = PepStore::connect(&url).await.unwrap();
        first
            .receive_operation(&operation("op", "jti", "nonce", "request"))
            .await
            .unwrap();
        first.mark_started("op", 1_001).await.unwrap();
        drop(first);
        let restarted = PepStore::connect(&url).await.unwrap();
        assert_eq!(
            restarted
                .receive_operation(&operation("op", "jti", "nonce", "request"))
                .await
                .unwrap(),
            ReceiveOperation::Ambiguous
        );
        assert_eq!(
            restarted.operation_state("op").await.unwrap(),
            Some(OperationState::Ambiguous)
        );
    }

    #[tokio::test]
    async fn ambiguous_registry_entry_remains_non_executable() {
        let store = PepStore::connect("sqlite::memory:").await.unwrap();
        store
            .receive_operation(&operation("op", "jti", "nonce", "request"))
            .await
            .unwrap();
        store.mark_started("op", 1_001).await.unwrap();
        assert_eq!(
            store
                .receive_operation(&operation("op", "jti", "nonce", "request"))
                .await
                .unwrap(),
            ReceiveOperation::Ambiguous
        );
        assert_eq!(
            store
                .receive_operation(&operation("op", "jti", "nonce", "request"))
                .await
                .unwrap(),
            ReceiveOperation::Ambiguous
        );
    }

    #[tokio::test]
    async fn restart_preserves_existing_rows() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("preserved.db");
        let url = format!("sqlite://{}", path.display());
        let first = PepStore::connect(&url).await.unwrap();
        first.set_epoch("instance", 4, 7).await.unwrap();
        first.record_result("nonce", "digest", 1_000).await.unwrap();
        drop(first);
        let restarted = PepStore::connect(&url).await.unwrap();
        assert_eq!(restarted.epochs("instance").await.unwrap(), Some((4, 7)));
        let result: String =
            sqlx::query_scalar("SELECT result_digest FROM result_digests WHERE nonce='nonce'")
                .fetch_one(&restarted.pool)
                .await
                .unwrap();
        assert_eq!(result, "digest");
    }

    #[tokio::test]
    async fn migrations_on_existing_database_preserve_old_rows() {
        let directory = tempfile::tempdir().unwrap();
        let url = format!("sqlite://{}", directory.path().join("legacy.db").display());
        let options = sqlx::sqlite::SqliteConnectOptions::from_str(&url)
            .unwrap()
            .create_if_missing(true);
        let pool = sqlx::sqlite::SqlitePoolOptions::new()
            .connect_with(options)
            .await
            .unwrap();
        sqlx::raw_sql(include_str!("../migrations/0001_initial.sql"))
            .execute(&pool)
            .await
            .unwrap();
        sqlx::query("INSERT INTO instance_epochs VALUES('legacy',4,7)")
            .execute(&pool)
            .await
            .unwrap();
        sqlx::query("INSERT INTO result_digests VALUES('legacy-nonce','legacy-digest',1)")
            .execute(&pool)
            .await
            .unwrap();
        pool.close().await;
        let migrated = PepStore::connect(&url).await.unwrap();
        assert_eq!(migrated.epochs("legacy").await.unwrap(), Some((4, 7)));
        let digest: String = sqlx::query_scalar(
            "SELECT result_digest FROM result_digests WHERE nonce='legacy-nonce'",
        )
        .fetch_one(&migrated.pool)
        .await
        .unwrap();
        assert_eq!(digest, "legacy-digest");
    }
}
