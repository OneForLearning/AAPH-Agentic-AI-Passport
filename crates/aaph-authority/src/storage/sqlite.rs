//! `SQLite` repositories with explicit transactions and domain reconstruction.

use std::str::FromStr;

use aaph_core::action::{ActionKind, CanonicalActionRequest};
use aaph_core::agent::AgentDefinition;
use aaph_core::audit::{build_audit_event, genesis_hash};
use aaph_core::budget::BudgetAmounts;
use aaph_core::canonical::canonical_json;
use aaph_core::crypto::Digest384Value;
use aaph_core::ids::{
    AgentId, BudgetId, BudgetReservationId, InstanceId, MandateId, ReleaseId, SessionId,
};
use aaph_core::mandate::Mandate;
use aaph_core::permit::{AuditEvent, DecisionRecord};
use aaph_core::state::InstanceState;
use aaph_core::UtcTimestamp;
use async_trait::async_trait;
use sqlx::sqlite::{SqliteConnectOptions, SqlitePoolOptions};
use sqlx::{Row, SqliteConnection, SqlitePool};

static MIGRATOR: sqlx::migrate::Migrator = sqlx::migrate!("./migrations");

use super::{
    AuditRepository, BudgetRepository, ContainmentResult, DecisionRepository, DefinitionRepository,
    InstanceSnapshot, StateRepository, StorageError,
};

#[derive(Debug, Clone)]
pub struct SqliteStore {
    pool: SqlitePool,
}

impl SqliteStore {
    /// Opens `SQLite` with foreign keys enabled on every pooled connection.
    ///
    /// # Errors
    /// Returns an error for an invalid URL or connection failure.
    pub async fn connect(database_url: &str) -> Result<Self, StorageError> {
        let options = SqliteConnectOptions::from_str(database_url)
            .map_err(StorageError::Database)?
            .create_if_missing(true)
            .foreign_keys(true);
        let pool = SqlitePoolOptions::new()
            .max_connections(8)
            .after_connect(|connection, _| {
                Box::pin(async move {
                    sqlx::query("PRAGMA foreign_keys = ON")
                        .execute(connection)
                        .await?;
                    Ok(())
                })
            })
            .connect_with(options)
            .await?;
        Ok(Self { pool })
    }

    /// Applies all embedded, versioned migrations.
    ///
    /// # Errors
    /// Returns an error if a migration fails.
    pub async fn migrate(&self) -> Result<(), StorageError> {
        MIGRATOR
            .run(&self.pool)
            .await
            .map_err(StorageError::Migration)
    }

    #[must_use]
    pub const fn pool(&self) -> &SqlitePool {
        &self.pool
    }
}

fn canonical_string<T: serde::Serialize>(value: &T) -> Result<String, StorageError> {
    String::from_utf8(canonical_json(value)?).map_err(|_| StorageError::InvalidStoredData)
}

fn to_i64(value: u64) -> Result<i64, StorageError> {
    i64::try_from(value).map_err(|_| StorageError::NumericOverflow)
}

fn to_u64(value: i64) -> Result<u64, StorageError> {
    u64::try_from(value).map_err(|_| StorageError::InvalidStoredData)
}

async fn begin_immediate(connection: &mut SqliteConnection) -> Result<(), StorageError> {
    sqlx::query("BEGIN IMMEDIATE").execute(connection).await?;
    Ok(())
}

async fn rollback(connection: &mut SqliteConnection) {
    let _ignored = sqlx::query("ROLLBACK").execute(connection).await;
}

async fn commit_transaction(connection: &mut SqliteConnection) -> Result<(), StorageError> {
    sqlx::query("COMMIT").execute(connection).await?;
    Ok(())
}

#[async_trait]
impl DefinitionRepository for SqliteStore {
    async fn put_agent_definition(&self, value: &AgentDefinition) -> Result<(), StorageError> {
        let json = canonical_string(value)?;
        sqlx::query("INSERT INTO agent_definitions(agent_id,current_release_id,canonical_json) VALUES(?,?,?)")
            .bind(value.agent_id.as_str())
            .bind(value.current_release_id.as_str())
            .bind(json)
            .execute(&self.pool)
            .await?;
        Ok(())
    }

    async fn get_agent_definition(&self, id: &AgentId) -> Result<AgentDefinition, StorageError> {
        let row = sqlx::query("SELECT agent_id,current_release_id,canonical_json FROM agent_definitions WHERE agent_id=?")
            .bind(id.as_str())
            .fetch_one(&self.pool)
            .await?;
        let json: String = row.try_get("canonical_json")?;
        let value: AgentDefinition = serde_json::from_str(&json)?;
        let stored_agent: String = row.try_get("agent_id")?;
        let stored_release: String = row.try_get("current_release_id")?;
        if value.agent_id.as_str() != stored_agent
            || value.current_release_id.as_str() != stored_release
        {
            return Err(StorageError::InvalidStoredData);
        }
        Ok(value)
    }

    async fn put_release_and_manifest(
        &self,
        release_id: &ReleaseId,
        agent_id: &AgentId,
        release_json: &str,
        manifest_json: &str,
        manifest_digest: &str,
    ) -> Result<(), StorageError> {
        let mut connection = self.pool.acquire().await?;
        begin_immediate(&mut connection).await?;
        let result = async {
            sqlx::query(
                "INSERT INTO agent_releases(release_id,agent_id,canonical_json) VALUES(?,?,?)",
            )
            .bind(release_id.as_str())
            .bind(agent_id.as_str())
            .bind(release_json)
            .execute(&mut *connection)
            .await?;
            sqlx::query(
                "INSERT INTO behavioral_manifests(release_id,digest,canonical_json) VALUES(?,?,?)",
            )
            .bind(release_id.as_str())
            .bind(manifest_digest)
            .bind(manifest_json)
            .execute(&mut *connection)
            .await?;
            Ok::<(), sqlx::Error>(())
        }
        .await;
        if let Err(error) = result {
            rollback(&mut connection).await;
            return Err(StorageError::Database(error));
        }
        commit_transaction(&mut connection).await
    }

    async fn put_mandate(&self, value: &Mandate) -> Result<(), StorageError> {
        let json = canonical_string(value)?;
        sqlx::query("INSERT INTO mandates(mandate_id,agent_id,budget_id,not_before,expires_at,canonical_json) VALUES(?,?,?,?,?,?)")
            .bind(value.mandate_id.as_str()).bind(value.agent_id.as_str()).bind(value.budget_id.as_str())
            .bind(value.not_before.unix_seconds()).bind(value.expires_at.unix_seconds()).bind(json)
            .execute(&self.pool).await?;
        Ok(())
    }

    async fn get_mandate(&self, id: &MandateId) -> Result<Mandate, StorageError> {
        let row = sqlx::query("SELECT mandate_id,agent_id,budget_id,not_before,expires_at,canonical_json FROM mandates WHERE mandate_id=?")
            .bind(id.as_str()).fetch_one(&self.pool).await?;
        let json: String = row.try_get("canonical_json")?;
        let value: Mandate = serde_json::from_str(&json)?;
        let identifiers_match = value.mandate_id.as_str()
            == row.try_get::<String, _>("mandate_id")?
            && value.agent_id.as_str() == row.try_get::<String, _>("agent_id")?
            && value.budget_id.as_str() == row.try_get::<String, _>("budget_id")?;
        let dates_match = value.not_before.unix_seconds() == row.try_get::<i64, _>("not_before")?
            && value.expires_at.unix_seconds() == row.try_get::<i64, _>("expires_at")?;
        if !identifiers_match || !dates_match || value.expires_at <= value.not_before {
            return Err(StorageError::InvalidStoredData);
        }
        Ok(value)
    }
}

#[async_trait]
impl StateRepository for SqliteStore {
    async fn create_instance(
        &self,
        instance_id: &InstanceId,
        agent_id: &AgentId,
        release_id: &ReleaseId,
        public_key: &str,
        fingerprint: &str,
    ) -> Result<(), StorageError> {
        sqlx::query("INSERT INTO agent_instances(instance_id,agent_id,release_id,public_key,key_fingerprint,state,containment_epoch) VALUES(?,?,?,?,?,'ACTIVE',0)")
            .bind(instance_id.as_str()).bind(agent_id.as_str()).bind(release_id.as_str()).bind(public_key).bind(fingerprint)
            .execute(&self.pool).await?;
        Ok(())
    }

    async fn get_instance(&self, id: &InstanceId) -> Result<InstanceSnapshot, StorageError> {
        let row = sqlx::query(
            "SELECT instance_id,state,containment_epoch FROM agent_instances WHERE instance_id=?",
        )
        .bind(id.as_str())
        .fetch_one(&self.pool)
        .await?;
        let state = match row.try_get::<String, _>("state")?.as_str() {
            "ACTIVE" => InstanceState::Active,
            "CONTAINED" => InstanceState::Contained,
            "RECOVERY_PENDING" => InstanceState::RecoveryPending,
            "REVOKED" => InstanceState::Revoked,
            _ => return Err(StorageError::InvalidStoredData),
        };
        Ok(InstanceSnapshot {
            instance_id: InstanceId::new(row.try_get::<String, _>("instance_id")?)
                .map_err(|_| StorageError::InvalidStoredData)?,
            state,
            containment_epoch: to_u64(row.try_get("containment_epoch")?)?,
        })
    }

    async fn advance_containment_epoch(
        &self,
        id: &InstanceId,
        expected_epoch: u64,
    ) -> Result<u64, StorageError> {
        let expected = to_i64(expected_epoch)?;
        let result = sqlx::query("UPDATE agent_instances SET state='CONTAINED', containment_epoch=containment_epoch+1 WHERE instance_id=? AND containment_epoch=? AND containment_epoch<9223372036854775807")
            .bind(id.as_str()).bind(expected).execute(&self.pool).await?;
        if result.rows_affected() != 1 {
            return Err(StorageError::StaleEpoch);
        }
        expected_epoch
            .checked_add(1)
            .ok_or(StorageError::NumericOverflow)
    }

    async fn create_session(
        &self,
        session_id: &SessionId,
        instance_id: &InstanceId,
        created_at: UtcTimestamp,
        expires_at: UtcTimestamp,
    ) -> Result<(), StorageError> {
        if expires_at <= created_at {
            return Err(StorageError::InvalidStoredData);
        }
        sqlx::query("INSERT INTO agent_sessions(session_id,instance_id,state,session_epoch,created_at,expires_at) VALUES(?,?,'ACTIVE',0,?,?)")
            .bind(session_id.as_str()).bind(instance_id.as_str()).bind(created_at.unix_seconds()).bind(expires_at.unix_seconds())
            .execute(&self.pool).await?;
        Ok(())
    }

    async fn contain_instance(&self, id: &InstanceId) -> Result<ContainmentResult, StorageError> {
        let mut connection = self.pool.acquire().await?;
        begin_immediate(&mut connection).await?;
        let result = async {
            let row = sqlx::query("SELECT state,containment_epoch FROM agent_instances WHERE instance_id=?")
                .bind(id.as_str()).fetch_one(&mut *connection).await?;
            let state:String=row.try_get("state")?; let epoch:i64=row.try_get("containment_epoch")?;
            if state != "ACTIVE" { return Ok::<_,sqlx::Error>((epoch,false)); }
            let updated=epoch.checked_add(1).ok_or_else(||sqlx::Error::Protocol("epoch overflow".to_owned()))?;
            sqlx::query("UPDATE budget_ledgers SET action_reserved=action_reserved-COALESCE((SELECT SUM(r.action_count) FROM budget_reservations r JOIN agent_sessions s ON s.session_id=r.session_id WHERE r.budget_id=budget_ledgers.budget_id AND s.instance_id=? AND r.state='RESERVED'),0),read_reserved=read_reserved-COALESCE((SELECT SUM(r.read_bytes) FROM budget_reservations r JOIN agent_sessions s ON s.session_id=r.session_id WHERE r.budget_id=budget_ledgers.budget_id AND s.instance_id=? AND r.state='RESERVED'),0),write_reserved=write_reserved-COALESCE((SELECT SUM(r.write_bytes) FROM budget_reservations r JOIN agent_sessions s ON s.session_id=r.session_id WHERE r.budget_id=budget_ledgers.budget_id AND s.instance_id=? AND r.state='RESERVED'),0)").bind(id.as_str()).bind(id.as_str()).bind(id.as_str()).execute(&mut *connection).await?;
            sqlx::query("UPDATE budget_reservations SET state='RELEASED' WHERE state='RESERVED' AND session_id IN (SELECT session_id FROM agent_sessions WHERE instance_id=?)").bind(id.as_str()).execute(&mut *connection).await?;
            sqlx::query("UPDATE agent_sessions SET state='TERMINATED' WHERE instance_id=? AND state IN ('CREATED','ACTIVE')").bind(id.as_str()).execute(&mut *connection).await?;
            sqlx::query("UPDATE agent_instances SET state='CONTAINED',containment_epoch=? WHERE instance_id=? AND state='ACTIVE' AND containment_epoch=?").bind(updated).bind(id.as_str()).bind(epoch).execute(&mut *connection).await?;
            Ok((updated,true))
        }.await;
        match result {
            Ok((epoch, changed)) => {
                commit_transaction(&mut connection).await?;
                Ok(ContainmentResult {
                    epoch: to_u64(epoch)?,
                    changed,
                })
            }
            Err(error) => {
                rollback(&mut connection).await;
                Err(StorageError::Database(error))
            }
        }
    }

    async fn recover_instance(&self, id: &InstanceId) -> Result<u64, StorageError> {
        let mut connection = self.pool.acquire().await?;
        begin_immediate(&mut connection).await?;
        let result=async{
            let row=sqlx::query("SELECT state,containment_epoch FROM agent_instances WHERE instance_id=?").bind(id.as_str()).fetch_one(&mut *connection).await?;
            if row.try_get::<String,_>("state")? != "CONTAINED" { return Err(sqlx::Error::Protocol("instance is not contained".to_owned())); }
            sqlx::query("UPDATE agent_instances SET state='RECOVERY_PENDING' WHERE instance_id=? AND state='CONTAINED'").bind(id.as_str()).execute(&mut *connection).await?;
            row.try_get("containment_epoch")
        }.await;
        match result {
            Ok(epoch) => {
                commit_transaction(&mut connection).await?;
                to_u64(epoch)
            }
            Err(error) => {
                rollback(&mut connection).await;
                Err(StorageError::Database(error))
            }
        }
    }

    async fn activate_recovered(&self, id: &InstanceId) -> Result<(), StorageError> {
        let result = sqlx::query("UPDATE agent_instances SET state='ACTIVE' WHERE instance_id=? AND state='RECOVERY_PENDING'")
            .bind(id.as_str()).execute(&self.pool).await?;
        if result.rows_affected() != 1 {
            return Err(StorageError::InvalidStoredData);
        }
        Ok(())
    }
}

#[async_trait]
impl BudgetRepository for SqliteStore {
    async fn create_budget(
        &self,
        budget_id: &BudgetId,
        mandate_id: &MandateId,
        capacity: BudgetAmounts,
    ) -> Result<(), StorageError> {
        sqlx::query("INSERT INTO budget_ledgers(budget_id,mandate_id,action_capacity,read_capacity,write_capacity) VALUES(?,?,?,?,?)")
            .bind(budget_id.as_str()).bind(mandate_id.as_str()).bind(to_i64(capacity.action_count)?)
            .bind(to_i64(capacity.read_bytes)?).bind(to_i64(capacity.write_bytes)?)
            .execute(&self.pool).await?;
        Ok(())
    }

    async fn reserve(
        &self,
        reservation_id: &BudgetReservationId,
        budget_id: &BudgetId,
        session_id: &SessionId,
        amounts: BudgetAmounts,
    ) -> Result<(), StorageError> {
        let action = to_i64(amounts.action_count)?;
        let read = to_i64(amounts.read_bytes)?;
        let write = to_i64(amounts.write_bytes)?;
        let mut connection = self.pool.acquire().await?;
        begin_immediate(&mut connection).await?;
        let update = sqlx::query("UPDATE budget_ledgers SET action_reserved=action_reserved+?,read_reserved=read_reserved+?,write_reserved=write_reserved+? WHERE budget_id=? AND action_consumed+action_reserved+?<=action_capacity AND read_consumed+read_reserved+?<=read_capacity AND write_consumed+write_reserved+?<=write_capacity")
            .bind(action).bind(read).bind(write).bind(budget_id.as_str()).bind(action).bind(read).bind(write)
            .execute(&mut *connection).await;
        let update = match update {
            Ok(value) if value.rows_affected() == 1 => value,
            Ok(_) => {
                rollback(&mut connection).await;
                return Err(StorageError::BudgetExceeded);
            }
            Err(error) => {
                rollback(&mut connection).await;
                return Err(StorageError::Database(error));
            }
        };
        let _updated = update;
        let insert = sqlx::query("INSERT INTO budget_reservations(reservation_id,budget_id,session_id,state,action_count,read_bytes,write_bytes) VALUES(?,?,?,'RESERVED',?,?,?)")
            .bind(reservation_id.as_str()).bind(budget_id.as_str()).bind(session_id.as_str())
            .bind(action).bind(read).bind(write).execute(&mut *connection).await;
        if let Err(error) = insert {
            rollback(&mut connection).await;
            return Err(StorageError::Database(error));
        }
        commit_transaction(&mut connection).await
    }

    async fn commit(&self, reservation_id: &BudgetReservationId) -> Result<(), StorageError> {
        transition_reservation(&self.pool, reservation_id, true).await
    }

    async fn release(&self, reservation_id: &BudgetReservationId) -> Result<(), StorageError> {
        transition_reservation(&self.pool, reservation_id, false).await
    }

    async fn close_session(&self, session_id: &SessionId) -> Result<(), StorageError> {
        let mut connection = self.pool.acquire().await?;
        begin_immediate(&mut connection).await?;
        let rows = sqlx::query("SELECT reservation_id FROM budget_reservations WHERE session_id=? AND state='RESERVED'")
            .bind(session_id.as_str()).fetch_all(&mut *connection).await;
        let rows = match rows {
            Ok(rows) => rows,
            Err(error) => {
                rollback(&mut connection).await;
                return Err(StorageError::Database(error));
            }
        };
        for row in rows {
            let id: String = row.try_get("reservation_id")?;
            if let Err(error) =
                transition_reservation_on_connection(&mut connection, &id, false).await
            {
                rollback(&mut connection).await;
                return Err(error);
            }
        }
        let update = sqlx::query("UPDATE agent_sessions SET state='TERMINATED' WHERE session_id=? AND state IN ('CREATED','ACTIVE')")
            .bind(session_id.as_str()).execute(&mut *connection).await;
        if let Err(error) = update {
            rollback(&mut connection).await;
            return Err(StorageError::Database(error));
        }
        commit_transaction(&mut connection).await
    }

    async fn budget_totals(
        &self,
        budget_id: &BudgetId,
    ) -> Result<(BudgetAmounts, BudgetAmounts), StorageError> {
        let row = sqlx::query("SELECT action_consumed,read_consumed,write_consumed,action_reserved,read_reserved,write_reserved FROM budget_ledgers WHERE budget_id=?")
            .bind(budget_id.as_str()).fetch_one(&self.pool).await?;
        Ok((
            BudgetAmounts {
                action_count: to_u64(row.try_get("action_consumed")?)?,
                read_bytes: to_u64(row.try_get("read_consumed")?)?,
                write_bytes: to_u64(row.try_get("write_consumed")?)?,
            },
            BudgetAmounts {
                action_count: to_u64(row.try_get("action_reserved")?)?,
                read_bytes: to_u64(row.try_get("read_reserved")?)?,
                write_bytes: to_u64(row.try_get("write_reserved")?)?,
            },
        ))
    }
}

async fn transition_reservation(
    pool: &SqlitePool,
    id: &BudgetReservationId,
    commit: bool,
) -> Result<(), StorageError> {
    let mut connection = pool.acquire().await?;
    begin_immediate(&mut connection).await?;
    let result = transition_reservation_on_connection(&mut connection, id.as_str(), commit).await;
    if let Err(error) = result {
        rollback(&mut connection).await;
        return Err(error);
    }
    commit_transaction(&mut connection).await
}

async fn transition_reservation_on_connection(
    connection: &mut SqliteConnection,
    id: &str,
    commit: bool,
) -> Result<(), StorageError> {
    let row = sqlx::query("SELECT budget_id,state,action_count,read_bytes,write_bytes FROM budget_reservations WHERE reservation_id=?")
        .bind(id).fetch_optional(&mut *connection).await?.ok_or(StorageError::UnknownReservation)?;
    let state: String = row.try_get("state")?;
    if commit && state == "COMMITTED" {
        return Err(StorageError::AlreadyCommitted);
    }
    if commit && state == "RELEASED" {
        return Err(StorageError::CommitAfterRelease);
    }
    if !commit && state == "RELEASED" {
        return Ok(());
    }
    if !commit && state == "COMMITTED" {
        return Err(StorageError::ReleaseAfterCommit);
    }
    if state != "RESERVED" {
        return Err(StorageError::InvalidStoredData);
    }
    let budget_id: String = row.try_get("budget_id")?;
    let action: i64 = row.try_get("action_count")?;
    let read: i64 = row.try_get("read_bytes")?;
    let write: i64 = row.try_get("write_bytes")?;
    if commit {
        sqlx::query("UPDATE budget_ledgers SET action_reserved=action_reserved-?,read_reserved=read_reserved-?,write_reserved=write_reserved-?,action_consumed=action_consumed+?,read_consumed=read_consumed+?,write_consumed=write_consumed+? WHERE budget_id=?")
            .bind(action).bind(read).bind(write).bind(action).bind(read).bind(write).bind(&budget_id).execute(&mut *connection).await?;
        sqlx::query("UPDATE budget_reservations SET state='COMMITTED' WHERE reservation_id=? AND state='RESERVED'")
            .bind(id).execute(&mut *connection).await?;
    } else {
        sqlx::query("UPDATE budget_ledgers SET action_reserved=action_reserved-?,read_reserved=read_reserved-?,write_reserved=write_reserved-? WHERE budget_id=?")
            .bind(action).bind(read).bind(write).bind(&budget_id).execute(&mut *connection).await?;
        sqlx::query("UPDATE budget_reservations SET state='RELEASED' WHERE reservation_id=? AND state='RESERVED'")
            .bind(id).execute(&mut *connection).await?;
    }
    Ok(())
}

fn action_name(action: ActionKind) -> &'static str {
    match action {
        ActionKind::ListDirectory => "LIST_DIRECTORY",
        ActionKind::ReadFile => "READ_FILE",
        ActionKind::ComputeSha256 => "COMPUTE_SHA256",
        ActionKind::WriteReport => "WRITE_REPORT",
    }
}

#[async_trait]
impl DecisionRepository for SqliteStore {
    async fn record_request_and_decision(
        &self,
        request: &CanonicalActionRequest,
        request_digest: &str,
        decision: &DecisionRecord,
    ) -> Result<(), StorageError> {
        if request.request_id() != &decision.request_id {
            return Err(StorageError::InvalidStoredData);
        }
        let request_json = canonical_string(request)?;
        let decision_json = canonical_string(decision)?;
        let decision_name = serde_json::to_string(&decision.decision)?;
        let reason_name = serde_json::to_string(&decision.reason)?;
        let mut connection = self.pool.acquire().await?;
        begin_immediate(&mut connection).await?;
        let result = async {
            sqlx::query("INSERT INTO action_requests(request_id,session_id,action_kind,resource,request_digest,canonical_json) VALUES(?,?,?,?,?,?)")
                .bind(request.request_id().as_str())
                .bind(request.session_id().as_str())
                .bind(action_name(request.action()))
                .bind(request.resource())
                .bind(request_digest)
                .bind(request_json)
                .execute(&mut *connection)
                .await?;
            sqlx::query("INSERT INTO decision_records(request_id,decision,reason_code,decided_at,canonical_json) VALUES(?,?,?,?,?)")
                .bind(decision.request_id.as_str())
                .bind(decision_name.trim_matches('"'))
                .bind(reason_name.trim_matches('"'))
                .bind(decision.decided_at.unix_seconds())
                .bind(decision_json)
                .execute(&mut *connection)
                .await?;
            Ok::<(), sqlx::Error>(())
        }
        .await;
        if let Err(error) = result {
            rollback(&mut connection).await;
            return Err(StorageError::Database(error));
        }
        commit_transaction(&mut connection).await
    }

    async fn get_decision(
        &self,
        request_id: &aaph_core::ids::RequestId,
    ) -> Result<DecisionRecord, StorageError> {
        let row = sqlx::query(
            "SELECT request_id,decision,reason_code,decided_at,canonical_json FROM decision_records WHERE request_id=?",
        )
        .bind(request_id.as_str())
        .fetch_one(&self.pool)
        .await?;
        let value: DecisionRecord =
            serde_json::from_str(&row.try_get::<String, _>("canonical_json")?)?;
        let decision_name = serde_json::to_string(&value.decision)?;
        let reason_name = serde_json::to_string(&value.reason)?;
        let matches = value.request_id.as_str() == row.try_get::<String, _>("request_id")?
            && decision_name.trim_matches('"') == row.try_get::<String, _>("decision")?
            && reason_name.trim_matches('"') == row.try_get::<String, _>("reason_code")?
            && value.decided_at.unix_seconds() == row.try_get::<i64, _>("decided_at")?;
        if !matches {
            return Err(StorageError::InvalidStoredData);
        }
        Ok(value)
    }
}

#[async_trait]
impl AuditRepository for SqliteStore {
    async fn append_audit(
        &self,
        event_type: &str,
        subject: &str,
        payload_digest: &Digest384Value,
        timestamp: UtcTimestamp,
    ) -> Result<AuditEvent, StorageError> {
        let mut connection = self.pool.acquire().await?;
        begin_immediate(&mut connection).await?;
        let row = sqlx::query(
            "SELECT sequence,current_hash FROM audit_events ORDER BY sequence DESC LIMIT 1",
        )
        .fetch_optional(&mut *connection)
        .await;
        let (sequence, previous) = match row {
            Ok(Some(row)) => {
                let last = to_u64(row.try_get("sequence")?)?;
                let next = last.checked_add(1).ok_or(StorageError::NumericOverflow)?;
                let hash = Digest384Value::parse(row.try_get::<String, _>("current_hash")?)
                    .map_err(|_| StorageError::InvalidStoredData)?;
                (next, hash)
            }
            Ok(None) => (1, genesis_hash()?),
            Err(error) => {
                rollback(&mut connection).await;
                return Err(StorageError::Database(error));
            }
        };
        let event = build_audit_event(
            sequence,
            event_type.to_owned(),
            subject.to_owned(),
            payload_digest.clone(),
            previous,
            timestamp,
        )?;
        let json = canonical_string(&event)?;
        let insert = sqlx::query("INSERT INTO audit_events(sequence,event_type,subject,payload_digest,previous_hash,timestamp,current_hash,canonical_json) VALUES(?,?,?,?,?,?,?,?)")
            .bind(to_i64(event.sequence)?).bind(&event.event_type).bind(&event.subject).bind(event.payload_digest.as_str())
            .bind(event.previous_hash.as_str()).bind(event.timestamp.unix_seconds()).bind(event.current_hash.as_str()).bind(json)
            .execute(&mut *connection).await;
        if let Err(error) = insert {
            rollback(&mut connection).await;
            return Err(StorageError::Database(error));
        }
        commit_transaction(&mut connection).await?;
        Ok(event)
    }

    async fn load_audit_chain(&self) -> Result<Vec<AuditEvent>, StorageError> {
        let rows = sqlx::query("SELECT sequence,event_type,subject,payload_digest,previous_hash,timestamp,current_hash,canonical_json FROM audit_events ORDER BY sequence")
            .fetch_all(&self.pool).await?;
        let mut events = Vec::with_capacity(rows.len());
        for row in rows {
            let json: String = row.try_get("canonical_json")?;
            let event: AuditEvent = serde_json::from_str(&json)?;
            let matches = event.sequence == to_u64(row.try_get("sequence")?)?
                && event.event_type == row.try_get::<String, _>("event_type")?
                && event.subject == row.try_get::<String, _>("subject")?
                && event.payload_digest.as_str() == row.try_get::<String, _>("payload_digest")?
                && event.previous_hash.as_str() == row.try_get::<String, _>("previous_hash")?
                && event.timestamp.unix_seconds() == row.try_get::<i64, _>("timestamp")?
                && event.current_hash.as_str() == row.try_get::<String, _>("current_hash")?;
            if !matches {
                return Err(StorageError::InvalidStoredData);
            }
            events.push(event);
        }
        Ok(events)
    }
}

#[cfg(test)]
mod tests {
    use std::sync::atomic::{AtomicU64, Ordering};

    use aaph_core::action::{ActionKind, CanonicalActionRequest, RawActionProposal, ReasonCode};
    use aaph_core::agent::AgentDefinition;
    use aaph_core::audit::verify_audit_chain;
    use aaph_core::budget::BudgetAmounts;
    use aaph_core::ids::{
        AgentId, BudgetId, BudgetReservationId, InstanceId, MandateId, ReleaseId, SessionId,
    };
    use aaph_core::mandate::Mandate;
    use aaph_core::permit::{Decision, DecisionRecord};
    use aaph_core::state::InstanceState;
    use sqlx::Row;

    use super::*;

    static DATABASE_COUNTER: AtomicU64 = AtomicU64::new(0);

    async fn database() -> (SqliteStore, std::path::PathBuf) {
        let number = DATABASE_COUNTER.fetch_add(1, Ordering::Relaxed);
        let unique = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map_or(0, |duration| duration.as_nanos());
        let path = std::env::temp_dir().join(format!(
            "aaph-sqlite-test-{}-{unique}-{number}.db",
            std::process::id()
        ));
        let normalized = path.to_string_lossy().replace('\\', "/");
        let store = SqliteStore::connect(&format!("sqlite:///{normalized}"))
            .await
            .unwrap();
        store.migrate().await.unwrap();
        (store, path)
    }

    async fn cleanup(store: SqliteStore, path: std::path::PathBuf) {
        store.pool.close().await;
        let _ignored = std::fs::remove_file(path);
    }

    fn definition() -> AgentDefinition {
        AgentDefinition {
            agent_id: AgentId::new("agent").unwrap(),
            display_name: "Demo".to_owned(),
            current_release_id: ReleaseId::new("release").unwrap(),
            allowed_actions: vec![ActionKind::ReadFile],
            resource_prefixes: vec!["inbox/".to_owned()],
            purposes: vec!["analysis".to_owned()],
        }
    }

    fn mandate() -> Mandate {
        Mandate {
            mandate_id: MandateId::new("mandate").unwrap(),
            agent_id: AgentId::new("agent").unwrap(),
            budget_id: BudgetId::new("budget").unwrap(),
            allowed_actions: vec![ActionKind::ReadFile],
            resource_prefixes: vec!["inbox/".to_owned()],
            purposes: vec!["analysis".to_owned()],
            not_before: UtcTimestamp::from_unix_seconds(10),
            expires_at: UtcTimestamp::from_unix_seconds(20),
        }
    }

    async fn seed(store: &SqliteStore, capacity: BudgetAmounts) {
        store.put_agent_definition(&definition()).await.unwrap();
        store
            .put_release_and_manifest(
                &ReleaseId::new("release").unwrap(),
                &AgentId::new("agent").unwrap(),
                "{}",
                "{}",
                "manifest-digest",
            )
            .await
            .unwrap();
        store
            .create_instance(
                &InstanceId::new("instance").unwrap(),
                &AgentId::new("agent").unwrap(),
                &ReleaseId::new("release").unwrap(),
                "public-key",
                "fingerprint",
            )
            .await
            .unwrap();
        store
            .create_session(
                &SessionId::new("session").unwrap(),
                &InstanceId::new("instance").unwrap(),
                UtcTimestamp::from_unix_seconds(10),
                UtcTimestamp::from_unix_seconds(20),
            )
            .await
            .unwrap();
        store.put_mandate(&mandate()).await.unwrap();
        store
            .create_budget(
                &BudgetId::new("budget").unwrap(),
                &MandateId::new("mandate").unwrap(),
                capacity,
            )
            .await
            .unwrap();
    }

    #[tokio::test]
    async fn migrations_run_on_an_empty_database_and_enable_foreign_keys() {
        let (store, path) = database().await;
        let count: i64 = sqlx::query("SELECT COUNT(*) AS count FROM sqlite_master WHERE type='table' AND name IN ('agent_definitions','agent_releases','behavioral_manifests','agent_instances','agent_sessions','mandates','budget_ledgers','budget_reservations','action_requests','decision_records','execution_permits','containment_events','audit_events')")
            .fetch_one(store.pool()).await.unwrap().try_get("count").unwrap();
        assert_eq!(count, 13);
        let enabled: i64 = sqlx::query("PRAGMA foreign_keys")
            .fetch_one(store.pool())
            .await
            .unwrap()
            .try_get(0)
            .unwrap();
        assert_eq!(enabled, 1);
        cleanup(store, path).await;
    }

    #[tokio::test]
    async fn essential_domain_objects_round_trip_with_validation() {
        let (store, path) = database().await;
        seed(
            &store,
            BudgetAmounts {
                action_count: 3,
                read_bytes: 100,
                write_bytes: 50,
            },
        )
        .await;
        assert_eq!(
            store
                .get_agent_definition(&AgentId::new("agent").unwrap())
                .await
                .unwrap(),
            definition()
        );
        assert_eq!(
            store
                .get_mandate(&MandateId::new("mandate").unwrap())
                .await
                .unwrap(),
            mandate()
        );
        assert_eq!(
            store
                .get_instance(&InstanceId::new("instance").unwrap())
                .await
                .unwrap(),
            InstanceSnapshot {
                instance_id: InstanceId::new("instance").unwrap(),
                state: InstanceState::Active,
                containment_epoch: 0
            }
        );
        let request = CanonicalActionRequest::try_from(RawActionProposal {
            request_id: aaph_core::ids::RequestId::new("request").unwrap(),
            session_id: SessionId::new("session").unwrap(),
            action: "READ_FILE".to_owned(),
            resource: "inbox/file".to_owned(),
            size_bytes: Some(10),
            purpose: "analysis".to_owned(),
            destination: None,
        })
        .unwrap();
        let decision = DecisionRecord {
            request_id: request.request_id().clone(),
            decision: Decision::Deny,
            reason: ReasonCode::BudgetExceeded,
            decided_at: UtcTimestamp::from_unix_seconds(15),
        };
        store
            .record_request_and_decision(&request, "request-digest", &decision)
            .await
            .unwrap();
        assert_eq!(
            store.get_decision(request.request_id()).await.unwrap(),
            decision
        );
        cleanup(store, path).await;
    }

    #[tokio::test]
    async fn orphan_references_are_rejected() {
        let (store, path) = database().await;
        let result = store
            .create_session(
                &SessionId::new("orphan").unwrap(),
                &InstanceId::new("missing").unwrap(),
                UtcTimestamp::from_unix_seconds(1),
                UtcTimestamp::from_unix_seconds(2),
            )
            .await;
        assert!(result.is_err());
        cleanup(store, path).await;
    }

    #[tokio::test]
    async fn concurrent_reservations_near_capacity_do_not_overspend() {
        let (store, path) = database().await;
        seed(
            &store,
            BudgetAmounts {
                action_count: 1,
                read_bytes: 10,
                write_bytes: 0,
            },
        )
        .await;
        let amounts = BudgetAmounts {
            action_count: 1,
            read_bytes: 10,
            write_bytes: 0,
        };
        let first_id = BudgetReservationId::new("r1").unwrap();
        let second_id = BudgetReservationId::new("r2").unwrap();
        let budget = BudgetId::new("budget").unwrap();
        let session = SessionId::new("session").unwrap();
        let first = store.reserve(&first_id, &budget, &session, amounts);
        let second = store.reserve(&second_id, &budget, &session, amounts);
        let (first, second) = tokio::join!(first, second);
        assert_eq!(usize::from(first.is_ok()) + usize::from(second.is_ok()), 1);
        let (consumed, reserved) = store.budget_totals(&budget).await.unwrap();
        assert_eq!(consumed, BudgetAmounts::default());
        assert_eq!(reserved, amounts);
        cleanup(store, path).await;
    }

    #[tokio::test]
    async fn commit_and_release_transitions_are_enforced() {
        let (store, path) = database().await;
        seed(
            &store,
            BudgetAmounts {
                action_count: 5,
                read_bytes: 100,
                write_bytes: 100,
            },
        )
        .await;
        let budget = BudgetId::new("budget").unwrap();
        let session = SessionId::new("session").unwrap();
        let amounts = BudgetAmounts {
            action_count: 1,
            read_bytes: 10,
            write_bytes: 0,
        };
        let committed = BudgetReservationId::new("committed").unwrap();
        store
            .reserve(&committed, &budget, &session, amounts)
            .await
            .unwrap();
        store.commit(&committed).await.unwrap();
        assert!(matches!(
            store.commit(&committed).await,
            Err(StorageError::AlreadyCommitted)
        ));
        assert!(matches!(
            store.release(&committed).await,
            Err(StorageError::ReleaseAfterCommit)
        ));
        let released = BudgetReservationId::new("released").unwrap();
        store
            .reserve(&released, &budget, &session, amounts)
            .await
            .unwrap();
        store.release(&released).await.unwrap();
        store.release(&released).await.unwrap();
        assert!(matches!(
            store.commit(&released).await,
            Err(StorageError::CommitAfterRelease)
        ));
        cleanup(store, path).await;
    }

    #[tokio::test]
    async fn closing_session_releases_pending_without_resetting_consumed() {
        let (store, path) = database().await;
        seed(
            &store,
            BudgetAmounts {
                action_count: 5,
                read_bytes: 100,
                write_bytes: 100,
            },
        )
        .await;
        let budget = BudgetId::new("budget").unwrap();
        let session = SessionId::new("session").unwrap();
        let amounts = BudgetAmounts {
            action_count: 1,
            read_bytes: 10,
            write_bytes: 0,
        };
        let committed = BudgetReservationId::new("committed").unwrap();
        store
            .reserve(&committed, &budget, &session, amounts)
            .await
            .unwrap();
        store.commit(&committed).await.unwrap();
        store
            .reserve(
                &BudgetReservationId::new("pending").unwrap(),
                &budget,
                &session,
                amounts,
            )
            .await
            .unwrap();
        store.close_session(&session).await.unwrap();
        let (consumed, reserved) = store.budget_totals(&budget).await.unwrap();
        assert_eq!(consumed, amounts);
        assert_eq!(reserved, BudgetAmounts::default());
        cleanup(store, path).await;
    }

    #[tokio::test]
    async fn containment_epoch_update_is_conditional() {
        let (store, path) = database().await;
        seed(
            &store,
            BudgetAmounts {
                action_count: 1,
                read_bytes: 1,
                write_bytes: 1,
            },
        )
        .await;
        let instance = InstanceId::new("instance").unwrap();
        assert_eq!(
            store.advance_containment_epoch(&instance, 0).await.unwrap(),
            1
        );
        assert!(matches!(
            store.advance_containment_epoch(&instance, 0).await,
            Err(StorageError::StaleEpoch)
        ));
        assert_eq!(
            store
                .get_instance(&instance)
                .await
                .unwrap()
                .containment_epoch,
            1
        );
        cleanup(store, path).await;
    }

    #[tokio::test]
    async fn audit_chain_detects_modification_deletion_and_permutation() {
        let (store, path) = database().await;
        let payload = genesis_hash().unwrap();
        for number in 1..=3 {
            store
                .append_audit(
                    "DECISION",
                    &format!("subject-{number}"),
                    &payload,
                    UtcTimestamp::from_unix_seconds(number),
                )
                .await
                .unwrap();
        }
        let events = store.load_audit_chain().await.unwrap();
        verify_audit_chain(&events).unwrap();
        let mut modified = events.clone();
        modified[1].subject = "tampered".to_owned();
        assert!(verify_audit_chain(&modified).is_err());
        let mut deleted = events.clone();
        deleted.remove(1);
        assert!(verify_audit_chain(&deleted).is_err());
        let mut permuted = events;
        permuted.swap(0, 1);
        assert!(verify_audit_chain(&permuted).is_err());
        let mut inserted = modified;
        inserted.insert(1, inserted[0].clone());
        assert!(verify_audit_chain(&inserted).is_err());
        cleanup(store, path).await;
    }

    #[tokio::test]
    async fn failed_reservation_rolls_back_ledger_update() {
        let (store, path) = database().await;
        seed(
            &store,
            BudgetAmounts {
                action_count: 5,
                read_bytes: 100,
                write_bytes: 100,
            },
        )
        .await;
        let id = BudgetReservationId::new("duplicate").unwrap();
        let budget = BudgetId::new("budget").unwrap();
        let session = SessionId::new("session").unwrap();
        let first = BudgetAmounts {
            action_count: 1,
            read_bytes: 10,
            write_bytes: 0,
        };
        store.reserve(&id, &budget, &session, first).await.unwrap();
        let before = store.budget_totals(&budget).await.unwrap();
        assert!(store
            .reserve(
                &id,
                &budget,
                &session,
                BudgetAmounts {
                    action_count: 2,
                    read_bytes: 20,
                    write_bytes: 0
                }
            )
            .await
            .is_err());
        assert_eq!(store.budget_totals(&budget).await.unwrap(), before);
        cleanup(store, path).await;
    }
}
