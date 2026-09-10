//! Narrow repository contracts and their `SQLite` implementation.

mod sqlite;

use aaph_core::action::CanonicalActionRequest;
use aaph_core::agent::AgentDefinition;
use aaph_core::audit::AuditChainError;
use aaph_core::budget::BudgetAmounts;
use aaph_core::ids::{
    AgentId, BudgetId, BudgetReservationId, InstanceId, MandateId, ReleaseId, SessionId,
};
use aaph_core::mandate::Mandate;
use aaph_core::permit::{AuditEvent, DecisionRecord};
use aaph_core::state::InstanceState;
use aaph_core::UtcTimestamp;
use async_trait::async_trait;

pub use sqlite::SqliteStore;

#[derive(Debug)]
pub enum StorageError {
    Database(sqlx::Error),
    Migration(sqlx::migrate::MigrateError),
    Serialization(serde_json::Error),
    Audit(AuditChainError),
    Canonical(aaph_core::canonical::CanonicalError),
    InvalidStoredData,
    NumericOverflow,
    BudgetExceeded,
    UnknownReservation,
    AlreadyCommitted,
    CommitAfterRelease,
    ReleaseAfterCommit,
    StaleEpoch,
}

impl std::fmt::Display for StorageError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("transactional controller storage operation failed")
    }
}
impl std::error::Error for StorageError {}
impl From<sqlx::Error> for StorageError {
    fn from(value: sqlx::Error) -> Self {
        Self::Database(value)
    }
}
impl From<serde_json::Error> for StorageError {
    fn from(value: serde_json::Error) -> Self {
        Self::Serialization(value)
    }
}
impl From<AuditChainError> for StorageError {
    fn from(value: AuditChainError) -> Self {
        Self::Audit(value)
    }
}
impl From<aaph_core::canonical::CanonicalError> for StorageError {
    fn from(value: aaph_core::canonical::CanonicalError) -> Self {
        Self::Canonical(value)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize)]
pub struct InstanceSnapshot {
    pub instance_id: InstanceId,
    pub state: InstanceState,
    pub containment_epoch: u64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ContainmentResult {
    pub epoch: u64,
    pub changed: bool,
}

#[async_trait]
pub trait DefinitionRepository {
    async fn put_agent_definition(&self, value: &AgentDefinition) -> Result<(), StorageError>;
    async fn get_agent_definition(&self, id: &AgentId) -> Result<AgentDefinition, StorageError>;
    async fn put_release_and_manifest(
        &self,
        release_id: &ReleaseId,
        agent_id: &AgentId,
        release_json: &str,
        manifest_json: &str,
        manifest_digest: &str,
    ) -> Result<(), StorageError>;
    async fn put_mandate(&self, value: &Mandate) -> Result<(), StorageError>;
    async fn get_mandate(&self, id: &MandateId) -> Result<Mandate, StorageError>;
}

#[async_trait]
pub trait StateRepository {
    async fn create_instance(
        &self,
        instance_id: &InstanceId,
        agent_id: &AgentId,
        release_id: &ReleaseId,
        public_key: &str,
        fingerprint: &str,
    ) -> Result<(), StorageError>;
    async fn get_instance(&self, id: &InstanceId) -> Result<InstanceSnapshot, StorageError>;
    async fn advance_containment_epoch(
        &self,
        id: &InstanceId,
        expected_epoch: u64,
    ) -> Result<u64, StorageError>;
    async fn create_session(
        &self,
        session_id: &SessionId,
        instance_id: &InstanceId,
        created_at: UtcTimestamp,
        expires_at: UtcTimestamp,
    ) -> Result<(), StorageError>;
    async fn contain_instance(&self, id: &InstanceId) -> Result<ContainmentResult, StorageError>;
    async fn recover_instance(&self, id: &InstanceId) -> Result<u64, StorageError>;
    async fn activate_recovered(&self, id: &InstanceId) -> Result<(), StorageError>;
}

#[async_trait]
pub trait BudgetRepository {
    async fn create_budget(
        &self,
        budget_id: &BudgetId,
        mandate_id: &MandateId,
        capacity: BudgetAmounts,
    ) -> Result<(), StorageError>;
    async fn reserve(
        &self,
        reservation_id: &BudgetReservationId,
        budget_id: &BudgetId,
        session_id: &SessionId,
        amounts: BudgetAmounts,
    ) -> Result<(), StorageError>;
    async fn commit(&self, reservation_id: &BudgetReservationId) -> Result<(), StorageError>;
    async fn release(&self, reservation_id: &BudgetReservationId) -> Result<(), StorageError>;
    async fn close_session(&self, session_id: &SessionId) -> Result<(), StorageError>;
    async fn budget_totals(
        &self,
        budget_id: &BudgetId,
    ) -> Result<(BudgetAmounts, BudgetAmounts), StorageError>;
}

#[async_trait]
pub trait AuditRepository {
    async fn append_audit(
        &self,
        event_type: &str,
        subject: &str,
        payload_digest: &aaph_core::crypto::Digest384Value,
        timestamp: UtcTimestamp,
    ) -> Result<AuditEvent, StorageError>;
    async fn load_audit_chain(&self) -> Result<Vec<AuditEvent>, StorageError>;
}

#[async_trait]
pub trait DecisionRepository {
    async fn record_request_and_decision(
        &self,
        request: &CanonicalActionRequest,
        request_digest: &str,
        decision: &DecisionRecord,
    ) -> Result<(), StorageError>;
    async fn get_decision(
        &self,
        request_id: &aaph_core::ids::RequestId,
    ) -> Result<DecisionRecord, StorageError>;
}
