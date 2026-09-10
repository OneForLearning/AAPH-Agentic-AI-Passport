//! Decisions, permits, containment records, and audit records.

use crate::action::ReasonCode;
use crate::crypto::Digest384Value;
use crate::ids::{
    AgentId, BudgetReservationId, EffectOperationId, InstanceId, Jti, PepId, PermitId,
    PolicyVersion, RequestId, SessionId,
};
use crate::UtcTimestamp;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum Decision {
    Permit,
    Deny,
    Quarantine,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DecisionRecord {
    pub request_id: RequestId,
    pub decision: Decision,
    pub reason: ReasonCode,
    pub decided_at: UtcTimestamp,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ExecutionPermit {
    permit_id: PermitId,
    jti: Jti,
    request_digest: Digest384Value,
    agent_id: AgentId,
    instance_id: InstanceId,
    session_id: SessionId,
    holder_key_fingerprint: Digest384Value,
    audience_pep_id: PepId,
    issued_at: UtcTimestamp,
    expires_at: UtcTimestamp,
    nonce: String,
    effect_operation_id: EffectOperationId,
    session_epoch: u64,
    containment_epoch: u64,
    budget_reservation_id: BudgetReservationId,
    policy_version: PolicyVersion,
    policy_digest: Digest384Value,
}

/// Unvalidated fields used only as input to controlled permit construction.
#[derive(Debug)]
pub struct ExecutionPermitFields {
    pub permit_id: PermitId,
    pub jti: Jti,
    pub request_digest: Digest384Value,
    pub agent_id: AgentId,
    pub instance_id: InstanceId,
    pub session_id: SessionId,
    pub holder_key_fingerprint: Digest384Value,
    pub audience_pep_id: PepId,
    pub issued_at: UtcTimestamp,
    pub expires_at: UtcTimestamp,
    pub nonce: String,
    pub effect_operation_id: EffectOperationId,
    pub session_epoch: u64,
    pub containment_epoch: u64,
    pub budget_reservation_id: BudgetReservationId,
    pub policy_version: PolicyVersion,
    pub policy_digest: Digest384Value,
}

/// Configurable time bounds checked both when constructing and verifying permits.
#[derive(Debug, Clone, Copy)]
pub struct PermitTimePolicy {
    pub max_lifetime_seconds: u64,
    pub max_future_skew_seconds: u64,
}

impl Default for PermitTimePolicy {
    fn default() -> Self {
        Self {
            max_lifetime_seconds: 60,
            max_future_skew_seconds: 5,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PermitTimeError {
    Expired,
    IssuedInFuture,
    InvalidInterval,
    LifetimeExceeded,
    TimeOverflow,
    EmptyNonce,
}

impl ExecutionPermit {
    /// Returns the local credential identifier (`credential_id := permit_id`).
    #[must_use]
    pub const fn permit_id(&self) -> &PermitId {
        &self.permit_id
    }
    #[must_use]
    pub const fn jti(&self) -> &Jti {
        &self.jti
    }
    #[must_use]
    pub const fn request_digest(&self) -> &Digest384Value {
        &self.request_digest
    }
    #[must_use]
    pub const fn instance_id(&self) -> &InstanceId {
        &self.instance_id
    }
    #[must_use]
    pub const fn session_id(&self) -> &SessionId {
        &self.session_id
    }
    #[must_use]
    pub const fn holder_key_fingerprint(&self) -> &Digest384Value {
        &self.holder_key_fingerprint
    }
    #[must_use]
    pub const fn audience_pep_id(&self) -> &PepId {
        &self.audience_pep_id
    }
    #[must_use]
    pub fn nonce(&self) -> &str {
        &self.nonce
    }
    #[must_use]
    pub const fn effect_operation_id(&self) -> &EffectOperationId {
        &self.effect_operation_id
    }
    #[must_use]
    pub const fn session_epoch(&self) -> u64 {
        self.session_epoch
    }
    #[must_use]
    pub const fn containment_epoch(&self) -> u64 {
        self.containment_epoch
    }
    #[must_use]
    pub const fn expires_at(&self) -> UtcTimestamp {
        self.expires_at
    }

    /// Constructs a permit only after checking its time bounds and nonce.
    ///
    /// # Errors
    /// Returns an error for invalid time bounds or an empty nonce.
    pub fn new(
        fields: ExecutionPermitFields,
        policy: PermitTimePolicy,
        now: UtcTimestamp,
    ) -> Result<Self, PermitTimeError> {
        if fields.nonce.is_empty() {
            return Err(PermitTimeError::EmptyNonce);
        }
        validate_times(fields.issued_at, fields.expires_at, policy, now)?;
        Ok(Self {
            permit_id: fields.permit_id,
            jti: fields.jti,
            request_digest: fields.request_digest,
            agent_id: fields.agent_id,
            instance_id: fields.instance_id,
            session_id: fields.session_id,
            holder_key_fingerprint: fields.holder_key_fingerprint,
            audience_pep_id: fields.audience_pep_id,
            issued_at: fields.issued_at,
            expires_at: fields.expires_at,
            nonce: fields.nonce,
            effect_operation_id: fields.effect_operation_id,
            session_epoch: fields.session_epoch,
            containment_epoch: fields.containment_epoch,
            budget_reservation_id: fields.budget_reservation_id,
            policy_version: fields.policy_version,
            policy_digest: fields.policy_digest,
        })
    }

    /// Rechecks permit time validity at a verification boundary.
    ///
    /// # Errors
    /// Returns an error when the permit is expired, future-dated, or too long-lived.
    pub fn validate_time(
        &self,
        policy: PermitTimePolicy,
        now: UtcTimestamp,
    ) -> Result<(), PermitTimeError> {
        if self.nonce.is_empty() {
            return Err(PermitTimeError::EmptyNonce);
        }
        validate_times(self.issued_at, self.expires_at, policy, now)
    }
}

fn validate_times(
    issued_at: UtcTimestamp,
    expires_at: UtcTimestamp,
    policy: PermitTimePolicy,
    now: UtcTimestamp,
) -> Result<(), PermitTimeError> {
    if expires_at <= now {
        return Err(PermitTimeError::Expired);
    }
    let skew =
        i64::try_from(policy.max_future_skew_seconds).map_err(|_| PermitTimeError::TimeOverflow)?;
    let latest_issue = now
        .unix_seconds()
        .checked_add(skew)
        .ok_or(PermitTimeError::TimeOverflow)?;
    if issued_at.unix_seconds() > latest_issue {
        return Err(PermitTimeError::IssuedInFuture);
    }
    let lifetime = expires_at
        .unix_seconds()
        .checked_sub(issued_at.unix_seconds())
        .ok_or(PermitTimeError::TimeOverflow)?;
    if lifetime <= 0 {
        return Err(PermitTimeError::InvalidInterval);
    }
    let lifetime = u64::try_from(lifetime).map_err(|_| PermitTimeError::InvalidInterval)?;
    if lifetime > policy.max_lifetime_seconds {
        return Err(PermitTimeError::LifetimeExceeded);
    }
    Ok(())
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ContainmentEvent {
    pub instance_id: InstanceId,
    pub containment_epoch: u64,
    pub reason: ReasonCode,
    pub occurred_at: UtcTimestamp,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AuditEvent {
    pub sequence: u64,
    pub event_type: String,
    pub subject: String,
    pub payload_digest: Digest384Value,
    pub previous_hash: Digest384Value,
    pub timestamp: UtcTimestamp,
    pub current_hash: Digest384Value,
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn decision_json_is_stable() {
        for (value, json) in [
            (Decision::Permit, "\"PERMIT\""),
            (Decision::Deny, "\"DENY\""),
            (Decision::Quarantine, "\"QUARANTINE\""),
        ] {
            assert_eq!(serde_json::to_string(&value).unwrap(), json);
            assert_eq!(serde_json::from_str::<Decision>(json).unwrap(), value);
        }
    }
}
