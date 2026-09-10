use std::sync::Arc;

use aaph_core::action::{CanonicalActionRequest, ReasonCode};
use aaph_core::agent::attenuate_authority;
use aaph_core::crypto::{digest, Digest384Value, SigningKeyMaterial, ACTION_PROPOSAL_DOMAIN};
use aaph_core::ids::{
    BudgetReservationId, EffectOperationId, InstanceId, Jti, PermitId, SessionId,
};
use aaph_core::mandate::validate_mandate;
use aaph_core::permit::{
    ContainmentEvent, Decision, DecisionRecord, ExecutionPermit, ExecutionPermitFields,
    PermitTimePolicy,
};
use aaph_core::policy::{evaluate_proposal, AuthenticationContext};
use aaph_core::signed::{
    artifact_digest, DomainSeparated, SignedActionProposal, SignedArtifact, SignedContainmentEvent,
    SignedExecutionPermit,
};
use aaph_core::UtcTimestamp;
use serde::{Deserialize, Serialize};
use sqlx::Row;

use crate::clock::Clock;
use crate::configuration::{canonical, DemoConfig};
use crate::dispatcher::EffectDispatcher;
use crate::id_generator::IdGenerator;
use crate::storage::{
    AuditRepository, BudgetRepository, DecisionRepository, SqliteStore, StateRepository,
};

const SESSION_DOMAIN: &[u8] = b"AAPH-POC-SESSION-REQUEST-V1\0";

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SessionRequest {
    pub instance_id: InstanceId,
    pub session_id: SessionId,
    pub issued_at: UtcTimestamp,
}

impl DomainSeparated for SessionRequest {
    const DOMAIN: &'static [u8] = SESSION_DOMAIN;
}
pub type SignedSessionRequest = SignedArtifact<SessionRequest>;

#[derive(Debug)]
pub struct PermitSigningError;

#[derive(Debug, Serialize)]
#[serde(deny_unknown_fields)]
pub struct SessionResponse {
    pub session_id: SessionId,
    pub expires_at: UtcTimestamp,
    pub session_epoch: u64,
    pub containment_epoch: u64,
}

#[derive(Debug, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ActionResponse {
    pub decision: DecisionRecord,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub permit: Option<SignedExecutionPermit>,
    pub containment_propagation_incomplete: bool,
}

pub trait PermitSigner: Send + Sync {
    /// Signs an execution permit.
    ///
    /// # Errors
    /// Returns an error if canonicalization or signing fails.
    fn sign(&self, permit: ExecutionPermit) -> Result<SignedExecutionPermit, PermitSigningError>;
    /// Signs a containment event.
    ///
    /// # Errors
    /// Returns an error if canonicalization or signing fails.
    fn sign_containment(
        &self,
        event: ContainmentEvent,
    ) -> Result<SignedContainmentEvent, PermitSigningError>;
}

pub struct Ed25519PermitSigner(pub SigningKeyMaterial);
impl PermitSigner for Ed25519PermitSigner {
    fn sign(&self, permit: ExecutionPermit) -> Result<SignedExecutionPermit, PermitSigningError> {
        SignedExecutionPermit::sign(permit, &self.0).map_err(|_| PermitSigningError)
    }
    fn sign_containment(
        &self,
        event: ContainmentEvent,
    ) -> Result<SignedContainmentEvent, PermitSigningError> {
        SignedContainmentEvent::sign(event, &self.0).map_err(|_| PermitSigningError)
    }
}

#[derive(Clone)]
pub struct AuthorityOrchestrator {
    pub store: SqliteStore,
    pub config: Arc<DemoConfig>,
    pub clock: Arc<dyn Clock>,
    pub signer: Arc<dyn PermitSigner>,
    pub dispatcher: Arc<dyn EffectDispatcher>,
    pub id_generator: Arc<dyn IdGenerator>,
    pub admin_secret: Arc<String>,
    pub issuance_lock: Arc<tokio::sync::Mutex<()>>,
}

#[derive(Debug, Serialize)]
#[serde(untagged)]
pub enum ApiReason {
    Registered(ReasonCode),
    Local(LocalDiagnostic),
}

#[derive(Debug, Serialize)]
pub enum LocalDiagnostic {
    #[serde(rename = "LOCAL_INTERNAL_FAIL_CLOSED")]
    InternalFailClosed,
}

#[derive(Debug)]
pub struct ApiFailure {
    pub status: axum::http::StatusCode,
    pub reason: ApiReason,
}

impl AuthorityOrchestrator {
    /// Performs validated recovery without restoring prior authority.
    ///
    /// # Errors
    /// Returns a fail-closed API error for invalid authorization or state.
    pub async fn recover(
        &self,
        instance: &InstanceId,
        secret: &str,
        validated: bool,
    ) -> Result<(), ApiFailure> {
        if !constant_time_equal(secret.as_bytes(), self.admin_secret.as_bytes()) {
            return Err(unauthorized(ReasonCode::BadSignature));
        }
        if !validated {
            return Err(deny(ReasonCode::SchemaInvalid));
        }
        let _proof = aaph_core::state::RecoveryValidation::validated();
        let epoch = self
            .store
            .recover_instance(instance)
            .await
            .map_err(|_| deny(ReasonCode::AgentContained))?;
        let event = ContainmentEvent {
            instance_id: instance.clone(),
            containment_epoch: epoch,
            reason: ReasonCode::AgentContained,
            occurred_at: self.clock.now(),
        };
        let signed = self.signer.sign_containment(event).map_err(internal)?;
        if self
            .dispatcher
            .propagate_containment(&signed)
            .await
            .is_err()
        {
            return Err(ApiFailure {
                status: axum::http::StatusCode::SERVICE_UNAVAILABLE,
                reason: ApiReason::Local(LocalDiagnostic::InternalFailClosed),
            });
        }
        self.store
            .activate_recovered(instance)
            .await
            .map_err(internal)?;
        let recovery_digest = artifact_digest(signed.artifact()).map_err(|_| internal(()))?;
        self.store
            .append_audit(
                "INSTANCE_RECOVERED",
                instance.as_str(),
                &recovery_digest,
                self.clock.now(),
            )
            .await
            .map_err(internal)?;
        Ok(())
    }
    /// Creates and activates a new authenticated session.
    ///
    /// # Errors
    /// Returns a fail-closed API error when any session invariant fails.
    pub async fn create_session(
        &self,
        envelope: SignedSessionRequest,
    ) -> Result<SessionResponse, ApiFailure> {
        let now = self.clock.now();
        let request = envelope.artifact();
        let row = sqlx::query(
            "SELECT public_key,state,containment_epoch FROM agent_instances WHERE instance_id=?",
        )
        .bind(request.instance_id.as_str())
        .fetch_optional(self.store.pool())
        .await
        .map_err(internal)?
        .ok_or_else(|| deny(ReasonCode::SessionInactive))?;
        let state: String = row.try_get("state").map_err(|_| internal(()))?;
        if state != "ACTIVE" {
            return Err(deny(ReasonCode::AgentContained));
        }
        let stored_key: String = row.try_get("public_key").map_err(|_| internal(()))?;
        if envelope.verify().is_err() || envelope.signer_public_key().as_str() != stored_key {
            return Err(unauthorized(ReasonCode::BadSignature));
        }
        let age = now
            .unix_seconds()
            .checked_sub(request.issued_at.unix_seconds())
            .ok_or_else(|| deny(ReasonCode::SchemaInvalid))?;
        if !(0..=30).contains(&age) {
            return Err(deny(ReasonCode::SessionExpired));
        }
        let lifetime = i64::try_from(self.config.policy_file.session_lifetime_seconds)
            .map_err(|_| internal(()))?;
        let expires = now
            .unix_seconds()
            .checked_add(lifetime)
            .ok_or_else(|| internal(()))?;
        sqlx::query("INSERT INTO agent_sessions(session_id,instance_id,state,session_epoch,created_at,expires_at) VALUES(?,?,'ACTIVE',0,?,?)")
            .bind(request.session_id.as_str()).bind(request.instance_id.as_str()).bind(now.unix_seconds()).bind(expires)
            .execute(self.store.pool()).await.map_err(|_| deny(ReasonCode::Replay))?;
        Ok(SessionResponse {
            session_id: request.session_id.clone(),
            expires_at: UtcTimestamp::from_unix_seconds(expires),
            session_epoch: 0,
            containment_epoch: u64::try_from(
                row.try_get::<i64, _>("containment_epoch")
                    .map_err(|_| internal(()))?,
            )
            .map_err(|_| internal(()))?,
        })
    }

    // Keeping the security gates linear makes their normative order directly reviewable.
    #[allow(clippy::too_many_lines)]
    /// Evaluates a signed action proposal and may issue a bounded permit.
    ///
    /// # Errors
    /// Returns a fail-closed API error when validation or persistence fails.
    pub async fn propose(
        &self,
        envelope: SignedActionProposal,
    ) -> Result<ActionResponse, ApiFailure> {
        let _issuance_guard = self.issuance_lock.lock().await;
        let now = self.clock.now();
        let proposal = envelope.artifact().clone();
        let context = sqlx::query("SELECT s.state session_state,s.session_epoch,s.expires_at,i.instance_id,i.agent_id,i.release_id,i.public_key,i.key_fingerprint,i.state instance_state,i.containment_epoch,m.canonical_json mandate_json,b.budget_id,r.canonical_json release_json,bm.canonical_json manifest_json FROM agent_sessions s JOIN agent_instances i ON i.instance_id=s.instance_id JOIN mandates m ON m.agent_id=i.agent_id JOIN budget_ledgers b ON b.mandate_id=m.mandate_id JOIN agent_releases r ON r.release_id=i.release_id JOIN behavioral_manifests bm ON bm.release_id=r.release_id WHERE s.session_id=?")
            .bind(proposal.session_id.as_str()).fetch_optional(self.store.pool()).await.map_err(internal)?
            .ok_or_else(|| deny(ReasonCode::SessionInactive))?;
        let instance_state: String = context
            .try_get("instance_state")
            .map_err(|_| internal(()))?;
        if instance_state != "ACTIVE" {
            return Err(deny(ReasonCode::AgentContained));
        }
        let session_state: String = context.try_get("session_state").map_err(|_| internal(()))?;
        if session_state != "ACTIVE" {
            return Err(deny(ReasonCode::SessionInactive));
        }
        if now.unix_seconds()
            >= context
                .try_get::<i64, _>("expires_at")
                .map_err(|_| internal(()))?
        {
            return Err(deny(ReasonCode::SessionExpired));
        }
        let stored_key: String = context.try_get("public_key").map_err(|_| internal(()))?;
        if envelope.verify().is_err() || envelope.signer_public_key().as_str() != stored_key {
            return Err(unauthorized(ReasonCode::BadSignature));
        }
        let canonical_request = CanonicalActionRequest::try_from(proposal.clone())
            .map_err(|_| deny(ReasonCode::SchemaInvalid))?;
        let request_digest =
            digest(ACTION_PROPOSAL_DOMAIN, &canonical_request).map_err(|_| internal(()))?;
        if let Some(existing) = sqlx::query(
            "SELECT r.request_digest,d.canonical_json decision_json,p.canonical_json permit_json FROM action_requests r JOIN decision_records d ON d.request_id=r.request_id LEFT JOIN execution_permits p ON p.request_id=r.request_id WHERE r.request_id=?",
        )
        .bind(proposal.request_id.as_str())
        .fetch_optional(self.store.pool())
        .await
        .map_err(internal)?
        {
            let stored_digest: String = existing.try_get("request_digest").map_err(|_| internal(()))?;
            if stored_digest != request_digest.as_str() {
                return Err(conflict(ReasonCode::SchemaInvalid));
            }
            let decision: DecisionRecord = serde_json::from_str(
                &existing.try_get::<String, _>("decision_json").map_err(|_| internal(()))?,
            )
            .map_err(internal)?;
            let permit = existing
                .try_get::<Option<String>, _>("permit_json")
                .map_err(|_| internal(()))?
                .map(|json| serde_json::from_str(&json).map_err(internal))
                .transpose()?;
            return Ok(ActionResponse {
                decision,
                permit,
                containment_propagation_incomplete: false,
            });
        }
        let mandate: aaph_core::mandate::Mandate = serde_json::from_str(
            context
                .try_get::<String, _>("mandate_json")
                .map_err(|_| internal(()))?
                .as_str(),
        )
        .map_err(|_| internal(()))?;
        let validated =
            validate_mandate(&mandate, now).map_err(|_| deny(ReasonCode::MandateInvalid))?;
        let definition = &self.config.definition;
        if definition.current_release_id.as_str()
            != context
                .try_get::<String, _>("release_id")
                .map_err(|_| internal(()))?
        {
            return Err(deny(ReasonCode::EpochStale));
        }
        let manifest: aaph_core::agent::BehavioralManifest = serde_json::from_str(
            context
                .try_get::<String, _>("manifest_json")
                .map_err(|_| internal(()))?
                .as_str(),
        )
        .map_err(|_| internal(()))?;
        let effective = attenuate_authority(&validated, definition, &manifest)
            .map_err(|_| deny(ReasonCode::MandateInvalid))?;
        let outcome = evaluate_proposal(
            proposal,
            &effective,
            &self.config.policy,
            AuthenticationContext::AuthenticatedAndBound,
            now,
        );
        if outcome.record.decision != Decision::Permit {
            self.persist_decision(&canonical_request, &request_digest, &outcome.record)
                .await?;
            let propagation_incomplete = if outcome.record.decision == Decision::Quarantine {
                self.confine_and_propagate(&context, outcome.record.reason, now)
                    .await?
            } else {
                false
            };
            return Ok(ActionResponse {
                decision: outcome.record,
                permit: None,
                containment_propagation_incomplete: propagation_incomplete,
            });
        }
        let amounts = outcome.budget.ok_or_else(|| internal(()))?;
        let reservation_id =
            BudgetReservationId::new(self.id_generator.uuid_v7().map_err(internal)?)
                .map_err(|_| internal(()))?;
        let budget_id = validated.budget_id().clone();
        if let Err(error) = self
            .store
            .reserve(
                &reservation_id,
                &budget_id,
                &raw_session(&canonical_request),
                amounts,
            )
            .await
        {
            if matches!(error, crate::storage::StorageError::BudgetExceeded) {
                let record = DecisionRecord {
                    request_id: canonical_request.request_id().clone(),
                    decision: Decision::Deny,
                    reason: ReasonCode::BudgetExceeded,
                    decided_at: now,
                };
                self.persist_decision(&canonical_request, &request_digest, &record)
                    .await?;
                return Ok(ActionResponse {
                    decision: record,
                    permit: None,
                    containment_propagation_incomplete: false,
                });
            }
            return Err(internal(()));
        }
        let permit_result = self.make_permit(
            &context,
            &canonical_request,
            request_digest.clone(),
            reservation_id.clone(),
            now,
        );
        let Ok(signed) = permit_result.and_then(|permit| self.signer.sign(permit).map_err(|_| ()))
        else {
            let _ = self.store.release(&reservation_id).await;
            return Err(internal(()));
        };
        if self
            .persist_permit(
                &canonical_request,
                &request_digest,
                &outcome.record,
                &reservation_id,
                &signed,
            )
            .await
            .is_err()
        {
            let _ = self.store.release(&reservation_id).await;
            return Err(internal(()));
        }
        let _ = self.dispatcher.accept(&signed).await;
        Ok(ActionResponse {
            decision: outcome.record,
            permit: Some(signed),
            containment_propagation_incomplete: false,
        })
    }

    async fn confine_and_propagate(
        &self,
        context: &sqlx::sqlite::SqliteRow,
        reason: ReasonCode,
        now: UtcTimestamp,
    ) -> Result<bool, ApiFailure> {
        let instance = InstanceId::new(
            context
                .try_get::<String, _>("instance_id")
                .map_err(|_| internal(()))?,
        )
        .map_err(|_| internal(()))?;
        let result = self
            .store
            .contain_instance(&instance)
            .await
            .map_err(internal)?;
        let event = ContainmentEvent {
            instance_id: instance.clone(),
            containment_epoch: result.epoch,
            reason,
            occurred_at: now,
        };
        let signed = self
            .signer
            .sign_containment(event.clone())
            .map_err(internal)?;
        let canonical = canonical(&signed).map_err(|_| internal(()))?;
        if result.changed {
            sqlx::query("INSERT INTO containment_events(instance_id,expected_epoch,new_epoch,reason_code,occurred_at,canonical_json) VALUES(?,?,?,?,?,?)")
                .bind(instance.as_str()).bind(i64::try_from(result.epoch.saturating_sub(1)).map_err(|_|internal(()))?).bind(i64::try_from(result.epoch).map_err(|_|internal(()))?).bind(serde_json::to_value(reason).map_err(|_|internal(()))?.as_str().ok_or_else(||internal(()))?).bind(now.unix_seconds()).bind(canonical).execute(self.store.pool()).await.map_err(internal)?;
            let event_digest = artifact_digest(&event).map_err(|_| internal(()))?;
            self.store
                .append_audit("INSTANCE_CONTAINED", instance.as_str(), &event_digest, now)
                .await
                .map_err(internal)?;
        }
        Ok(self
            .dispatcher
            .propagate_containment(&signed)
            .await
            .is_err())
    }

    fn make_permit(
        &self,
        row: &sqlx::sqlite::SqliteRow,
        request: &CanonicalActionRequest,
        digest: Digest384Value,
        reservation: BudgetReservationId,
        now: UtcTimestamp,
    ) -> Result<ExecutionPermit, ()> {
        let expires = now
            .unix_seconds()
            .checked_add(
                i64::try_from(self.config.policy_file.permit_lifetime_seconds).map_err(|_| ())?,
            )
            .ok_or(())?;
        let instance_id = InstanceId::new(row.try_get::<String, _>("instance_id").map_err(|_| ())?)
            .map_err(|_| ())?;
        let agent_id =
            aaph_core::ids::AgentId::new(row.try_get::<String, _>("agent_id").map_err(|_| ())?)
                .map_err(|_| ())?;
        let fingerprint = Digest384Value::parse(
            row.try_get::<String, _>("key_fingerprint")
                .map_err(|_| ())?,
        )
        .map_err(|_| ())?;
        ExecutionPermit::new(
            ExecutionPermitFields {
                permit_id: PermitId::new(self.id_generator.uuid_v7().map_err(|_| ())?)
                    .map_err(|_| ())?,
                jti: Jti::new(self.id_generator.uuid_v7().map_err(|_| ())?).map_err(|_| ())?,
                request_digest: digest,
                agent_id,
                instance_id,
                session_id: raw_session(request),
                holder_key_fingerprint: fingerprint,
                audience_pep_id: self.config.policy_file.audience_pep_id.clone(),
                issued_at: now,
                expires_at: UtcTimestamp::from_unix_seconds(expires),
                nonce: self.id_generator.nonce().map_err(|_| ())?,
                effect_operation_id: EffectOperationId::new(
                    self.id_generator.uuid_v7().map_err(|_| ())?,
                )
                .map_err(|_| ())?,
                session_epoch: u64::try_from(
                    row.try_get::<i64, _>("session_epoch").map_err(|_| ())?,
                )
                .map_err(|_| ())?,
                containment_epoch: u64::try_from(
                    row.try_get::<i64, _>("containment_epoch").map_err(|_| ())?,
                )
                .map_err(|_| ())?,
                budget_reservation_id: reservation,
                policy_version: self.config.policy_file.policy_version.clone(),
                policy_digest: self.config.policy_digest.clone(),
            },
            PermitTimePolicy {
                max_lifetime_seconds: self.config.policy_file.permit_lifetime_seconds,
                max_future_skew_seconds: 0,
            },
            now,
        )
        .map_err(|_| ())
    }

    async fn persist_decision(
        &self,
        request: &CanonicalActionRequest,
        digest: &Digest384Value,
        decision: &DecisionRecord,
    ) -> Result<(), ApiFailure> {
        self.store
            .record_request_and_decision(request, digest.as_str(), decision)
            .await
            .map_err(internal)?;
        let audit_digest = artifact_digest_for(decision)?;
        self.store
            .append_audit(
                "DECISION",
                request.request_id().as_str(),
                &audit_digest,
                decision.decided_at,
            )
            .await
            .map_err(internal)?;
        Ok(())
    }

    async fn persist_permit(
        &self,
        request: &CanonicalActionRequest,
        digest: &Digest384Value,
        decision: &DecisionRecord,
        reservation: &BudgetReservationId,
        permit: &SignedExecutionPermit,
    ) -> Result<(), ApiFailure> {
        self.persist_decision(request, digest, decision).await?;
        let json = canonical(permit).map_err(|_| internal(()))?;
        let artifact: serde_json::Value =
            serde_json::to_value(permit.artifact()).map_err(|_| internal(()))?;
        let get = |name: &str| {
            artifact
                .get(name)
                .and_then(serde_json::Value::as_str)
                .ok_or_else(|| internal(()))
        };
        sqlx::query("INSERT INTO execution_permits(permit_id,jti,effect_operation_id,request_id,reservation_id,audience_pep_id,request_digest,nonce,session_epoch,containment_epoch,issued_at,expires_at,canonical_json) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?)")
            .bind(get("permit_id")?).bind(get("jti")?).bind(get("effect_operation_id")?).bind(request.request_id().as_str()).bind(reservation.as_str()).bind(get("audience_pep_id")?).bind(digest.as_str()).bind(get("nonce")?)
            .bind(artifact.get("session_epoch").and_then(serde_json::Value::as_u64).and_then(|v| i64::try_from(v).ok()).ok_or_else(|| internal(()))?)
            .bind(artifact.get("containment_epoch").and_then(serde_json::Value::as_u64).and_then(|v| i64::try_from(v).ok()).ok_or_else(|| internal(()))?)
            .bind(artifact.get("issued_at").and_then(serde_json::Value::as_i64).ok_or_else(|| internal(()))?)
            .bind(artifact.get("expires_at").and_then(serde_json::Value::as_i64).ok_or_else(|| internal(()))?).bind(json)
            .execute(self.store.pool()).await.map_err(internal)?;
        let permit_digest = artifact_digest(permit.artifact()).map_err(|_| internal(()))?;
        self.store
            .append_audit(
                "PERMIT_ISSUED",
                request.request_id().as_str(),
                &permit_digest,
                decision.decided_at,
            )
            .await
            .map_err(internal)?;
        Ok(())
    }
}

fn constant_time_equal(left: &[u8], right: &[u8]) -> bool {
    let mut difference = left.len() ^ right.len();
    let length = left.len().max(right.len());
    for index in 0..length {
        difference |= usize::from(*left.get(index).unwrap_or(&0) ^ *right.get(index).unwrap_or(&0));
    }
    difference == 0
}

fn raw_session(request: &CanonicalActionRequest) -> SessionId {
    request.session_id().clone()
}
fn artifact_digest_for<T: Serialize>(value: &T) -> Result<Digest384Value, ApiFailure> {
    aaph_core::crypto::digest(b"AAPH-POC-API-AUDIT-V1\0", value).map_err(|_| internal(()))
}
fn deny(reason: ReasonCode) -> ApiFailure {
    ApiFailure {
        status: axum::http::StatusCode::FORBIDDEN,
        reason: ApiReason::Registered(reason),
    }
}
fn unauthorized(reason: ReasonCode) -> ApiFailure {
    ApiFailure {
        status: axum::http::StatusCode::UNAUTHORIZED,
        reason: ApiReason::Registered(reason),
    }
}
fn conflict(reason: ReasonCode) -> ApiFailure {
    ApiFailure {
        status: axum::http::StatusCode::CONFLICT,
        reason: ApiReason::Registered(reason),
    }
}
fn internal<T>(_error: T) -> ApiFailure {
    ApiFailure {
        status: axum::http::StatusCode::INTERNAL_SERVER_ERROR,
        reason: ApiReason::Local(LocalDiagnostic::InternalFailClosed),
    }
}
