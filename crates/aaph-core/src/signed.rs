//! Strict signed envelopes for the sprint 2 AAPH artifacts.

use serde::{Deserialize, Serialize};

use crate::action::RawActionProposal;
use crate::crypto::{
    digest, sign, verify, CryptoError, Digest384Value, PublicKeyValue, SignatureValue,
    SigningKeyMaterial, ACTION_PROPOSAL_DOMAIN, AUDIT_EVENT_DOMAIN, CONTAINMENT_EVENT_DOMAIN,
    EXECUTION_PERMIT_DOMAIN,
};
use crate::permit::{
    AuditEvent, ContainmentEvent, ExecutionPermit, PermitTimeError, PermitTimePolicy,
};
use crate::UtcTimestamp;

/// Marker serialized into every sprint 2 envelope.
pub const DEMO_MARKER: &str = "NON_PRODUCTION_DEMO";

/// Types with a fixed cryptographic domain separator.
pub trait DomainSeparated {
    /// NUL-terminated domain identifier.
    const DOMAIN: &'static [u8];
}

impl DomainSeparated for RawActionProposal {
    const DOMAIN: &'static [u8] = ACTION_PROPOSAL_DOMAIN;
}
impl DomainSeparated for ExecutionPermit {
    const DOMAIN: &'static [u8] = EXECUTION_PERMIT_DOMAIN;
}
impl DomainSeparated for ContainmentEvent {
    const DOMAIN: &'static [u8] = CONTAINMENT_EVENT_DOMAIN;
}
impl DomainSeparated for AuditEvent {
    const DOMAIN: &'static [u8] = AUDIT_EVENT_DOMAIN;
}

/// Closed envelope. Unknown fields and invalid encoded values are rejected by Serde.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SignedArtifact<T> {
    marker: String,
    artifact: T,
    signer_public_key: PublicKeyValue,
    signature: SignatureValue,
}

pub type SignedActionProposal = SignedArtifact<RawActionProposal>;
pub type SignedExecutionPermit = SignedArtifact<ExecutionPermit>;
pub type SignedContainmentEvent = SignedArtifact<ContainmentEvent>;

impl<T> SignedArtifact<T>
where
    T: DomainSeparated + Serialize,
{
    /// Signs the canonical, length-delimited transcript for an artifact.
    ///
    /// # Errors
    /// Returns an error when canonicalization fails.
    pub fn sign(artifact: T, key: &SigningKeyMaterial) -> Result<Self, CryptoError> {
        let signature = sign(T::DOMAIN, &artifact, key)?;
        Ok(Self {
            marker: DEMO_MARKER.to_owned(),
            artifact,
            signer_public_key: key.public_key(),
            signature,
        })
    }

    /// Verifies the marker and canonical Ed25519 signature.
    ///
    /// # Errors
    /// Returns an error for an invalid marker, encoding, canonicalization, or signature.
    pub fn verify(&self) -> Result<(), SignedArtifactError> {
        if self.marker != DEMO_MARKER {
            return Err(SignedArtifactError::InvalidMarker);
        }
        verify(
            T::DOMAIN,
            &self.artifact,
            &self.signer_public_key,
            &self.signature,
        )
        .map_err(SignedArtifactError::Crypto)
    }

    #[must_use]
    pub const fn artifact(&self) -> &T {
        &self.artifact
    }

    #[must_use]
    pub const fn signer_public_key(&self) -> &PublicKeyValue {
        &self.signer_public_key
    }
}

impl SignedExecutionPermit {
    /// Verifies both signature and configurable permit lifetime.
    ///
    /// # Errors
    /// Returns an error if signature or time validation fails.
    pub fn verify_permit(
        &self,
        policy: PermitTimePolicy,
        now: UtcTimestamp,
    ) -> Result<(), SignedArtifactError> {
        self.verify()?;
        self.artifact
            .validate_time(policy, now)
            .map_err(SignedArtifactError::PermitTime)
    }
}

#[derive(Debug)]
pub enum SignedArtifactError {
    InvalidMarker,
    Crypto(CryptoError),
    PermitTime(PermitTimeError),
}

impl std::fmt::Display for SignedArtifactError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::InvalidMarker => {
                formatter.write_str("artifact is not marked NON_PRODUCTION_DEMO")
            }
            Self::Crypto(error) => write!(formatter, "{error}"),
            Self::PermitTime(_) => formatter.write_str("permit time validation failed"),
        }
    }
}

impl std::error::Error for SignedArtifactError {}

/// Computes the stable SHA-384 digest under the artifact's fixed domain.
///
/// # Errors
/// Returns an error when canonicalization fails.
pub fn artifact_digest<T: DomainSeparated + Serialize>(
    artifact: &T,
) -> Result<Digest384Value, CryptoError> {
    digest(T::DOMAIN, artifact)
}

/// Test-only hook for proving domain separation. Not exported in production builds.
#[cfg(test)]
fn verify_with_domain<T: Serialize>(
    envelope: &SignedArtifact<T>,
    domain: &[u8],
) -> Result<(), CryptoError> {
    verify(
        domain,
        &envelope.artifact,
        &envelope.signer_public_key,
        &envelope.signature,
    )
}

#[cfg(test)]
mod tests {
    use serde_json::Value;

    use super::*;
    use crate::action::{RawActionProposal, ReasonCode};
    use crate::crypto::public_key_fingerprint;
    use crate::ids::{
        AgentId, BudgetReservationId, EffectOperationId, InstanceId, Jti, PepId, PermitId,
        PolicyVersion, RequestId, SessionId,
    };
    use crate::permit::{ExecutionPermitFields, PermitTimePolicy};

    const KEY_ONE: &str = "AQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQE";
    const KEY_TWO: &str = "AgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgI";

    fn key_one() -> SigningKeyMaterial {
        SigningKeyMaterial::from_encoded(KEY_ONE).unwrap()
    }

    fn action() -> RawActionProposal {
        RawActionProposal {
            request_id: RequestId::new("request-1").unwrap(),
            session_id: SessionId::new("session-1").unwrap(),
            action: "READ_FILE".to_owned(),
            resource: "inbox/report.txt".to_owned(),
            size_bytes: Some(10),
            purpose: "analysis".to_owned(),
            destination: None,
        }
    }

    fn containment() -> ContainmentEvent {
        ContainmentEvent {
            instance_id: InstanceId::new("instance-1").unwrap(),
            containment_epoch: 2,
            reason: ReasonCode::AgentContained,
            occurred_at: UtcTimestamp::from_unix_seconds(1_000),
        }
    }

    fn permit_fields(issued: i64, expires: i64) -> ExecutionPermitFields {
        let key = key_one();
        ExecutionPermitFields {
            permit_id: PermitId::new("permit-1").unwrap(),
            jti: Jti::new("jti-1").unwrap(),
            request_digest: artifact_digest(&action()).unwrap(),
            agent_id: AgentId::new("agent-1").unwrap(),
            instance_id: InstanceId::new("instance-1").unwrap(),
            session_id: SessionId::new("session-1").unwrap(),
            holder_key_fingerprint: public_key_fingerprint(&key.public_key()).unwrap(),
            audience_pep_id: PepId::new("pep-1").unwrap(),
            issued_at: UtcTimestamp::from_unix_seconds(issued),
            expires_at: UtcTimestamp::from_unix_seconds(expires),
            nonce: "nonce-1".to_owned(),
            effect_operation_id: EffectOperationId::new("effect-operation-1").unwrap(),
            session_epoch: 3,
            containment_epoch: 2,
            budget_reservation_id: BudgetReservationId::new("reservation-1").unwrap(),
            policy_version: PolicyVersion::new("policy-v1").unwrap(),
            policy_digest: artifact_digest(&containment()).unwrap(),
        }
    }

    fn permit() -> ExecutionPermit {
        ExecutionPermit::new(
            permit_fields(1_000, 1_030),
            PermitTimePolicy::default(),
            UtcTimestamp::from_unix_seconds(1_000),
        )
        .unwrap()
    }

    #[test]
    fn all_required_artifacts_sign_and_verify() {
        let key = key_one();
        SignedActionProposal::sign(action(), &key)
            .unwrap()
            .verify()
            .unwrap();
        SignedExecutionPermit::sign(permit(), &key)
            .unwrap()
            .verify_permit(
                PermitTimePolicy::default(),
                UtcTimestamp::from_unix_seconds(1_001),
            )
            .unwrap();
        SignedContainmentEvent::sign(containment(), &key)
            .unwrap()
            .verify()
            .unwrap();
    }

    #[test]
    fn permit_binds_jti_nonce_and_effect_operation_id() {
        let envelope = SignedExecutionPermit::sign(permit(), &key_one()).unwrap();
        let base = serde_json::to_value(&envelope).unwrap();
        let replacements = [
            ("permit_id", Value::String("permit-2".to_owned())),
            ("jti", Value::String("jti-2".to_owned())),
            (
                "request_digest",
                Value::String(artifact_digest(&containment()).unwrap().as_str().to_owned()),
            ),
            ("agent_id", Value::String("agent-2".to_owned())),
            ("instance_id", Value::String("instance-2".to_owned())),
            ("session_id", Value::String("session-2".to_owned())),
            (
                "holder_key_fingerprint",
                Value::String(artifact_digest(&action()).unwrap().as_str().to_owned()),
            ),
            ("audience_pep_id", Value::String("pep-2".to_owned())),
            ("issued_at", Value::from(999)),
            ("expires_at", Value::from(1029)),
            ("nonce", Value::String("nonce-2".to_owned())),
            (
                "effect_operation_id",
                Value::String("effect-operation-2".to_owned()),
            ),
            ("session_epoch", Value::from(4)),
            ("containment_epoch", Value::from(3)),
            (
                "budget_reservation_id",
                Value::String("reservation-2".to_owned()),
            ),
            ("policy_version", Value::String("policy-v2".to_owned())),
            (
                "policy_digest",
                Value::String(artifact_digest(&action()).unwrap().as_str().to_owned()),
            ),
        ];
        for (field, replacement) in replacements {
            let mut tampered = base.clone();
            tampered["artifact"][field] = replacement;
            let decoded: SignedExecutionPermit = serde_json::from_value(tampered).unwrap();
            assert!(decoded.verify().is_err(), "field was not signed: {field}");
        }
    }

    #[test]
    fn wrong_key_and_domain_are_rejected() {
        let mut value =
            serde_json::to_value(SignedActionProposal::sign(action(), &key_one()).unwrap())
                .unwrap();
        value["signer_public_key"] = Value::String(key_one().public_key().as_str().to_owned());
        let wrong_key = SigningKeyMaterial::from_encoded(KEY_TWO)
            .unwrap()
            .public_key();
        value["signer_public_key"] = Value::String(wrong_key.as_str().to_owned());
        let decoded: SignedActionProposal = serde_json::from_value(value).unwrap();
        assert!(decoded.verify().is_err());

        let valid = SignedActionProposal::sign(action(), &key_one()).unwrap();
        assert!(verify_with_domain(&valid, EXECUTION_PERMIT_DOMAIN).is_err());
    }

    #[test]
    fn unknown_envelope_field_is_rejected() {
        let envelope = SignedActionProposal::sign(action(), &key_one()).unwrap();
        let mut value = serde_json::to_value(envelope).unwrap();
        value["unexpected"] = Value::Bool(true);
        assert!(serde_json::from_value::<SignedActionProposal>(value).is_err());
    }

    #[test]
    fn permit_time_bounds_are_enforced_at_construction() {
        let policy = PermitTimePolicy::default();
        let now = UtcTimestamp::from_unix_seconds(1_000);
        assert_eq!(
            ExecutionPermit::new(permit_fields(900, 1_000), policy, now),
            Err(PermitTimeError::Expired)
        );
        assert_eq!(
            ExecutionPermit::new(permit_fields(1_006, 1_020), policy, now),
            Err(PermitTimeError::IssuedInFuture)
        );
        assert_eq!(
            ExecutionPermit::new(permit_fields(1_000, 1_061), policy, now),
            Err(PermitTimeError::LifetimeExceeded)
        );
    }

    #[test]
    fn permit_time_bounds_are_rechecked_during_verification() {
        let policy = PermitTimePolicy::default();
        let now = UtcTimestamp::from_unix_seconds(1_000);
        for (issued_at, expires_at) in [(900, 1_000), (1_006, 1_020), (1_000, 1_061)] {
            let mut value = serde_json::to_value(permit()).unwrap();
            value["issued_at"] = Value::from(issued_at);
            value["expires_at"] = Value::from(expires_at);
            let unchecked: ExecutionPermit = serde_json::from_value(value).unwrap();
            let envelope = SignedExecutionPermit::sign(unchecked, &key_one()).unwrap();
            assert!(envelope.verify_permit(policy, now).is_err());
        }
    }

    #[test]
    fn digest_is_stable_and_changes_with_a_field() {
        let first = action();
        let same = action();
        let mut changed = action();
        changed.resource = "inbox/other.txt".to_owned();
        assert_eq!(
            artifact_digest(&first).unwrap(),
            artifact_digest(&same).unwrap()
        );
        assert_ne!(
            artifact_digest(&first).unwrap(),
            artifact_digest(&changed).unwrap()
        );
    }

    #[test]
    fn all_domain_separators_are_distinct_and_nul_terminated() {
        let domains = [
            ACTION_PROPOSAL_DOMAIN,
            EXECUTION_PERMIT_DOMAIN,
            CONTAINMENT_EVENT_DOMAIN,
            AUDIT_EVENT_DOMAIN,
        ];
        for domain in domains {
            assert_eq!(domain.last(), Some(&0));
        }
        for left in 0..domains.len() {
            for right in (left + 1)..domains.len() {
                assert_ne!(domains[left], domains[right]);
            }
        }
    }

    #[test]
    fn python_rust_interoperability_fixture_verifies() {
        let fixture_path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../../fixtures/interop-action.json");
        let fixture: Value = serde_json::from_slice(&std::fs::read(fixture_path).unwrap()).unwrap();
        let proposal: RawActionProposal =
            serde_json::from_value(fixture["proposal"].clone()).unwrap();
        assert_eq!(
            String::from_utf8(crate::canonical::canonical_json(&proposal).unwrap()).unwrap(),
            fixture["canonical_json"]
        );
        assert_eq!(
            crate::crypto::digest(ACTION_PROPOSAL_DOMAIN, &proposal)
                .unwrap()
                .as_str(),
            fixture["digest_sha384"].as_str().unwrap()
        );
        let envelope: SignedActionProposal = serde_json::from_value(serde_json::json!({"marker":DEMO_MARKER,"artifact":proposal,"signer_public_key":fixture["public_key"],"signature":fixture["signature"]})).unwrap();
        envelope.verify().unwrap();
    }
}
