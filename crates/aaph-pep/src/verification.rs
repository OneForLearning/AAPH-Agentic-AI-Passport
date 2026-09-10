use crate::replay::PepStore;
use aaph_core::action::{CanonicalActionRequest, ReasonCode};
use aaph_core::crypto::{digest, public_key_fingerprint, PublicKeyValue, ACTION_PROPOSAL_DOMAIN};
use aaph_core::ids::PepId;
use aaph_core::permit::PermitTimePolicy;
use aaph_core::signed::SignedExecutionPermit;
use aaph_core::UtcTimestamp;
use serde::Deserialize;

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EffectRequest {
    pub permit: SignedExecutionPermit,
    pub request: CanonicalActionRequest,
    pub holder_public_key: PublicKeyValue,
}

/// Verifies and atomically consumes an execution permit.
///
/// # Errors
///
/// Returns a stable fail-closed reason when any permit invariant fails.
pub async fn verify(
    input: &EffectRequest,
    authority: &PublicKeyValue,
    audience: &PepId,
    now: UtcTimestamp,
    max_lifetime: u64,
    store: &PepStore,
) -> Result<(), ReasonCode> {
    if input.permit.signer_public_key() != authority || input.permit.verify().is_err() {
        return Err(ReasonCode::BadSignature);
    }
    let permit = input.permit.artifact();
    if permit.audience_pep_id() != audience {
        return Err(ReasonCode::AudienceMismatch);
    }
    permit
        .validate_time(
            PermitTimePolicy {
                max_lifetime_seconds: max_lifetime,
                max_future_skew_seconds: 5,
            },
            now,
        )
        .map_err(|_| ReasonCode::PermitExpired)?;
    let request_digest = digest(ACTION_PROPOSAL_DOMAIN, &input.request)
        .map_err(|_| ReasonCode::InternalFailClosed)?;
    if &request_digest != permit.request_digest() {
        return Err(ReasonCode::RequestDigestMismatch);
    }
    let fingerprint =
        public_key_fingerprint(&input.holder_public_key).map_err(|_| ReasonCode::BadSignature)?;
    if &fingerprint != permit.holder_key_fingerprint()
        || input.request.session_id() != permit.session_id()
    {
        return Err(ReasonCode::BadSignature);
    }
    let epochs = store
        .epochs(permit.instance_id().as_str())
        .await
        .map_err(|_| ReasonCode::InternalFailClosed)?
        .ok_or(ReasonCode::EpochStale)?;
    if epochs != (permit.session_epoch(), permit.containment_epoch()) {
        return Err(ReasonCode::EpochStale);
    }
    Ok(())
}
