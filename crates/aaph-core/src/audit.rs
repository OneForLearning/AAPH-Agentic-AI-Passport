//! Tamper-evident SHA-384 audit chain.

use serde::Serialize;

use crate::crypto::{digest, CryptoError, Digest384Value, AUDIT_EVENT_DOMAIN};
use crate::permit::AuditEvent;
use crate::UtcTimestamp;

/// Base64url representation of 48 zero bytes, used as the documented genesis hash.
pub const AUDIT_GENESIS_HASH: &str =
    "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";

#[derive(Debug, Serialize)]
struct AuditEventBody<'a> {
    sequence: u64,
    event_type: &'a str,
    subject: &'a str,
    payload_digest: &'a Digest384Value,
    previous_hash: &'a Digest384Value,
    timestamp: UtcTimestamp,
}

#[derive(Debug)]
pub enum AuditChainError {
    InvalidSequence,
    EmptyEventType,
    EmptySubject,
    InvalidGenesis(CryptoError),
    Digest(CryptoError),
    PreviousHashMismatch,
    CurrentHashMismatch,
}

impl std::fmt::Display for AuditChainError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("audit chain validation failed")
    }
}

impl std::error::Error for AuditChainError {}

/// Returns the constant hash used before the first event.
///
/// # Errors
/// Returns an error only if the compiled-in constant is malformed.
pub fn genesis_hash() -> Result<Digest384Value, AuditChainError> {
    Digest384Value::parse(AUDIT_GENESIS_HASH).map_err(AuditChainError::InvalidGenesis)
}

/// Constructs one audit event and computes its current hash.
///
/// # Errors
/// Returns an error for empty metadata, sequence zero, or digest failure.
pub fn build_audit_event(
    sequence: u64,
    event_type: String,
    subject: String,
    payload_digest: Digest384Value,
    previous_hash: Digest384Value,
    timestamp: UtcTimestamp,
) -> Result<AuditEvent, AuditChainError> {
    if sequence == 0 {
        return Err(AuditChainError::InvalidSequence);
    }
    if event_type.is_empty() {
        return Err(AuditChainError::EmptyEventType);
    }
    if subject.is_empty() {
        return Err(AuditChainError::EmptySubject);
    }
    let current_hash = digest(
        AUDIT_EVENT_DOMAIN,
        &AuditEventBody {
            sequence,
            event_type: &event_type,
            subject: &subject,
            payload_digest: &payload_digest,
            previous_hash: &previous_hash,
            timestamp,
        },
    )
    .map_err(AuditChainError::Digest)?;
    Ok(AuditEvent {
        sequence,
        event_type,
        subject,
        payload_digest,
        previous_hash,
        timestamp,
        current_hash,
    })
}

/// Verifies sequence continuity, links, and every event digest.
///
/// # Errors
/// Returns an error on modification, deletion, insertion, or reordering.
pub fn verify_audit_chain(events: &[AuditEvent]) -> Result<(), AuditChainError> {
    let mut previous = genesis_hash()?;
    for (index, event) in events.iter().enumerate() {
        let expected_sequence = u64::try_from(index)
            .ok()
            .and_then(|value| value.checked_add(1))
            .ok_or(AuditChainError::InvalidSequence)?;
        if event.sequence != expected_sequence {
            return Err(AuditChainError::InvalidSequence);
        }
        if event.previous_hash != previous {
            return Err(AuditChainError::PreviousHashMismatch);
        }
        let rebuilt = build_audit_event(
            event.sequence,
            event.event_type.clone(),
            event.subject.clone(),
            event.payload_digest.clone(),
            event.previous_hash.clone(),
            event.timestamp,
        )?;
        if event.current_hash != rebuilt.current_hash {
            return Err(AuditChainError::CurrentHashMismatch);
        }
        previous = event.current_hash.clone();
    }
    Ok(())
}
