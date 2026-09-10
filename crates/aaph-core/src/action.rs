//! Raw and canonical action contracts.

use crate::ids::{RequestId, SessionId};
use serde::{Deserialize, Serialize};

/// Maximum accepted UTF-8 byte length of a raw action name.
pub const MAX_ACTION_NAME_BYTES: usize = 64;
/// Maximum accepted byte count for a single action.
pub const MAX_ACTION_BYTES: u64 = 16 * 1024 * 1024;

/// Closed set of registered remote actions.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum ActionKind {
    /// List entries below inbox.
    ListDirectory,
    /// Read a bounded file below inbox.
    ReadFile,
    /// Compute SHA-256 below inbox.
    ComputeSha256,
    /// Write a bounded report below output.
    WriteReport,
}

/// Stable reason codes emitted by validation and later decisions.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum ReasonCode {
    #[serde(rename = "E_BAD_SIGNATURE")]
    BadSignature,
    #[serde(rename = "E_SCHEMA_INVALID")]
    SchemaInvalid,
    #[serde(rename = "E_SESSION_INACTIVE")]
    SessionInactive,
    #[serde(rename = "E_SESSION_EXPIRED")]
    SessionExpired,
    #[serde(rename = "E_EPOCH_STALE")]
    EpochStale,
    #[serde(rename = "E_ACTION_NOT_ALLOWED")]
    ActionNotAllowed,
    #[serde(rename = "E_RESOURCE_OUT_OF_SCOPE")]
    ResourceOutOfScope,
    #[serde(rename = "E_DESTINATION_NOT_ALLOWED")]
    DestinationNotAllowed,
    #[serde(rename = "E_BUDGET_EXCEEDED")]
    BudgetExceeded,
    #[serde(rename = "E_REPLAY")]
    Replay,
    #[serde(rename = "E_AGENT_CONTAINED")]
    AgentContained,
    #[serde(rename = "E_PERMIT_EXPIRED")]
    PermitExpired,
    #[serde(rename = "E_AUDIENCE_MISMATCH")]
    AudienceMismatch,
    #[serde(rename = "E_REQUEST_DIGEST_MISMATCH")]
    RequestDigestMismatch,
    #[serde(rename = "E_MANDATE_INVALID")]
    MandateInvalid,
    #[serde(rename = "E_PURPOSE_NOT_ALLOWED")]
    PurposeNotAllowed,
    #[serde(rename = "E_INTERNAL_FAIL_CLOSED")]
    InternalFailClosed,
    #[serde(rename = "P_POLICY_MATCH")]
    PolicyMatch,
}

/// Untrusted proposal emitted by an agent.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RawActionProposal {
    pub request_id: RequestId,
    pub session_id: SessionId,
    /// Untrusted action name resolved only by controlled conversion.
    pub action: String,
    /// Workspace-relative resource text, not yet path-canonicalized.
    pub resource: String,
    pub size_bytes: Option<u64>,
    /// Declared business purpose, treated as hostile input.
    pub purpose: String,
    /// Any external destination is forbidden by policy.
    pub destination: Option<String>,
}

/// Validated, transport-independent request constructed by AAPH.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CanonicalActionRequest {
    request_id: RequestId,
    session_id: SessionId,
    action: ActionKind,
    resource: String,
    size_bytes: Option<u64>,
    purpose: String,
    destination: Option<String>,
}

impl CanonicalActionRequest {
    #[must_use]
    pub const fn action(&self) -> ActionKind {
        self.action
    }
    #[must_use]
    pub const fn request_id(&self) -> &RequestId {
        &self.request_id
    }
    #[must_use]
    pub const fn session_id(&self) -> &SessionId {
        &self.session_id
    }
    #[must_use]
    pub fn resource(&self) -> &str {
        &self.resource
    }
    #[must_use]
    pub const fn size_bytes(&self) -> Option<u64> {
        self.size_bytes
    }
    #[must_use]
    pub fn purpose(&self) -> &str {
        &self.purpose
    }
    #[must_use]
    pub fn destination(&self) -> Option<&str> {
        self.destination.as_deref()
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CanonicalizationError {
    InvalidActionNameLength,
    UnknownAction,
    SizeLimitExceeded,
}

impl TryFrom<RawActionProposal> for CanonicalActionRequest {
    type Error = CanonicalizationError;
    fn try_from(raw: RawActionProposal) -> Result<Self, Self::Error> {
        if raw.action.is_empty() || raw.action.len() > MAX_ACTION_NAME_BYTES {
            return Err(CanonicalizationError::InvalidActionNameLength);
        }
        let action = match raw.action.as_str() {
            "LIST_DIRECTORY" => ActionKind::ListDirectory,
            "READ_FILE" => ActionKind::ReadFile,
            "COMPUTE_SHA256" => ActionKind::ComputeSha256,
            "WRITE_REPORT" => ActionKind::WriteReport,
            _ => return Err(CanonicalizationError::UnknownAction),
        };
        if raw.size_bytes.is_some_and(|size| size > MAX_ACTION_BYTES) {
            return Err(CanonicalizationError::SizeLimitExceeded);
        }
        Ok(Self {
            request_id: raw.request_id,
            session_id: raw.session_id,
            action,
            resource: raw.resource,
            size_bytes: raw.size_bytes,
            purpose: raw.purpose,
            destination: raw.destination,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    fn raw(action: &str, size_bytes: Option<u64>) -> RawActionProposal {
        RawActionProposal {
            request_id: RequestId::new("request-1").unwrap(),
            session_id: SessionId::new("session-1").unwrap(),
            action: action.to_owned(),
            resource: "inbox/file.txt".to_owned(),
            size_bytes,
            purpose: "analysis".to_owned(),
            destination: None,
        }
    }

    #[test]
    fn action_kind_json_is_stable() {
        for (value, json) in [
            (ActionKind::ListDirectory, "\"LIST_DIRECTORY\""),
            (ActionKind::ReadFile, "\"READ_FILE\""),
            (ActionKind::ComputeSha256, "\"COMPUTE_SHA256\""),
            (ActionKind::WriteReport, "\"WRITE_REPORT\""),
        ] {
            assert_eq!(serde_json::to_string(&value).unwrap(), json);
            assert_eq!(serde_json::from_str::<ActionKind>(json).unwrap(), value);
        }
    }

    #[test]
    fn reason_code_json_is_stable() {
        let cases = [
            (ReasonCode::BadSignature, "E_BAD_SIGNATURE"),
            (ReasonCode::SchemaInvalid, "E_SCHEMA_INVALID"),
            (ReasonCode::SessionInactive, "E_SESSION_INACTIVE"),
            (ReasonCode::SessionExpired, "E_SESSION_EXPIRED"),
            (ReasonCode::EpochStale, "E_EPOCH_STALE"),
            (ReasonCode::ActionNotAllowed, "E_ACTION_NOT_ALLOWED"),
            (ReasonCode::ResourceOutOfScope, "E_RESOURCE_OUT_OF_SCOPE"),
            (
                ReasonCode::DestinationNotAllowed,
                "E_DESTINATION_NOT_ALLOWED",
            ),
            (ReasonCode::BudgetExceeded, "E_BUDGET_EXCEEDED"),
            (ReasonCode::Replay, "E_REPLAY"),
            (ReasonCode::AgentContained, "E_AGENT_CONTAINED"),
            (ReasonCode::PermitExpired, "E_PERMIT_EXPIRED"),
            (ReasonCode::AudienceMismatch, "E_AUDIENCE_MISMATCH"),
            (
                ReasonCode::RequestDigestMismatch,
                "E_REQUEST_DIGEST_MISMATCH",
            ),
            (ReasonCode::MandateInvalid, "E_MANDATE_INVALID"),
            (ReasonCode::PurposeNotAllowed, "E_PURPOSE_NOT_ALLOWED"),
            (ReasonCode::InternalFailClosed, "E_INTERNAL_FAIL_CLOSED"),
            (ReasonCode::PolicyMatch, "P_POLICY_MATCH"),
        ];
        for (value, name) in cases {
            let json = format!("\"{name}\"");
            assert_eq!(serde_json::to_string(&value).unwrap(), json);
            assert_eq!(serde_json::from_str::<ReasonCode>(&json).unwrap(), value);
        }
    }

    #[test]
    fn unknown_json_fields_are_rejected() {
        let json = r#"{"request_id":"r","session_id":"s","action":"READ_FILE","resource":"inbox/a","size_bytes":1,"extra":true}"#;
        assert!(serde_json::from_str::<RawActionProposal>(json).is_err());
        assert!(serde_json::from_str::<ActionKind>("\"OPEN_SHELL\"").is_err());
        let null_required = r#"{"request_id":null,"session_id":"s","action":"READ_FILE","resource":"inbox/a","size_bytes":1}"#;
        assert!(serde_json::from_str::<RawActionProposal>(null_required).is_err());
    }

    #[test]
    fn unknown_action_is_rejected() {
        assert_eq!(
            CanonicalActionRequest::try_from(raw("OPEN_SHELL", None)),
            Err(CanonicalizationError::UnknownAction)
        );
    }

    #[test]
    fn names_and_sizes_are_bounded() {
        assert_eq!(
            CanonicalActionRequest::try_from(raw(&"x".repeat(MAX_ACTION_NAME_BYTES + 1), None)),
            Err(CanonicalizationError::InvalidActionNameLength)
        );
        assert!(CanonicalActionRequest::try_from(raw("READ_FILE", Some(MAX_ACTION_BYTES))).is_ok());
        assert_eq!(
            CanonicalActionRequest::try_from(raw("READ_FILE", Some(MAX_ACTION_BYTES + 1))),
            Err(CanonicalizationError::SizeLimitExceeded)
        );
    }
}
