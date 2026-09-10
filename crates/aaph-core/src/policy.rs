//! Pure, attenuating demonstration policy decision point.

use std::collections::{BTreeMap, BTreeSet};

use crate::action::{
    ActionKind, CanonicalActionRequest, CanonicalizationError, RawActionProposal, ReasonCode,
};
use crate::agent::EffectiveAuthority;
use crate::budget::BudgetAmounts;
use crate::permit::{Decision, DecisionRecord};
use crate::UtcTimestamp;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ActionPolicy {
    pub resource_prefix: String,
    pub purposes: BTreeSet<String>,
    pub max_bytes: Option<u64>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DemoPolicy {
    rules: BTreeMap<ActionKind, ActionPolicy>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DemoPolicyConfig {
    pub enabled_actions: BTreeSet<ActionKind>,
    pub purposes: BTreeSet<String>,
    pub max_read_bytes: u64,
    pub max_write_bytes: u64,
}

impl DemoPolicy {
    #[must_use]
    pub fn closed_default() -> Self {
        Self::from_config(DemoPolicyConfig {
            enabled_actions: BTreeSet::from([
                ActionKind::ListDirectory,
                ActionKind::ReadFile,
                ActionKind::ComputeSha256,
                ActionKind::WriteReport,
            ]),
            purposes: BTreeSet::from(["analysis".to_owned()]),
            max_read_bytes: 1_048_576,
            max_write_bytes: 262_144,
        })
    }

    #[must_use]
    pub fn from_config(config: DemoPolicyConfig) -> Self {
        let mut rules = BTreeMap::new();
        for action in config.enabled_actions {
            let (resource_prefix, max_bytes) = match action {
                ActionKind::ListDirectory | ActionKind::ComputeSha256 => ("inbox/", None),
                ActionKind::ReadFile => ("inbox/", Some(config.max_read_bytes)),
                ActionKind::WriteReport => ("output/", Some(config.max_write_bytes)),
            };
            rules.insert(
                action,
                ActionPolicy {
                    resource_prefix: resource_prefix.to_owned(),
                    purposes: config.purposes.clone(),
                    max_bytes,
                },
            );
        }
        Self { rules }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AuthenticationContext {
    AuthenticatedAndBound,
    AuthenticatedDigestMismatch,
    AuthenticatedReplay,
    UnattributedReplay,
    AuthenticatedExpiredPermit,
    UnattributedExpiredPermit,
    UnauthenticatedBadSignature,
    Indeterminate,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DecisionClass {
    Permit,
    OrdinaryDeny,
    ContainmentRequested,
    InternalFailClosed,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PolicyOutcome {
    pub record: DecisionRecord,
    pub class: DecisionClass,
    pub budget: Option<BudgetAmounts>,
}

/// Authenticates semantic binding, canonicalizes hostile input, and evaluates policy.
#[must_use]
pub fn evaluate_proposal(
    proposal: RawActionProposal,
    authority: &EffectiveAuthority,
    policy: &DemoPolicy,
    authentication: AuthenticationContext,
    decided_at: UtcTimestamp,
) -> PolicyOutcome {
    if let Some(result) = authentication_outcome(&proposal.request_id, authentication, decided_at) {
        return result;
    }
    if proposal.destination.is_some() {
        return outcome(
            &proposal.request_id,
            Decision::Quarantine,
            ReasonCode::DestinationNotAllowed,
            DecisionClass::ContainmentRequested,
            decided_at,
            None,
        );
    }
    let request_id = proposal.request_id.clone();
    let request = match CanonicalActionRequest::try_from(proposal) {
        Ok(request) => request,
        Err(
            CanonicalizationError::UnknownAction | CanonicalizationError::InvalidActionNameLength,
        ) => {
            return outcome(
                &request_id,
                Decision::Quarantine,
                ReasonCode::ActionNotAllowed,
                DecisionClass::ContainmentRequested,
                decided_at,
                None,
            )
        }
        Err(CanonicalizationError::SizeLimitExceeded) => {
            return outcome(
                &request_id,
                Decision::Deny,
                ReasonCode::SchemaInvalid,
                DecisionClass::OrdinaryDeny,
                decided_at,
                None,
            )
        }
    };
    evaluate_canonical(&request, authority, policy, decided_at)
}

fn authentication_outcome(
    request_id: &crate::ids::RequestId,
    authentication: AuthenticationContext,
    decided_at: UtcTimestamp,
) -> Option<PolicyOutcome> {
    let (decision, reason, class) = match authentication {
        AuthenticationContext::AuthenticatedAndBound => return None,
        AuthenticationContext::UnauthenticatedBadSignature => (
            Decision::Deny,
            ReasonCode::BadSignature,
            DecisionClass::OrdinaryDeny,
        ),
        AuthenticationContext::AuthenticatedDigestMismatch => (
            Decision::Quarantine,
            ReasonCode::RequestDigestMismatch,
            DecisionClass::ContainmentRequested,
        ),
        AuthenticationContext::AuthenticatedReplay => (
            Decision::Quarantine,
            ReasonCode::Replay,
            DecisionClass::ContainmentRequested,
        ),
        AuthenticationContext::UnattributedReplay => (
            Decision::Deny,
            ReasonCode::Replay,
            DecisionClass::OrdinaryDeny,
        ),
        AuthenticationContext::AuthenticatedExpiredPermit => (
            Decision::Quarantine,
            ReasonCode::PermitExpired,
            DecisionClass::ContainmentRequested,
        ),
        AuthenticationContext::UnattributedExpiredPermit => (
            Decision::Deny,
            ReasonCode::PermitExpired,
            DecisionClass::OrdinaryDeny,
        ),
        AuthenticationContext::Indeterminate => (
            Decision::Deny,
            ReasonCode::InternalFailClosed,
            DecisionClass::InternalFailClosed,
        ),
    };
    Some(outcome(
        request_id, decision, reason, class, decided_at, None,
    ))
}

fn evaluate_canonical(
    request: &CanonicalActionRequest,
    authority: &EffectiveAuthority,
    policy: &DemoPolicy,
    decided_at: UtcTimestamp,
) -> PolicyOutcome {
    if !valid_action_resource(request.action(), request.resource()) {
        return outcome(
            request.request_id(),
            Decision::Quarantine,
            ReasonCode::ResourceOutOfScope,
            DecisionClass::ContainmentRequested,
            decided_at,
            None,
        );
    }
    if let Some(result) = authority_outcome(request, authority, decided_at) {
        return result;
    }
    evaluate_policy_rule(request, policy, decided_at)
}

fn authority_outcome(
    request: &CanonicalActionRequest,
    authority: &EffectiveAuthority,
    decided_at: UtcTimestamp,
) -> Option<PolicyOutcome> {
    let (mandate_action, definition_action, manifest_action) =
        authority.all_allow_action(request.action());
    if !manifest_action {
        return Some(outcome(
            request.request_id(),
            Decision::Quarantine,
            ReasonCode::ActionNotAllowed,
            DecisionClass::ContainmentRequested,
            decided_at,
            None,
        ));
    }
    if !mandate_action || !definition_action {
        return Some(outcome(
            request.request_id(),
            Decision::Deny,
            ReasonCode::ActionNotAllowed,
            DecisionClass::OrdinaryDeny,
            decided_at,
            None,
        ));
    }
    if !authority.all_allow_resource(request.resource()) {
        return Some(outcome(
            request.request_id(),
            Decision::Quarantine,
            ReasonCode::ResourceOutOfScope,
            DecisionClass::ContainmentRequested,
            decided_at,
            None,
        ));
    }
    if !authority.all_allow_purpose(request.purpose()) {
        return Some(outcome(
            request.request_id(),
            Decision::Deny,
            ReasonCode::PurposeNotAllowed,
            DecisionClass::OrdinaryDeny,
            decided_at,
            None,
        ));
    }
    None
}

fn evaluate_policy_rule(
    request: &CanonicalActionRequest,
    policy: &DemoPolicy,
    decided_at: UtcTimestamp,
) -> PolicyOutcome {
    let Some(rule) = policy.rules.get(&request.action()) else {
        return outcome(
            request.request_id(),
            Decision::Deny,
            ReasonCode::ActionNotAllowed,
            DecisionClass::OrdinaryDeny,
            decided_at,
            None,
        );
    };
    if !rule.purposes.contains(request.purpose()) {
        return outcome(
            request.request_id(),
            Decision::Deny,
            ReasonCode::PurposeNotAllowed,
            DecisionClass::OrdinaryDeny,
            decided_at,
            None,
        );
    }
    if !request.resource().starts_with(&rule.resource_prefix) {
        return outcome(
            request.request_id(),
            Decision::Quarantine,
            ReasonCode::ResourceOutOfScope,
            DecisionClass::ContainmentRequested,
            decided_at,
            None,
        );
    }
    if let Some(maximum) = rule.max_bytes {
        let Some(size) = request.size_bytes() else {
            return outcome(
                request.request_id(),
                Decision::Deny,
                ReasonCode::SchemaInvalid,
                DecisionClass::OrdinaryDeny,
                decided_at,
                None,
            );
        };
        if size > maximum {
            return outcome(
                request.request_id(),
                Decision::Deny,
                ReasonCode::ActionNotAllowed,
                DecisionClass::OrdinaryDeny,
                decided_at,
                None,
            );
        }
    }
    let size = request.size_bytes().unwrap_or(0);
    let budget = match request.action() {
        ActionKind::ReadFile => BudgetAmounts {
            action_count: 1,
            read_bytes: size,
            write_bytes: 0,
        },
        ActionKind::WriteReport => BudgetAmounts {
            action_count: 1,
            read_bytes: 0,
            write_bytes: size,
        },
        ActionKind::ListDirectory | ActionKind::ComputeSha256 => BudgetAmounts {
            action_count: 1,
            read_bytes: 0,
            write_bytes: 0,
        },
    };
    outcome(
        request.request_id(),
        Decision::Permit,
        ReasonCode::PolicyMatch,
        DecisionClass::Permit,
        decided_at,
        Some(budget),
    )
}

fn valid_logical_path(path: &str) -> bool {
    if path.is_empty()
        || path.starts_with('/')
        || path.starts_with('\\')
        || path.contains('\0')
        || path.contains('\\')
    {
        return false;
    }
    let mut components = path.split('/');
    let Some(first) = components.next() else {
        return false;
    };
    if first.contains(':') {
        return false;
    }
    !std::iter::once(first)
        .chain(components)
        .any(|part| part.is_empty() || part == "." || part == "..")
}

fn valid_action_resource(action: ActionKind, path: &str) -> bool {
    (action == ActionKind::ListDirectory && path == "inbox/") || valid_logical_path(path)
}

fn outcome(
    request_id: &crate::ids::RequestId,
    decision: Decision,
    reason: ReasonCode,
    class: DecisionClass,
    decided_at: UtcTimestamp,
    budget: Option<BudgetAmounts>,
) -> PolicyOutcome {
    PolicyOutcome {
        record: DecisionRecord {
            request_id: request_id.clone(),
            decision,
            reason,
            decided_at,
        },
        class,
        budget,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::agent::{attenuate_authority, AgentDefinition, BehavioralManifest};
    use crate::ids::{AgentId, BudgetId, MandateId, ReleaseId, RequestId, SessionId};
    use crate::mandate::{validate_mandate, Mandate};

    fn mandate(actions: Vec<ActionKind>) -> Mandate {
        Mandate {
            mandate_id: MandateId::new("mandate").unwrap(),
            agent_id: AgentId::new("agent").unwrap(),
            budget_id: BudgetId::new("budget").unwrap(),
            allowed_actions: actions,
            resource_prefixes: vec!["inbox/".to_owned(), "output/".to_owned()],
            purposes: vec!["analysis".to_owned()],
            not_before: UtcTimestamp::from_unix_seconds(900),
            expires_at: UtcTimestamp::from_unix_seconds(1_100),
        }
    }

    fn definition(actions: Vec<ActionKind>) -> AgentDefinition {
        AgentDefinition {
            agent_id: AgentId::new("agent").unwrap(),
            display_name: "demo".to_owned(),
            current_release_id: ReleaseId::new("release").unwrap(),
            allowed_actions: actions,
            resource_prefixes: vec!["inbox/".to_owned(), "output/".to_owned()],
            purposes: vec!["analysis".to_owned()],
        }
    }

    fn manifest(actions: Vec<ActionKind>) -> BehavioralManifest {
        BehavioralManifest {
            schema_version: 1,
            allowed_actions: actions,
            resource_prefixes: vec!["inbox/".to_owned(), "output/".to_owned()],
            purposes: vec!["analysis".to_owned()],
        }
    }

    fn authority(
        mandate_actions: Vec<ActionKind>,
        definition_actions: Vec<ActionKind>,
        manifest_actions: Vec<ActionKind>,
    ) -> EffectiveAuthority {
        let validated = validate_mandate(
            &mandate(mandate_actions),
            UtcTimestamp::from_unix_seconds(1_000),
        )
        .unwrap();
        attenuate_authority(
            &validated,
            &definition(definition_actions),
            &manifest(manifest_actions),
        )
        .unwrap()
    }

    fn proposal(action: &str, resource: &str) -> RawActionProposal {
        RawActionProposal {
            request_id: RequestId::new("request").unwrap(),
            session_id: SessionId::new("session").unwrap(),
            action: action.to_owned(),
            resource: resource.to_owned(),
            size_bytes: Some(10),
            purpose: "analysis".to_owned(),
            destination: None,
        }
    }

    fn decide(proposal: RawActionProposal, authority: &EffectiveAuthority) -> PolicyOutcome {
        evaluate_proposal(
            proposal,
            authority,
            &DemoPolicy::closed_default(),
            AuthenticationContext::AuthenticatedAndBound,
            UtcTimestamp::from_unix_seconds(1_000),
        )
    }

    #[test]
    fn valid_action_in_complete_intersection_is_permitted() {
        let all = vec![ActionKind::ReadFile];
        let result = decide(
            proposal("READ_FILE", "inbox/report.txt"),
            &authority(all.clone(), all.clone(), all),
        );
        assert_eq!(result.record.decision, Decision::Permit);
        assert_eq!(result.record.reason, ReasonCode::PolicyMatch);
        assert_eq!(
            result.budget,
            Some(BudgetAmounts {
                action_count: 1,
                read_bytes: 10,
                write_bytes: 0
            })
        );
    }

    #[test]
    fn listing_the_declared_inbox_root_is_permitted() {
        let all = vec![ActionKind::ListDirectory];
        let result = decide(
            proposal("LIST_DIRECTORY", "inbox/"),
            &authority(all.clone(), all.clone(), all),
        );
        assert_eq!(result.record.decision, Decision::Permit);
        assert_eq!(result.record.reason, ReasonCode::PolicyMatch);
    }

    #[test]
    fn definition_cannot_create_right_absent_from_mandate() {
        let result = decide(
            proposal("WRITE_REPORT", "output/report.txt"),
            &authority(
                vec![ActionKind::ReadFile],
                vec![ActionKind::ReadFile, ActionKind::WriteReport],
                vec![ActionKind::ReadFile, ActionKind::WriteReport],
            ),
        );
        assert_eq!(result.class, DecisionClass::OrdinaryDeny);
        assert_eq!(result.record.reason, ReasonCode::ActionNotAllowed);
    }

    #[test]
    fn mandate_right_absent_from_manifest_requests_containment() {
        let result = decide(
            proposal("READ_FILE", "inbox/report.txt"),
            &authority(
                vec![ActionKind::ReadFile],
                vec![ActionKind::ReadFile],
                vec![],
            ),
        );
        assert_eq!(result.class, DecisionClass::ContainmentRequested);
    }

    #[test]
    fn policy_rule_cannot_expand_effective_authority() {
        let expansive = DemoPolicy::closed_default();
        let effective = authority(
            vec![ActionKind::ReadFile],
            vec![ActionKind::ReadFile],
            vec![ActionKind::ReadFile],
        );
        let result = evaluate_proposal(
            proposal("WRITE_REPORT", "output/report.txt"),
            &effective,
            &expansive,
            AuthenticationContext::AuthenticatedAndBound,
            UtcTimestamp::from_unix_seconds(1_000),
        );
        assert_ne!(result.record.decision, Decision::Permit);
    }

    #[test]
    fn hostile_paths_destination_and_unknown_action_request_containment() {
        let all = vec![ActionKind::ReadFile];
        let effective = authority(all.clone(), all.clone(), all);
        for path in [
            "inbox/../secret",
            "C:/absolute",
            "/absolute",
            "inbox//file",
            "inbox/./file",
            "inbox/file\0tail",
        ] {
            assert_eq!(
                decide(proposal("READ_FILE", path), &effective).class,
                DecisionClass::ContainmentRequested,
                "path: {path:?}"
            );
        }
        let mut external = proposal("READ_FILE", "inbox/file");
        external.destination = Some("https://example.invalid".to_owned());
        assert_eq!(
            decide(external, &effective).record.reason,
            ReasonCode::DestinationNotAllowed
        );
        assert_eq!(
            decide(proposal("OPEN_SHELL", "inbox/file"), &effective).class,
            DecisionClass::ContainmentRequested
        );
    }

    #[test]
    fn authentication_controls_risk_attribution_and_unknown_state_fails_closed() {
        let all = vec![ActionKind::ReadFile];
        let effective = authority(all.clone(), all.clone(), all);
        let bad_signature = evaluate_proposal(
            proposal("OPEN_SHELL", "inbox/file"),
            &effective,
            &DemoPolicy::closed_default(),
            AuthenticationContext::UnauthenticatedBadSignature,
            UtcTimestamp::from_unix_seconds(1_000),
        );
        assert_eq!(bad_signature.class, DecisionClass::OrdinaryDeny);
        for context in [
            AuthenticationContext::UnattributedReplay,
            AuthenticationContext::UnattributedExpiredPermit,
        ] {
            let result = evaluate_proposal(
                proposal("READ_FILE", "inbox/file"),
                &effective,
                &DemoPolicy::closed_default(),
                context,
                UtcTimestamp::from_unix_seconds(1_000),
            );
            assert_eq!(result.class, DecisionClass::OrdinaryDeny);
        }
        for context in [
            AuthenticationContext::AuthenticatedReplay,
            AuthenticationContext::AuthenticatedExpiredPermit,
        ] {
            let result = evaluate_proposal(
                proposal("READ_FILE", "inbox/file"),
                &effective,
                &DemoPolicy::closed_default(),
                context,
                UtcTimestamp::from_unix_seconds(1_000),
            );
            assert_eq!(result.class, DecisionClass::ContainmentRequested);
        }
        let mismatch = evaluate_proposal(
            proposal("READ_FILE", "inbox/file"),
            &effective,
            &DemoPolicy::closed_default(),
            AuthenticationContext::AuthenticatedDigestMismatch,
            UtcTimestamp::from_unix_seconds(1_000),
        );
        assert_eq!(mismatch.class, DecisionClass::ContainmentRequested);
        let unknown = evaluate_proposal(
            proposal("READ_FILE", "inbox/file"),
            &effective,
            &DemoPolicy::closed_default(),
            AuthenticationContext::Indeterminate,
            UtcTimestamp::from_unix_seconds(1_000),
        );
        assert_eq!(unknown.class, DecisionClass::InternalFailClosed);
        assert_eq!(unknown.record.decision, Decision::Deny);
    }

    #[test]
    fn verdict_and_reason_are_deterministic() {
        let all = vec![ActionKind::ReadFile];
        let effective = authority(all.clone(), all.clone(), all);
        let first = decide(proposal("READ_FILE", "inbox/file"), &effective);
        let second = decide(proposal("READ_FILE", "inbox/file"), &effective);
        assert_eq!(first, second);
    }
}
