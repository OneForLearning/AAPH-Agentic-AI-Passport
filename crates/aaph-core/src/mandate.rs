//! Authority-bearing mandate contract.

use std::collections::BTreeSet;

use crate::action::ActionKind;
use crate::ids::{AgentId, BudgetId, MandateId};
use crate::UtcTimestamp;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Mandate {
    pub mandate_id: MandateId,
    pub agent_id: AgentId,
    pub budget_id: BudgetId,
    pub allowed_actions: Vec<ActionKind>,
    pub resource_prefixes: Vec<String>,
    pub purposes: Vec<String>,
    pub not_before: UtcTimestamp,
    pub expires_at: UtcTimestamp,
}

/// Closed authority dimensions shared by the attenuation stages.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AuthorityScope {
    pub(crate) actions: BTreeSet<ActionKind>,
    pub(crate) resource_prefixes: BTreeSet<String>,
    pub(crate) purposes: BTreeSet<String>,
}

impl AuthorityScope {
    #[must_use]
    pub(crate) fn allows_action(&self, action: ActionKind) -> bool {
        self.actions.contains(&action)
    }

    #[must_use]
    pub(crate) fn allows_resource(&self, resource: &str) -> bool {
        self.resource_prefixes
            .iter()
            .any(|prefix| resource.starts_with(prefix))
    }

    #[must_use]
    pub(crate) fn allows_purpose(&self, purpose: &str) -> bool {
        self.purposes.contains(purpose)
    }

    #[must_use]
    pub fn contains(&self, action: ActionKind, resource: &str, purpose: &str) -> bool {
        self.allows_action(action) && self.allows_resource(resource) && self.allows_purpose(purpose)
    }

    #[must_use]
    pub(crate) fn intersection(&self, other: &Self) -> Self {
        Self {
            actions: self.actions.intersection(&other.actions).copied().collect(),
            resource_prefixes: self
                .resource_prefixes
                .intersection(&other.resource_prefixes)
                .cloned()
                .collect(),
            purposes: self
                .purposes
                .intersection(&other.purposes)
                .cloned()
                .collect(),
        }
    }
}

/// Authority proven to originate from one currently valid mandate only.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ValidatedAuthority {
    pub(crate) mandate_id: MandateId,
    agent_id: AgentId,
    budget_id: BudgetId,
    scope: AuthorityScope,
}

impl ValidatedAuthority {
    #[must_use]
    pub const fn agent_id(&self) -> &AgentId {
        &self.agent_id
    }

    #[must_use]
    pub const fn budget_id(&self) -> &BudgetId {
        &self.budget_id
    }

    #[must_use]
    pub(crate) const fn scope(&self) -> &AuthorityScope {
        &self.scope
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MandateValidationError {
    NotYetValid,
    Expired,
    InvalidInterval,
    EmptyAuthority,
}

/// Validates a mandate and derives authority from no other input.
///
/// # Errors
/// Returns an error when dates or declared authority are invalid.
pub fn validate_mandate(
    mandate: &Mandate,
    now: UtcTimestamp,
) -> Result<ValidatedAuthority, MandateValidationError> {
    if mandate.expires_at <= mandate.not_before {
        return Err(MandateValidationError::InvalidInterval);
    }
    if now < mandate.not_before {
        return Err(MandateValidationError::NotYetValid);
    }
    if now >= mandate.expires_at {
        return Err(MandateValidationError::Expired);
    }
    if mandate.allowed_actions.is_empty()
        || mandate.resource_prefixes.is_empty()
        || mandate.purposes.is_empty()
    {
        return Err(MandateValidationError::EmptyAuthority);
    }
    Ok(ValidatedAuthority {
        mandate_id: mandate.mandate_id.clone(),
        agent_id: mandate.agent_id.clone(),
        budget_id: mandate.budget_id.clone(),
        scope: AuthorityScope {
            actions: mandate.allowed_actions.iter().copied().collect(),
            resource_prefixes: mandate.resource_prefixes.iter().cloned().collect(),
            purposes: mandate.purposes.iter().cloned().collect(),
        },
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn mandate() -> Mandate {
        Mandate {
            mandate_id: MandateId::new("m").unwrap(),
            agent_id: AgentId::new("a").unwrap(),
            budget_id: BudgetId::new("b").unwrap(),
            allowed_actions: vec![ActionKind::ReadFile],
            resource_prefixes: vec!["inbox/".to_owned()],
            purposes: vec!["analysis".to_owned()],
            not_before: UtcTimestamp::from_unix_seconds(10),
            expires_at: UtcTimestamp::from_unix_seconds(20),
        }
    }

    #[test]
    fn validation_derives_only_declared_mandate_authority() {
        let authority = validate_mandate(&mandate(), UtcTimestamp::from_unix_seconds(15)).unwrap();
        assert!(authority
            .scope()
            .contains(ActionKind::ReadFile, "inbox/file", "analysis"));
        assert!(!authority
            .scope()
            .contains(ActionKind::WriteReport, "output/file", "analysis"));
    }

    #[test]
    fn invalid_mandate_dates_and_empty_authority_are_rejected() {
        assert_eq!(
            validate_mandate(&mandate(), UtcTimestamp::from_unix_seconds(9)),
            Err(MandateValidationError::NotYetValid)
        );
        assert_eq!(
            validate_mandate(&mandate(), UtcTimestamp::from_unix_seconds(20)),
            Err(MandateValidationError::Expired)
        );
        let mut empty = mandate();
        empty.allowed_actions.clear();
        assert_eq!(
            validate_mandate(&empty, UtcTimestamp::from_unix_seconds(15)),
            Err(MandateValidationError::EmptyAuthority)
        );
    }
}
