//! Agent definition, release, and behavioral manifest contracts.

use crate::action::ActionKind;
use std::collections::BTreeSet;

use crate::ids::{AgentId, BudgetId, MandateId, ReleaseId};
use crate::mandate::{AuthorityScope, ValidatedAuthority};
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BehavioralManifest {
    pub schema_version: u32,
    pub allowed_actions: Vec<ActionKind>,
    pub resource_prefixes: Vec<String>,
    pub purposes: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AgentRelease {
    pub release_id: ReleaseId,
    pub agent_id: AgentId,
    pub version: String,
    pub manifest: BehavioralManifest,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AgentDefinition {
    pub agent_id: AgentId,
    pub display_name: String,
    pub current_release_id: ReleaseId,
    pub allowed_actions: Vec<ActionKind>,
    pub resource_prefixes: Vec<String>,
    pub purposes: Vec<String>,
}

/// Authority after mandatory attenuation by definition and manifest.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EffectiveAuthority {
    pub(crate) mandate_id: MandateId,
    pub(crate) budget_id: BudgetId,
    pub(crate) scope: AuthorityScope,
    mandate_scope: AuthorityScope,
    definition_scope: AuthorityScope,
    manifest_scope: AuthorityScope,
}

impl EffectiveAuthority {
    #[must_use]
    pub fn contains(&self, action: ActionKind, resource: &str, purpose: &str) -> bool {
        self.scope.contains(action, resource, purpose)
    }

    #[must_use]
    pub(crate) fn all_allow_action(&self, action: ActionKind) -> (bool, bool, bool) {
        (
            self.mandate_scope.allows_action(action),
            self.definition_scope.allows_action(action),
            self.manifest_scope.allows_action(action),
        )
    }

    #[must_use]
    pub(crate) fn all_allow_resource(&self, resource: &str) -> bool {
        self.mandate_scope.allows_resource(resource)
            && self.definition_scope.allows_resource(resource)
            && self.manifest_scope.allows_resource(resource)
    }

    #[must_use]
    pub(crate) fn all_allow_purpose(&self, purpose: &str) -> bool {
        self.mandate_scope.allows_purpose(purpose)
            && self.definition_scope.allows_purpose(purpose)
            && self.manifest_scope.allows_purpose(purpose)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AttenuationError {
    AgentMismatch,
}

fn scope(actions: &[ActionKind], resources: &[String], purposes: &[String]) -> AuthorityScope {
    AuthorityScope {
        actions: actions.iter().copied().collect::<BTreeSet<_>>(),
        resource_prefixes: resources.iter().cloned().collect(),
        purposes: purposes.iter().cloned().collect(),
    }
}

/// Intersects mandate authority with both agent-declared bounds.
///
/// # Errors
/// Returns an error when the definition does not identify the mandated agent.
pub fn attenuate_authority(
    authority: &ValidatedAuthority,
    definition: &AgentDefinition,
    manifest: &BehavioralManifest,
) -> Result<EffectiveAuthority, AttenuationError> {
    if authority.agent_id() != &definition.agent_id {
        return Err(AttenuationError::AgentMismatch);
    }
    let definition_scope = scope(
        &definition.allowed_actions,
        &definition.resource_prefixes,
        &definition.purposes,
    );
    let manifest_scope = scope(
        &manifest.allowed_actions,
        &manifest.resource_prefixes,
        &manifest.purposes,
    );
    Ok(EffectiveAuthority {
        mandate_id: authority.mandate_id.clone(),
        budget_id: authority.budget_id().clone(),
        scope: authority
            .scope()
            .intersection(&definition_scope)
            .intersection(&manifest_scope),
        mandate_scope: authority.scope().clone(),
        definition_scope,
        manifest_scope,
    })
}
