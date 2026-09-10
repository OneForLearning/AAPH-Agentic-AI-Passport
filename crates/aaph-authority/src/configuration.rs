use std::collections::BTreeSet;
use std::path::Path;

use aaph_core::action::ActionKind;
use aaph_core::agent::{AgentDefinition, BehavioralManifest};
use aaph_core::budget::BudgetAmounts;
use aaph_core::canonical::canonical_json;
use aaph_core::crypto::{digest, Digest384Value};
use aaph_core::ids::{PepId, PolicyVersion, ReleaseId};
use aaph_core::mandate::{validate_mandate, Mandate};
use aaph_core::policy::{DemoPolicy, DemoPolicyConfig};
use aaph_core::UtcTimestamp;
use serde::{Deserialize, Serialize};

const POLICY_DOMAIN: &[u8] = b"AAPH-POC-POLICY-CONFIG-V1\0";

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PolicyFile {
    pub schema_version: u32,
    pub policy_version: PolicyVersion,
    pub audience_pep_id: PepId,
    pub enabled_actions: BTreeSet<ActionKind>,
    pub purposes: BTreeSet<String>,
    pub max_read_bytes: u64,
    pub max_write_bytes: u64,
    pub session_lifetime_seconds: u64,
    pub permit_lifetime_seconds: u64,
    pub max_body_bytes: usize,
    pub budget: BudgetAmounts,
}

#[derive(Debug, Clone)]
pub struct DemoConfig {
    pub definition: AgentDefinition,
    pub manifest: BehavioralManifest,
    pub mandate: Mandate,
    pub policy_file: PolicyFile,
    pub policy: DemoPolicy,
    pub policy_digest: Digest384Value,
}

impl DemoConfig {
    /// Loads and validates the closed demo configuration files.
    ///
    /// # Errors
    /// Returns a bounded diagnostic when a file or schema is invalid.
    pub fn load(directory: &Path, now: UtcTimestamp) -> Result<Self, String> {
        let manifest: BehavioralManifest = read_json(&directory.join("agent-manifest.json"))?;
        let mandate: Mandate = read_json(&directory.join("mandate.json"))?;
        let policy_file: PolicyFile = read_json(&directory.join("policy.json"))?;
        if manifest.schema_version != 1 || policy_file.schema_version != 1 {
            return Err("unsupported configuration schema".to_owned());
        }
        validate_mandate(&mandate, now).map_err(|_| "invalid demo mandate".to_owned())?;
        if policy_file.enabled_actions.is_empty()
            || policy_file.purposes.is_empty()
            || policy_file.session_lifetime_seconds == 0
            || policy_file.permit_lifetime_seconds == 0
            || policy_file.permit_lifetime_seconds > 60
            || policy_file.max_body_bytes == 0
        {
            return Err("unsafe or empty policy configuration".to_owned());
        }
        let definition = AgentDefinition {
            agent_id: mandate.agent_id.clone(),
            display_name: "AAPH demo agent".to_owned(),
            current_release_id: ReleaseId::new("demo-release-v1").map_err(|e| e.to_string())?,
            allowed_actions: manifest.allowed_actions.clone(),
            resource_prefixes: manifest.resource_prefixes.clone(),
            purposes: manifest.purposes.clone(),
        };
        let policy = DemoPolicy::from_config(DemoPolicyConfig {
            enabled_actions: policy_file.enabled_actions.clone(),
            purposes: policy_file.purposes.clone(),
            max_read_bytes: policy_file.max_read_bytes,
            max_write_bytes: policy_file.max_write_bytes,
        });
        let policy_digest = digest(POLICY_DOMAIN, &policy_file).map_err(|e| e.to_string())?;
        Ok(Self {
            definition,
            manifest,
            mandate,
            policy_file,
            policy,
            policy_digest,
        })
    }
}

fn read_json<T: serde::de::DeserializeOwned>(path: &Path) -> Result<T, String> {
    let bytes = std::fs::read(path).map_err(|_| "configuration read failed".to_owned())?;
    serde_json::from_slice(&bytes).map_err(|_| "configuration schema invalid".to_owned())
}

/// Serializes a value using JCS.
///
/// # Errors
/// Returns a bounded diagnostic when canonicalization fails.
pub fn canonical<T: Serialize>(value: &T) -> Result<String, String> {
    let bytes = canonical_json(value).map_err(|_| "canonicalization failed".to_owned())?;
    String::from_utf8(bytes).map_err(|_| "canonical JSON was not UTF-8".to_owned())
}
