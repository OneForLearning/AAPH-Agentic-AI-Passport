pub mod clock;
pub mod configuration;
pub mod dispatcher;
pub mod id_generator;
pub mod orchestrator;
pub mod policy;
pub mod quarantine;
pub mod routes;
pub mod storage;

use crate::orchestrator::AuthorityOrchestrator;
use crate::storage::{BudgetRepository, DefinitionRepository, StateRepository};
use aaph_core::agent::AgentRelease;
use aaph_core::crypto::{public_key_fingerprint, PublicKeyValue};
use aaph_core::ids::InstanceId;

/// Public agent identity provisioned at the server boundary.
#[derive(Clone)]
pub struct AuthorityServerIdentityConfig {
    agent_public_key: PublicKeyValue,
}

impl AuthorityServerIdentityConfig {
    /// Loads the required publishable agent key from a file.
    ///
    /// # Errors
    ///
    /// Returns an error when the file is unavailable or is not a canonical
    /// Ed25519 public key.
    pub fn from_public_key_file(path: &std::path::Path) -> Result<Self, std::io::Error> {
        let value = std::fs::read_to_string(path).map_err(|error| {
            std::io::Error::new(
                error.kind(),
                format!(
                    "agent public key is unavailable at {}: {error}",
                    path.display()
                ),
            )
        })?;
        let agent_public_key = PublicKeyValue::parse(value.trim()).map_err(|_| {
            std::io::Error::other(format!("agent public key is invalid at {}", path.display()))
        })?;
        Ok(Self { agent_public_key })
    }

    #[must_use]
    pub const fn agent_public_key(&self) -> &PublicKeyValue {
        &self.agent_public_key
    }
}

/// Authority application assembled entirely from typed orchestration
/// dependencies, without opening a listener or a workspace capability.
pub struct AuthorityApp {
    orchestrator: AuthorityOrchestrator,
}

impl AuthorityApp {
    #[must_use]
    pub fn new(orchestrator: AuthorityOrchestrator) -> Self {
        Self { orchestrator }
    }

    pub fn router(self) -> axum::Router {
        routes::router(self.orchestrator)
    }

    pub fn public_router(&self) -> axum::Router {
        routes::public_router(self.orchestrator.clone())
    }

    pub fn admin_router(&self) -> axum::Router {
        routes::admin_router(self.orchestrator.clone())
    }
}
/// Installs the fixed demo authority objects when the store is empty.
///
/// # Errors
///
/// Returns an error when persistence, identifier validation, canonicalization,
/// or public-key fingerprinting fails.
pub async fn bootstrap(
    store: &storage::SqliteStore,
    config: &configuration::DemoConfig,
    public_key: &PublicKeyValue,
) -> Result<(), Box<dyn std::error::Error>> {
    let count: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM agent_definitions")
        .fetch_one(store.pool())
        .await?;
    if count != 0 {
        return Ok(());
    }
    store.put_agent_definition(&config.definition).await?;
    let release = AgentRelease {
        release_id: config.definition.current_release_id.clone(),
        agent_id: config.definition.agent_id.clone(),
        version: "1.0.0-demo".to_owned(),
        manifest: config.manifest.clone(),
    };
    let release_json = configuration::canonical(&release).map_err(std::io::Error::other)?;
    let manifest_json =
        configuration::canonical(&config.manifest).map_err(std::io::Error::other)?;
    store
        .put_release_and_manifest(
            &release.release_id,
            &release.agent_id,
            &release_json,
            &manifest_json,
            config.policy_digest.as_str(),
        )
        .await?;
    store.put_mandate(&config.mandate).await?;
    store
        .create_budget(
            &config.mandate.budget_id,
            &config.mandate.mandate_id,
            config.policy_file.budget,
        )
        .await?;
    let fingerprint = public_key_fingerprint(public_key)?;
    let instance_id = InstanceId::new("demo-instance")?;
    store
        .create_instance(
            &instance_id,
            &config.definition.agent_id,
            &config.definition.current_release_id,
            public_key.as_str(),
            fingerprint.as_str(),
        )
        .await?;
    Ok(())
}

#[cfg(test)]
mod server_identity_tests {
    use super::*;
    use aaph_core::crypto::SigningKeyMaterial;
    use std::sync::atomic::{AtomicU64, Ordering};

    static PATH_IDS: AtomicU64 = AtomicU64::new(1);

    fn public_key_file() -> (std::path::PathBuf, PublicKeyValue) {
        let key = SigningKeyMaterial::generate().public_key();
        let directory = std::env::temp_dir().join(format!(
            "aaph-server-public-key-{}-{}",
            std::process::id(),
            PATH_IDS.fetch_add(1, Ordering::Relaxed)
        ));
        std::fs::create_dir_all(&directory).unwrap();
        let path = directory.join("public.key");
        std::fs::write(&path, key.as_str()).unwrap();
        (path, key)
    }

    #[tokio::test]
    async fn server_starts_with_agent_public_key_only() {
        let (path, expected) = public_key_file();
        let identity = AuthorityServerIdentityConfig::from_public_key_file(&path).unwrap();
        assert_eq!(identity.agent_public_key(), &expected);

        let store = storage::SqliteStore::connect("sqlite::memory:")
            .await
            .unwrap();
        store.migrate().await.unwrap();
        let directory = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../../config");
        let config = configuration::DemoConfig::load(
            &directory,
            aaph_core::UtcTimestamp::from_unix_seconds(1_780_000_000),
        )
        .unwrap();
        bootstrap(&store, &config, identity.agent_public_key())
            .await
            .unwrap();
        let stored: String = sqlx::query_scalar(
            "SELECT public_key FROM agent_instances WHERE instance_id='demo-instance'",
        )
        .fetch_one(store.pool())
        .await
        .unwrap();
        assert_eq!(stored, expected.as_str());
        std::fs::remove_dir_all(path.parent().unwrap()).unwrap();
    }

    #[test]
    fn server_rejects_missing_agent_public_key() {
        let path = std::env::temp_dir().join(format!(
            "aaph-missing-agent-public-key-{}-{}",
            std::process::id(),
            PATH_IDS.fetch_add(1, Ordering::Relaxed)
        ));
        assert!(AuthorityServerIdentityConfig::from_public_key_file(&path).is_err());
        std::fs::write(&path, "not-a-public-key").unwrap();
        assert!(AuthorityServerIdentityConfig::from_public_key_file(&path).is_err());
        std::fs::remove_file(path).unwrap();
    }
}
