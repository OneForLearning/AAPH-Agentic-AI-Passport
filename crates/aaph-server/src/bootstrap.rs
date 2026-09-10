use aaph_authority::clock::{Clock as AuthorityClock, SystemClock as AuthoritySystemClock};
use aaph_authority::configuration::DemoConfig;
use aaph_authority::dispatcher::{ContainmentSink, EffectDispatcher, PermitDispatcher};
use aaph_authority::id_generator::ProductionIdGenerator;
use aaph_authority::orchestrator::{AuthorityOrchestrator, Ed25519PermitSigner};
use aaph_authority::storage::SqliteStore;
use aaph_authority::{
    bootstrap as bootstrap_authority, AuthorityApp, AuthorityServerIdentityConfig,
};
use aaph_core::crypto::{PublicKeyValue, SigningKeyMaterial};
use aaph_core::signed::{artifact_digest, SignedContainmentEvent, SignedExecutionPermit};
use aaph_core::UtcTimestamp;
use aaph_pep::replay::{ApplyResult, PepStore};
use aaph_pep::sandbox::Workspace;
use aaph_pep::{Clock as PepClock, PepApp, PepAppConfig};
use async_trait::async_trait;
use std::path::{Path, PathBuf};
use std::sync::Arc;

pub async fn run_cli() -> Result<(), Box<dyn std::error::Error>> {
    match command()? {
        Command::Help => {
            println!("Usage: aaph-server [healthcheck <url> <ca-file>]\n\nRuns the NON_PRODUCTION_DEMO unified HTTPS server.\n\nOptions:\n  -h, --help     Show help\n  -V, --version  Show version");
            Ok(())
        }
        Command::Version => {
            println!("aaph-server {}", env!("CARGO_PKG_VERSION"));
            Ok(())
        }
        Command::Healthcheck { url, ca } => healthcheck(&url, &ca).await,
        Command::Run => run().await,
    }
}

enum Command {
    Run,
    Help,
    Version,
    Healthcheck { url: String, ca: PathBuf },
}

fn command() -> Result<Command, std::io::Error> {
    let mut args = std::env::args_os().skip(1);
    let Some(first) = args.next() else {
        return Ok(Command::Run);
    };
    if first == "--help" || first == "-h" {
        return Ok(Command::Help);
    }
    if first == "--version" || first == "-V" {
        return Ok(Command::Version);
    }
    if first != "healthcheck" {
        return Err(std::io::Error::other("unknown command"));
    }
    let url = args
        .next()
        .and_then(|value| value.into_string().ok())
        .ok_or_else(|| std::io::Error::other("healthcheck URL is required"))?;
    let ca = args
        .next()
        .map(PathBuf::from)
        .ok_or_else(|| std::io::Error::other("healthcheck CA file is required"))?;
    if args.next().is_some() {
        return Err(std::io::Error::other("too many healthcheck arguments"));
    }
    Ok(Command::Healthcheck { url, ca })
}

async fn healthcheck(url: &str, ca: &Path) -> Result<(), Box<dyn std::error::Error>> {
    let certificate = reqwest::Certificate::from_pem(&std::fs::read(ca)?)?;
    reqwest::Client::builder()
        .https_only(true)
        .add_root_certificate(certificate)
        .timeout(std::time::Duration::from_secs(3))
        .build()?
        .get(url)
        .send()
        .await?
        .error_for_status()?;
    Ok(())
}

struct ServerConfig {
    public_addr: String,
    admin_addr: String,
    authority_database_url: String,
    pep_database_url: String,
    config_dir: PathBuf,
    workspace: PathBuf,
    public_tls_cert: PathBuf,
    public_tls_key: PathBuf,
    admin_tls_cert: PathBuf,
    admin_tls_key: PathBuf,
    agent_public_key: PathBuf,
    authority_signing_key: PathBuf,
    admin_secret: String,
}

impl ServerConfig {
    fn from_env() -> Result<Self, std::io::Error> {
        let public_tls_cert = PathBuf::from(required("AAPH_PUBLIC_TLS_CERT")?);
        let public_tls_key = PathBuf::from(required("AAPH_PUBLIC_TLS_KEY")?);
        let config = Self {
            public_addr: std::env::var("AAPH_PUBLIC_LISTEN_ADDR")
                .unwrap_or_else(|_| "127.0.0.1:3000".to_owned()),
            admin_addr: std::env::var("AAPH_ADMIN_LISTEN_ADDR")
                .unwrap_or_else(|_| "127.0.0.1:3002".to_owned()),
            authority_database_url: std::env::var("AAPH_AUTHORITY_DATABASE_URL")
                .unwrap_or_else(|_| "sqlite://authority.db".to_owned()),
            pep_database_url: std::env::var("AAPH_PEP_DATABASE_URL")
                .unwrap_or_else(|_| "sqlite://pep.db".to_owned()),
            config_dir: std::env::var("AAPH_CONFIG_DIR")
                .map_or_else(|_| PathBuf::from("config"), PathBuf::from),
            workspace: std::env::var("AAPH_PEP_WORKSPACE")
                .map_or_else(|_| PathBuf::from("pep-workspace"), PathBuf::from),
            admin_tls_cert: std::env::var("AAPH_ADMIN_TLS_CERT")
                .map_or_else(|_| public_tls_cert.clone(), PathBuf::from),
            admin_tls_key: std::env::var("AAPH_ADMIN_TLS_KEY")
                .map_or_else(|_| public_tls_key.clone(), PathBuf::from),
            public_tls_cert,
            public_tls_key,
            agent_public_key: PathBuf::from(required("AAPH_AGENT_PUBLIC_KEY_FILE")?),
            authority_signing_key: PathBuf::from(required("AAPH_AUTHORITY_SIGNING_KEY_FILE")?),
            admin_secret: required("AAPH_ADMIN_SECRET")?,
        };
        config.validate()?;
        Ok(config)
    }

    fn validate(&self) -> Result<(), std::io::Error> {
        if self.public_addr == self.admin_addr {
            return Err(std::io::Error::other(
                "public and admin listeners must use distinct addresses",
            ));
        }
        Ok(())
    }
}

#[derive(Clone)]
struct InternalPepSink {
    store: PepStore,
    authority: PublicKeyValue,
}

#[async_trait]
impl PermitDispatcher for InternalPepSink {
    async fn accept(&self, _permit: &SignedExecutionPermit) -> Result<(), ()> {
        Ok(())
    }
}

#[async_trait]
impl ContainmentSink for InternalPepSink {
    async fn propagate_containment(&self, event: &SignedContainmentEvent) -> Result<(), ()> {
        if event.signer_public_key() != &self.authority || event.verify().is_err() {
            return Err(());
        }
        let digest = artifact_digest(event.artifact()).map_err(|_| ())?;
        match self
            .store
            .apply_containment(
                event.artifact().instance_id.as_str(),
                event.artifact().containment_epoch,
                digest.as_str(),
            )
            .await
            .map_err(|_| ())?
        {
            ApplyResult::Applied | ApplyResult::AlreadyApplied => Ok(()),
            ApplyResult::Regressive => Err(()),
        }
    }
}

pub struct ServerRouters {
    pub public: axum::Router,
    pub admin: axum::Router,
}

async fn assemble(config: &ServerConfig) -> Result<ServerRouters, Box<dyn std::error::Error>> {
    std::fs::create_dir_all(config.workspace.join("inbox"))?;
    std::fs::create_dir_all(config.workspace.join("output"))?;
    let authority_store = SqliteStore::connect(&config.authority_database_url).await?;
    authority_store.migrate().await?;
    let pep_store = PepStore::connect(&config.pep_database_url).await?;
    pep_store.set_epoch("demo-instance", 0, 0).await?;
    let authority_clock: Arc<dyn AuthorityClock> = Arc::new(AuthoritySystemClock);
    let demo = DemoConfig::load(&config.config_dir, authority_clock.now())
        .map_err(std::io::Error::other)?;
    let identity = AuthorityServerIdentityConfig::from_public_key_file(&config.agent_public_key)?;
    bootstrap_authority(&authority_store, &demo, identity.agent_public_key()).await?;
    let authority_signing_key = SigningKeyMaterial::from_path(&config.authority_signing_key)
        .map_err(|_| std::io::Error::other("authority signing key is invalid"))?;
    let authority_public_key = authority_signing_key.public_key();
    let dispatcher: Arc<dyn EffectDispatcher> = Arc::new(InternalPepSink {
        store: pep_store.clone(),
        authority: authority_public_key.clone(),
    });
    let authority = AuthorityApp::new(AuthorityOrchestrator {
        store: authority_store,
        config: Arc::new(demo.clone()),
        clock: authority_clock,
        signer: Arc::new(Ed25519PermitSigner(authority_signing_key)),
        dispatcher,
        id_generator: Arc::new(ProductionIdGenerator),
        admin_secret: Arc::new(config.admin_secret.clone()),
        issuance_lock: Arc::new(tokio::sync::Mutex::new(())),
    });
    let pep_clock: Arc<dyn PepClock> = Arc::new(ServerClock);
    let pep = PepApp::new(
        pep_store,
        Arc::new(Workspace::open(
            &config.workspace,
            1024,
            1_048_576,
            262_144,
        )?),
        pep_clock,
        PepAppConfig {
            authority: authority_public_key,
            audience: demo.policy_file.audience_pep_id,
            body_limit: demo.policy_file.max_body_bytes,
            max_lifetime: demo.policy_file.permit_lifetime_seconds,
        },
    );
    Ok(ServerRouters {
        public: crate::public_api::router(&authority, &pep),
        admin: crate::admin_api::router(&authority),
    })
}

struct ServerClock;
impl PepClock for ServerClock {
    fn now(&self) -> UtcTimestamp {
        let seconds = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .ok()
            .and_then(|value| i64::try_from(value.as_secs()).ok())
            .unwrap_or(0);
        UtcTimestamp::from_unix_seconds(seconds)
    }
}

async fn run() -> Result<(), Box<dyn std::error::Error>> {
    tracing_subscriber::fmt()
        .json()
        .with_env_filter(tracing_subscriber::EnvFilter::from_default_env())
        .init();
    let config = ServerConfig::from_env()?;
    let routers = assemble(&config).await?;
    let public_tls = axum_server::tls_rustls::RustlsConfig::from_pem_file(
        &config.public_tls_cert,
        &config.public_tls_key,
    )
    .await?;
    let admin_tls = axum_server::tls_rustls::RustlsConfig::from_pem_file(
        &config.admin_tls_cert,
        &config.admin_tls_key,
    )
    .await?;
    let public_addr = config.public_addr.parse()?;
    let admin_addr = config.admin_addr.parse()?;
    tracing::info!(address = %config.public_addr, "NON_PRODUCTION_DEMO public listener ready");
    tracing::info!(address = %config.admin_addr, "NON_PRODUCTION_DEMO admin listener ready");
    tokio::try_join!(
        crate::public_api::serve(public_addr, public_tls, routers.public),
        crate::admin_api::serve(admin_addr, admin_tls, routers.admin)
    )?;
    Ok(())
}

fn required(name: &str) -> Result<String, std::io::Error> {
    std::env::var(name).map_err(|_| std::io::Error::other(format!("{name} is required")))
}

#[cfg(test)]
mod tests {
    use super::*;
    use aaph_core::action::ReasonCode;
    use aaph_core::ids::InstanceId;
    use aaph_core::permit::ContainmentEvent;
    use aaph_core::signed::SignedContainmentEvent;
    use axum::body::Body;
    use axum::http::{Request, StatusCode};
    use tower::ServiceExt;

    fn sqlite_url(path: &Path) -> String {
        format!("sqlite://{}", path.to_string_lossy().replace('\\', "/"))
    }

    #[tokio::test]
    async fn complete_server_builds_in_memory_with_public_agent_key_only() {
        let directory = tempfile::tempdir().unwrap();
        let authority_key_dir = directory.path().join("authority");
        aaph_core::crypto::generate_development_keypair(&authority_key_dir, false).unwrap();
        let authority_key_path = authority_key_dir.join("signing.key");
        let agent_public_path = directory.path().join("agent-public.key");
        std::fs::write(
            &agent_public_path,
            SigningKeyMaterial::generate().public_key().as_str(),
        )
        .unwrap();
        let workspace = directory.path().join("workspace");
        let config = ServerConfig {
            public_addr: "127.0.0.1:0".to_owned(),
            admin_addr: "127.0.0.1:1".to_owned(),
            authority_database_url: sqlite_url(&directory.path().join("authority.db")),
            pep_database_url: sqlite_url(&directory.path().join("pep.db")),
            config_dir: Path::new(env!("CARGO_MANIFEST_DIR")).join("../../config"),
            workspace,
            public_tls_cert: directory.path().join("unused-public.crt"),
            public_tls_key: directory.path().join("unused-public.key"),
            admin_tls_cert: directory.path().join("unused-admin.crt"),
            admin_tls_key: directory.path().join("unused-admin.key"),
            agent_public_key: agent_public_path,
            authority_signing_key: authority_key_path,
            admin_secret: "NON_PRODUCTION_DEMO_ADMIN".to_owned(),
        };
        config.validate().unwrap();
        let routers = assemble(&config).await.unwrap();

        let health = routers
            .public
            .clone()
            .oneshot(
                Request::builder()
                    .uri("/health")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(health.status(), StatusCode::OK);

        let direct = routers
            .public
            .clone()
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/v1/effects/execute")
                    .header("content-type", "application/json")
                    .body(Body::from("{}"))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(direct.status(), StatusCode::BAD_REQUEST);

        let admin_on_public = routers
            .public
            .oneshot(
                Request::builder()
                    .uri("/v1/admin/instances/demo-instance/recovery")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(admin_on_public.status(), StatusCode::NOT_FOUND);
        let public_on_admin = routers
            .admin
            .oneshot(
                Request::builder()
                    .uri("/health")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(public_on_admin.status(), StatusCode::NOT_FOUND);
    }

    #[tokio::test]
    async fn authority_containment_is_immediately_observed_by_pep() {
        let store = PepStore::connect("sqlite::memory:").await.unwrap();
        store.set_epoch("demo-instance", 0, 0).await.unwrap();
        let key = SigningKeyMaterial::generate();
        let sink = InternalPepSink {
            store: store.clone(),
            authority: key.public_key(),
        };
        let event = SignedContainmentEvent::sign(
            ContainmentEvent {
                instance_id: InstanceId::new("demo-instance").unwrap(),
                containment_epoch: 1,
                reason: ReasonCode::AgentContained,
                occurred_at: UtcTimestamp::from_unix_seconds(1_780_000_000),
            },
            &key,
        )
        .unwrap();
        sink.propagate_containment(&event).await.unwrap();
        assert_eq!(store.epochs("demo-instance").await.unwrap(), Some((0, 1)));
    }
}
