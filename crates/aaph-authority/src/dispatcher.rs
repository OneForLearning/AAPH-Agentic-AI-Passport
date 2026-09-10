use aaph_core::signed::SignedContainmentEvent;
use aaph_core::signed::SignedExecutionPermit;
use async_trait::async_trait;
use std::sync::atomic::{AtomicU64, Ordering};

static LAST_PROPAGATION_MILLIS: AtomicU64 = AtomicU64::new(0);

pub fn last_propagation_millis() -> u64 {
    LAST_PROPAGATION_MILLIS.load(Ordering::Relaxed)
}

#[async_trait]
pub trait PermitDispatcher: Send + Sync {
    async fn accept(&self, permit: &SignedExecutionPermit) -> Result<(), ()>;
}

#[async_trait]
pub trait ContainmentSink: Send + Sync {
    async fn propagate_containment(&self, event: &SignedContainmentEvent) -> Result<(), ()>;
}

pub trait EffectDispatcher: PermitDispatcher + ContainmentSink {}

impl<T> EffectDispatcher for T where T: PermitDispatcher + ContainmentSink {}

#[cfg(test)]
pub struct DeterministicNoopDispatcher;
pub struct HttpPepDispatcher {
    endpoint: String,
    client: reqwest::Client,
}
impl HttpPepDispatcher {
    /// Creates an HTTPS-only PEP client pinned to the supplied CA.
    ///
    /// # Errors
    /// Returns a client construction error for an invalid CA or TLS setup.
    pub fn new(endpoint: String, ca_pem: &[u8]) -> Result<Self, reqwest::Error> {
        let certificate = reqwest::Certificate::from_pem(ca_pem)?;
        let client = reqwest::Client::builder()
            .add_root_certificate(certificate)
            .https_only(true)
            .timeout(std::time::Duration::from_secs(5))
            .build()?;
        Ok(Self { endpoint, client })
    }
}

#[cfg(test)]
#[async_trait]
impl PermitDispatcher for DeterministicNoopDispatcher {
    async fn accept(&self, _permit: &SignedExecutionPermit) -> Result<(), ()> {
        Ok(())
    }
}

#[cfg(test)]
#[async_trait]
impl ContainmentSink for DeterministicNoopDispatcher {
    async fn propagate_containment(&self, _event: &SignedContainmentEvent) -> Result<(), ()> {
        Ok(())
    }
}

#[async_trait]
impl PermitDispatcher for HttpPepDispatcher {
    async fn accept(&self, _permit: &SignedExecutionPermit) -> Result<(), ()> {
        Ok(())
    }
}

#[async_trait]
impl ContainmentSink for HttpPepDispatcher {
    async fn propagate_containment(&self, event: &SignedContainmentEvent) -> Result<(), ()> {
        let started = std::time::Instant::now();
        self.client
            .post(format!("{}/internal/v1/containment-events", self.endpoint))
            .json(event)
            .send()
            .await
            .map_err(|_| ())?
            .error_for_status()
            .map(|_| {
                let millis = u64::try_from(started.elapsed().as_millis()).unwrap_or(u64::MAX);
                LAST_PROPAGATION_MILLIS.store(millis, Ordering::Relaxed);
            })
            .map_err(|_| ())
    }
}
