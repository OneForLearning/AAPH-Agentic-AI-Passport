mod admin_api;
mod bootstrap;
mod public_api;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    if rustls::crypto::CryptoProvider::get_default().is_none() {
        rustls::crypto::ring::default_provider()
            .install_default()
            .map_err(|_| std::io::Error::other("cannot install rustls ring provider"))?;
    }
    bootstrap::run_cli().await
}
