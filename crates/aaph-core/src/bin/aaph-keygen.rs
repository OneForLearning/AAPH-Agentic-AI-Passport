//! Local development key generator for the non-production demonstration.

use std::path::PathBuf;

use aaph_core::crypto::generate_development_keypair;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let mut arguments = std::env::args_os().skip(1);
    let Some(directory) = arguments.next() else {
        return Err("usage: aaph-keygen <directory> [--force]".into());
    };
    if directory == "--help" || directory == "-h" {
        println!("Usage: aaph-keygen <directory> [--force]\n\nGenerates NON_PRODUCTION_DEMO Ed25519 key files without implicit overwrite.");
        return Ok(());
    }
    let force = match arguments.next() {
        None => false,
        Some(value) if value == "--force" => true,
        Some(_) => return Err("only the explicit --force overwrite option is accepted".into()),
    };
    if arguments.next().is_some() {
        return Err("too many arguments".into());
    }
    let directory = PathBuf::from(directory);
    generate_development_keypair(&directory, force)?;
    println!("NON_PRODUCTION_DEMO: generated private signing.key (0600 on Unix) and publishable public.key (0644 on Unix) in {}", directory.display());
    Ok(())
}
