mod identity;
mod socket;
mod ledger;
mod orchestrator;
mod sdl;
mod mandate_engine;
mod persistence;
mod defense;

use crate::orchestrator::SovereignOrchestrator;
use log::{info, LevelFilter};
use env_logger::Builder;

#[tokio::main]
async fn main() {
    // Initialize logger
    Builder::new()
        .filter_level(LevelFilter::Info)
        .parse_default_env()
        .init();

    info!("Initializing Sovereign Native Core...");

    // In production, the golden hash is embedded in the binary or retrieved from a sealed hardware enclave.
    // For this implementation, we use a placeholder hash.
    let golden_hash = vec![0u8; 32];

    let orchestrator = SovereignOrchestrator::new(9000, golden_hash);

    if let Err(e) = orchestrator.run().await {
        eprintln!("Critical failure in Sovereign Orchestrator: {:?}", e);
        std::process::exit(1);
    }
}
