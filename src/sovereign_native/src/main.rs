mod identity;
mod socket;
mod ledger;
mod ssm;
mod sdl;
mod persistence;
mod defense;
mod pipeline;
mod automation;
mod connector;
mod types;
mod crypto;
mod intelligence;
mod encryption;
mod stream;
mod mesh;
mod radio;
mod shield;
mod autonomous_engineering;

#[cfg(test)]
mod tests;

use crate::ssm::SovereignStateMachine;
use log::{info, LevelFilter};
use env_logger::Builder;
use std::time::Duration;

#[tokio::main]
async fn main() {
    // Initialize logger
    Builder::new()
        .filter_level(LevelFilter::Info)
        .parse_default_env()
        .init();

    info!("Initializing Sovereign Native Core (SSM Mode)...");

    let tenant_id = "sovereign-root-01";
    let ssm = SovereignStateMachine::new(tenant_id);

    info!("Sovereign State Machine active. Eliminating attention tax...");

    // The Autonomous Heartbeat Loop
    loop {
        ssm.tick().await;
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
}


use crate::ssm::SovereignStateMachine;
use log::{info, LevelFilter};
use env_logger::Builder;
use std::time::Duration;

#[tokio::main]
async fn main() {
    // Initialize logger
    Builder::new()
        .filter_level(LevelFilter::Info)
        .parse_default_env()
        .init();

    info!("Initializing Sovereign Native Core (SSM Mode)...");

    let tenant_id = "sovereign-root-01";
    let ssm = SovereignStateMachine::new(tenant_id);

    info!("Sovereign State Machine active. Eliminating attention tax...");

    // The Autonomous Heartbeat Loop
    loop {
        ssm.tick().await;
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
}
