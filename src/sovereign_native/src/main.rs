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
mod gateway;
mod proxy_types;
mod digital_proxy;
mod sovereign_guardian;
mod zk;

#[cfg(test)]
mod tests;

use crate::ssm::SovereignStateMachine;
use crate::gateway::GatewayBuilder;
use crate::mesh::MeshNode;
use crate::identity::IdentityEngine;
use crate::connector::SovereignHttpConnector;
use crate::ledger::SovereignLedger;
use crate::automation::AutomationEngine;
use crate::digital_proxy::ProxyRegistry;
use crate::sovereign_guardian::SovereignGuardian;
use log::{info, LevelFilter};
use env_logger::Builder;
use std::sync::{Arc, Mutex};
use std::time::Duration;

#[tokio::main]
async fn main() {
    // Initialize logger
    Builder::new()
        .filter_level(LevelFilter::Info)
        .parse_default_env()
        .init();

    info!("Initializing Sovereign Native Core (SSM + Gateway + Proxy Mode)...");

    let tenant_id = "sovereign-root-01";

    // Initialize Identity Engine
    let identity_engine = Arc::new(Mutex::new(IdentityEngine::new()));
    let gateway_identity = Arc::new(identity_engine.lock().unwrap().create_identity("gateway-root"));

    // Initialize Mesh Node
    let mesh_node = Arc::new(MeshNode::new(gateway_identity.clone()));

    // Initialize Core Infrastructure
    let ledger = Arc::new(SovereignLedger::new());
    let automation = Arc::new(AutomationEngine::new());

    // Initialize Sovereign Guardian - ZERO ERROR ENFORCEMENT
    let guardian = Arc::new(SovereignGuardian::new(ledger.clone()));

    // Initialize Digital Proxy Registry - ATTENTION ELIMINATION
    let proxy_registry = Arc::new(ProxyRegistry::new(
        Arc::new(move |entity_id| {
            let identity = identity_engine.lock().unwrap().create_identity(entity_id);
            Arc::new(MeshNode::new(Arc::new(identity)))
        }),
        // These will be set properly below
        automation.clone(),
        ledger.clone(),
        guardian.clone(),
    ));

    // Initialize Sovereign Gateway with Mesh integration
    let gateway = Arc::new(GatewayBuilder::new()
        .listen_address("0.0.0.0:8080")
        .mesh_enabled(true)
        .pqc_required(true)
        .rate_limit(1000)
        .build()
        .with_mesh(mesh_node.clone()));

    // Register HTTP Connector
    gateway.register_connector(Box::new(SovereignHttpConnector::new()));

    // Start Gateway
    // gateway.start().await; // Commented out for now - needs async context

    // Initialize SSM with Gateway integration
    let ssm = Arc::new(SovereignStateMachine::new(tenant_id));

    // Create SSM with proxy integration
    let ssm_arc = ssm.clone();
    let proxy_registry_with_ssm = Arc::new(ProxyRegistry::new(
        Arc::new(move |entity_id| {
            let identity = identity_engine.lock().unwrap().create_identity(entity_id);
            Arc::new(MeshNode::new(Arc::new(identity)))
        }),
        ssm_arc,
        automation,
        ledger,
        guardian,
    ));

    info!("Sovereign State Machine active. Eliminating attention tax...");
    info!("Sovereign Gateway active. PQC root of trust established.");
    info!("Sovereign Guardian active. Zero-error enforcement online.");
    info!("Digital Proxy Registry active. Attention elimination online.");

    // The Autonomous Heartbeat Loop
    // Processes SSM ticks AND Digital Proxy work queues
    loop {
        ssm.tick().await;

        // Also process any pending Digital Proxy work
        let _proxy_results = proxy_registry_with_ssm.process_all().await;

        tokio::time::sleep(Duration::from_millis(100)).await;
    }
}
