use crate::identity::NodeIdentity;
use crate::socket::{SovereignSocket, SocketError};
use crate::ledger::{SovereignLedger, Transaction};
use crate::defense::SovereignImmuneSystem;
use tokio::net::{TcpListener, TcpStream};
use std::sync::{Arc, Mutex};
use anyhow::{Result, Context};
use log::{info, error, warn};
use std::time::Duration;

pub struct SovereignOrchestrator {
    pub identity: Arc<NodeIdentity>,
    pub ledger: Arc<Mutex<SovereignLedger>>,
    pub sis: Arc<SovereignImmuneSystem>,
    pub port: u16,
}

impl SovereignOrchestrator {
    pub fn new(port: u16, golden_hash: Vec<u8>) -> Self {
        Self {
            identity: Arc::new(NodeIdentity::generate()),
            ledger: Arc::new(Mutex::new(SovereignLedger::new())),
            sis: Arc::new(SovereignImmuneSystem::new(golden_hash)),
            port,
        }
    }

    /// Starts the sovereign node and listens for incoming BFT frames.
    pub async fn run(&self) -> Result<()> {
        let listener = TcpListener::bind(format!("0.0.0.0:{}", self.port))
            .await
            .context("Failed to bind TCP listener")?;

        info!("Sovereign Node started on port {}. Identity: {}", self.port, self.identity);

        // Start the SIS Integrity Monitor in the background
        let sis_monitor = Arc::clone(&self.sis);
        tokio::spawn(async move {
            loop {
                tokio::time::sleep(Duration::from_secs(60)).await;
                match sis_monitor.verify_integrity() {
                    Ok(true) => {}, // All good
                    Ok(false) => {
                        if let Err(e) = sis_monitor.trigger_repair().await {
                            error!("SIS: Repair loop failed: {:?}", e);
                        }
                    }
                    Err(e) => error!("SIS: Integrity check encountered error: {:?}", e),
                }
            }
        });

        loop {
            let (stream, addr) = listener.accept().await?;
            info!("New connection from {}", addr);

            let identity = Arc::clone(&self.identity);
            let ledger = Arc::clone(&self.ledger);

            tokio::spawn(async move {
                if let Err(e) = Self::handle_connection(stream, identity, ledger).await {
                    error!("Connection error from {}: {:?}", addr, e);
                }
            });
        }
    }

    async fn handle_connection(
        stream: TcpStream,
        identity: Arc<NodeIdentity>,
        ledger: Arc<Mutex<SovereignLedger>>,
    ) -> Result<()> {
        let mut socket = SovereignSocket::new(stream);

        loop {
            // 1. Receive frame
            let frame_data = socket.receive_frame().await
                .map_err(|e| anyhow::anyhow!("Socket error: {:?}", e))?;

            // 2. Deserialize as a Transaction
            let tx: Transaction = serde_json::from_slice(&frame_data)
                .context("Failed to deserialize Transaction")?;

            // 3. Verify PQC Signature
            if !NodeIdentity::verify(&serde_json::to_vec(&tx.key).unwrap(), &tx.signature, &tx.sender) {
                warn!("Invalid PQC signature received. Dropping frame.");
                continue;
            }

            // 4. Apply to Ledger (Atomic State Update)
            let new_root = {
                let mut lock = ledger.lock().unwrap();
                lock.apply_transaction(tx, &identity.public_key_sign)?
            };

            info!("State updated. New Merkle Root: {:?}", new_root);

            // 5. Send Attestation back to peer
            let response = serde_json::to_vec(&new_root)?;
            socket.send_frame(&response).await
                .map_err(|e| anyhow::anyhow!("Socket error: {:?}", e))?;
        }
    }
}
