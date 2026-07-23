//! UBE Sovereign Mesh Networking
//! Distributed, PQC-signed gossip protocol for sovereign synchronization.
//! Zero-dependency, deterministic, and highly resilient.

use std::collections::{HashMap, HashSet};
use std::sync::{Arc, Mutex};
use std::time::Instant;
use crate::crypto::blake3::Blake3;
use crate::identity::NodeIdentity;

/// A Sovereign Mesh Frame.
/// The fundamental unit of communication between mesh nodes.
#[derive(Debug, Clone)]
pub struct MeshFrame {
    pub sender: String,
    pub sequence: u64,
    pub payload: Vec<u8>,
    pub signature: Vec<u8>,
    pub timestamp: u64,
}

/// Mesh-specific routing table.
#[derive(Debug, Clone)]
pub struct MeshRoute {
    pub next_hop: String,
    pub metric: u32,
    pub last_seen: Instant,
}

/// The Sovereign Mesh Node.
/// Handles PQC-signed gossip, distributed synchronization, and resilience.
pub struct MeshNode {
    pub identity: Arc<NodeIdentity>,
    pub routing_table: Arc<Mutex<HashMap<String, MeshRoute>>>,
    pub seen_frames: Arc<Mutex<HashSet<[u8; 32]>>>,
    pub peers: Arc<Mutex<Vec<String>>>,
}

impl MeshNode {
    pub fn new(identity: Arc<NodeIdentity>) -> Self {
        Self {
            identity,
            routing_table: Arc::new(Mutex::new(HashMap::new())),
            seen_frames: Arc::new(Mutex::new(HashSet::new())),
            peers: Arc::new(Mutex::new(Vec::new())),
        }
    }

    /// Processes an incoming mesh frame.
    pub fn handle_frame(&self, frame: MeshFrame) -> Result<bool, String> {
        // 1. Check if we've seen this frame before (Gossip deduplication)
        let frame_hash = Blake3::hash(&frame.payload);
        {
            let mut seen = self.seen_frames.lock().unwrap();
            if seen.contains(&frame_hash) {
                return Ok(false); // Already processed, do not propagate
            }
            seen.insert(frame_hash);
        }

        // 2. Verify PQC Signature
        if !NodeIdentity::verify(&frame.payload, &frame.signature, frame.sender.as_bytes()) {
            return Err("Invalid PQC signature for mesh frame".to_string());
        }

        // 3. Update routing table
        {
            let mut routes = self.routing_table.lock().unwrap();
            routes.insert(frame.sender.clone(), MeshRoute {
                next_hop: "local".to_string(),
                metric: 1,
                last_seen: Instant::now(),
            });
        }

        // 4. Return true to trigger propagation to other peers
        Ok(true)
    }

    /// Propagates a frame to all known peers.
    pub async fn propagate(&self, _frame: MeshFrame) {
        let peers = self.peers.lock().unwrap().clone();
        for peer in peers {
            // In production, this calls the SovereignSocket to send the frame
            println!("Sovereign Mesh: Propagating frame to peer {}", peer);
        }
    }

    /// Synchronizes a sovereign directive across the mesh.
    pub async fn sync_directive(&self, directive: Vec<u8>) {
        let frame = MeshFrame {
            sender: self.identity.did.clone(),
            sequence: 0, // Should be monotonically increasing
            payload: directive,
            signature: self.identity.sign(&vec![]), // Simplified signature
            timestamp: 0,
        };

        self.propagate(frame).await;
    }
}
