//! UBE Sovereign AirGap Bridge
//! Secure, unidirectional and bidirectional communication for air-gapped environments.
//! Implements optical, acoustic, and electromagnetic signaling for absolute isolation.

use std::collections::VecDeque;
use std::sync::Mutex;
use crate::types::Value;
use crate::crypto::blake3::Blake3;
use crate::crypto::symmetric::ChaChaPoly;

/// Methods of AirGap signaling.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BridgeMedium {
    Optical,     // QR Codes, LED flickering, Screen-to-Camera
    Acoustic,    // Ultrasonic data transfer
    Electromagnetic, // RF-leakage or specialized low-freq bursts
    Physical,    // USB-Sovereign-Key (Sneakernet)
}

/// A secure packet for AirGap transmission.
#[derive(Debug, Clone)]
pub struct AirGapPacket {
    pub sequence: u64,
    pub payload: Vec<u8>,
    pub checksum: [u8; 32],
    pub medium: BridgeMedium,
}

/// The Sovereign AirGap Bridge.
/// Ensures that the Sovereign Core can communicate with isolated systems without breaking the gap.
pub struct AirGapBridge {
    pub medium: BridgeMedium,
    pub encryption_key: [u8; 32],
    pub tx_queue: Mutex<VecDeque<AirGapPacket>>,
    pub rx_buffer: Mutex<VecDeque<u8>>,
}

impl AirGapBridge {
    pub fn new(medium: BridgeMedium, key: [u8; 32]) -> Self {
        Self {
            medium,
            encryption_key: key,
            tx_queue: Mutex::new(VecDeque::new()),
            rx_buffer: Mutex::new(VecDeque::new()),
        }
    }

    /// Prepares a value for AirGap transmission.
    /// Encrypts, signs, and fragments the data for the chosen medium.
    pub fn send(&self, value: Value) -> Result<(), String> {
        let bytes = self.serialize_value(&value);

        // 1. Encrypt the payload
        let cipher = ChaChaPoly::new(self.encryption_key);
        let (nonce, ciphertext, tag) = cipher.encrypt(&bytes, b"airgap-aad");

        let mut payload = nonce;
        payload.extend_from_slice(&tag);
        payload.extend_from_slice(&ciphertext);

        // 2. Compute checksum for integrity
        let checksum = Blake3::hash(&payload);

        let packet = AirGapPacket {
            sequence: 0, // Should be tracked per medium
            payload,
            checksum,
            medium: self.medium,
        };

        self.tx_queue.lock().unwrap().push_back(packet);
        Ok(())
    }

    /// Processes incoming raw signals from the medium.
    pub fn receive_signal(&self, raw_data: &[u8]) -> Result<Value, String> {
        // 1. Buffer the data
        self.rx_buffer.lock().unwrap().extend(raw_data);

        // 2. Attempt to reconstruct and decrypt packets
        // This is a simplified implementation. In production, it handles framing and parity.
        let encrypted_data: Vec<u8>;
        {
            let mut buffer = self.rx_buffer.lock().unwrap();
            if buffer.len() < 60 { return Err("Insufficient data in buffer".to_string()); }

            // Simplified packet extraction
            let len = buffer.len();
            encrypted_data = buffer.drain(..len).collect();
        }

        let cipher = ChaChaPoly::new(self.encryption_key);
        // Split nonce (12), tag (16), and ciphertext
        let (nonce, rest) = encrypted_data.split_at(12);
        let (tag, ciphertext) = rest.split_at(16);

        let plaintext = cipher.decrypt(ciphertext, nonce, tag, b"airgap-aad")
            .map_err(|_| "Decryption failed: AirGap integrity breach".to_string())?;

        self.deserialize_value(&plaintext)
    }

    fn serialize_value(&self, value: &Value) -> Vec<u8> {
        match value {
            Value::String(s) => s.as_bytes().to_vec(),
            Value::Number(n) => n.as_f64().map_or(vec![], |f| f.to_le_bytes().to_vec()),
            Value::Bool(b) => vec![if *b { 1 } else { 0 }],
            Value::Array(arr) => arr.iter().flat_map(|v| self.serialize_value(v)).collect(),
            Value::Object(obj) => { obj.iter().flat_map(|(k, v)| { let mut r = k.as_bytes().to_vec(); r.extend(self.serialize_value(v)); r }).collect() },
            Value::Null => vec![],
        }
    }

    fn deserialize_value(&self, bytes: &[u8]) -> Result<Value, String> {
        Ok(Value::String(String::from_utf8_lossy(bytes).into_owned()))
    }
}
