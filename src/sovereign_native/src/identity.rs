use pqcrypto_dilithium::dilithium3 as dilithium;
use pqcrypto_kyber::kyber1024 as kyber;
use pqcrypto_traits::kem::{Ciphertext as KemCiphertext, SharedSecret as KemSharedSecret, PublicKey as KemPublicKey, SecretKey as KemSecretKey};
use pqcrypto_traits::sign::{DetachedSignature as SignDetachedSignature, PublicKey as SignPublicKey, SecretKey as SignSecretKey};
use serde::{Deserialize, Serialize};
use std::fmt;

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct NodeIdentity {
    pub public_key_sign: Vec<u8>,
    pub public_key_enc: Vec<u8>,
    #[serde(skip)]
    secret_key_sign: Vec<u8>,
    #[serde(skip)]
    secret_key_enc: Vec<u8>,
}

impl NodeIdentity {
    /// Generates a new PQC identity using Dilithium-3 for signing and Kyber-1024 for encryption.
    pub fn generate() -> Self {
        let (pk_sign, sk_sign) = dilithium::keypair();
        let (pk_enc, sk_enc) = kyber::keypair();

        Self {
            public_key_sign: pk_sign.as_bytes().to_vec(),
            public_key_enc: pk_enc.as_bytes().to_vec(),
            secret_key_sign: sk_sign.as_bytes().to_vec(),
            secret_key_enc: sk_enc.as_bytes().to_vec(),
        }
    }

    /// Signs a message using Dilithium-3.
    pub fn sign(&self, message: &[u8]) -> Vec<u8> {
        let sk = dilithium::SecretKey::from_bytes(&self.secret_key_sign)
            .expect("Invalid secret key for signing");
        let sig = dilithium::detached_sign(message, &sk);
        sig.as_bytes().to_vec()
    }

    /// Verifies a signature using a public key.
    pub fn verify(message: &[u8], signature: &[u8], public_key: &[u8]) -> bool {
        let pk = dilithium::PublicKey::from_bytes(public_key).expect("Invalid public key");
        let sig = dilithium::DetachedSignature::from_bytes(signature).expect("Invalid signature bytes");
        dilithium::verify_detached_signature(&sig, message, &pk).is_ok()
    }

    /// Encapsulates a shared secret for a recipient's Kyber public key.
    pub fn encapsulate(recipient_pk_bytes: &[u8]) -> (Vec<u8>, Vec<u8>) {
        let pk = kyber::PublicKey::from_bytes(recipient_pk_bytes).expect("Invalid recipient public key");
        let (shared_secret, ciphertext) = kyber::encapsulate(&pk);
        (shared_secret.as_bytes().to_vec(), ciphertext.as_bytes().to_vec())
    }

    /// Decapsulates a shared secret using the node's secret key.
    pub fn decapsulate(&self, ciphertext_bytes: &[u8]) -> Vec<u8> {
        let sk = kyber::SecretKey::from_bytes(&self.secret_key_enc)
            .expect("Invalid secret key for decapsulation");
        let ciphertext = kyber::Ciphertext::from_bytes(ciphertext_bytes).expect("Invalid ciphertext");
        let shared_secret = kyber::decapsulate(&ciphertext, &sk);
        shared_secret.as_bytes().to_vec()
    }
}

impl fmt::Display for NodeIdentity {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "SovereignNodeIdentity({:?})", self.public_key_sign)
    }
}
