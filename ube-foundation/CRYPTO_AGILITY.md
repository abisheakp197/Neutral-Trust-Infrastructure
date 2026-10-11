# CRYPTO AGILITY ARCHITECTURE — ube-foundation

## PQC Algorithm Agility Guarantees

1. **Algorithm Identifiers in Artifacts**: Every `PqcSignature` and `PqcEncryptedContainer` carries explicit `algorithm` metadata fields (e.g., `Dilithium5`, `ML-DSA-87`, `Dilithium5-Kyber1024-ChaCha20Poly1305`).
2. **Abstract Primitives Interface**: Cryptographic operations are isolated within `PqcKeyPair` and `PqcPublicKey` structs rather than hardcoding raw bytes in business logic.
3. **Algorithm Verification & Fail-Closed Downgrade Rejection**:
   `TrustEngine::evaluate` checks signature algorithm compatibility:
   ```rust
   if pqc_sig.algorithm != "Dilithium5" && pqc_sig.algorithm != "ML-DSA-87" {
       return PolicyDecision { decision: Decision::Deny, reason: "unsupported pqc algorithm".into() };
   }
   ```
4. **Seamless Rotation Path**: Upgrading algorithms (e.g. from Dilithium5 to ML-DSA-87) requires registering the new algorithm handler without breaking existing serialization formats.
