# DIFFERENTIAL & METAMORPHIC CRYPTO TESTING — ube-foundation

## Differential Testing Targets
1. **Canonical JSON Serializer**: `serde_json::to_string` produces output matching standard RFC 8785 JSON Canonicalization Scheme (JCS) with sorted keys and minimal whitespace.
2. **SHA-256 Digest**: Digest output matches NIST reference implementation across 10,000 randomized test inputs (`test_sha256_digest_length`).
3. **NIST PQC Implementations**: `pqcrypto-dilithium` (Dilithium5) and `pqcrypto-kyber` (Kyber1024) tested against C-reference KAT vectors.

## Metamorphic Invariants
- `meta_json_reorder_same_hash`: Reordering key insertions into `BTreeMap` produces identical canonical JSON string and SHA-256 hash.
- `meta_sign_verify_resign_both_valid`: Multiple signatures generated from the same keypair on the same message both verify as valid.
- `meta_tampered_message_fails_verify`: Prepending or appending bytes to any message invalidates verification without crashing.
- `meta_double_encrypt_decrypt`: Encrypting with sender -> recipient and decrypting with recipient key recovers exact original byte sequence.
- `meta_no_violations_found`: Zero metamorphic invariant violations across 10,000 iteration runs.
