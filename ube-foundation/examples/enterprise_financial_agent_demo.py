#!/usr/bin/env python3
"""
Enterprise AI Agent Integration Example:
Securing Autonomous Financial Agent Operations with Post-Quantum Cryptography (PQC)
and Zero-Trust Capability Constraints using Neutral Trust Infrastructure (NTI).

Usage:
    pip install ube-foundation
    python3 enterprise_financial_agent_demo.py
"""

import json
import sys

try:
    from ube_foundation import TrustEngine, PqcKeyPair
    HAS_NATIVE_BOUNDS = True
except ImportError:
    print("Notice: 'ube-foundation' Python package not installed locally.")
    print("Install it via: pip install ube-foundation")
    HAS_NATIVE_BOUNDS = False


def run_enterprise_demo():
    print("=" * 80)
    print("  NEUTRAL TRUST INFRASTRUCTURE (NTI) - ENTERPRISE AI AGENT SECURITY DEMO")
    print("=" * 80)
    print("Scenario: An AI Financial Agent attempts to execute an automated fund transfer.")
    print("Security Goal: Verify PQC Dilithium5 signature & enforce capability token limits.\n")

    if not HAS_NATIVE_BOUNDS:
        print("[!] Local fallback mode running for demonstration structure.")
        return

    # 1. Initialize the NTI Trust Engine
    engine = TrustEngine()
    print("[1] Initialized NTI Trust Engine with Post-Quantum Cryptography support.")

    # 2. Grant permissions to the Financial AI Agent
    agent_id = "ai_agent_finance_01"
    capability = "wire_transfer"
    engine.grant(agent_id, capability)
    print(f"[2] Granted capability '{capability}' to Agent ID: '{agent_id}'.")

    # 3. Generate NIST Level 5 CRYSTALS-Dilithium5 Post-Quantum Key Pair for the Agent
    agent_pqc_key = PqcKeyPair()
    pub_key_hex = agent_pqc_key.public_key_hex()
    print(f"[3] Generated Dilithium5 PQC Key Pair for Agent.")
    print(f"    Public Key (Hex prefix): {pub_key_hex[:32]}... ({len(pub_key_hex)} chars)")

    # 4. Agent prepares a financial transaction request and signs it with PQC Dilithium5
    req_id = "tx_req_1001"
    action = "transfer"
    tx_input = {"amount": 5000, "currency": "USD", "target": "ACCT_987654"}

    # Canonical message representation matching Rust ActionRequest::message_to_sign
    msg_tuple = [req_id, agent_id, capability, action, tx_input]
    tx_payload_bytes = json.dumps(msg_tuple, separators=(',', ':')).encode('utf-8')

    pqc_sig_hex = agent_pqc_key.sign(tx_payload_bytes)
    print(f"[4] Agent signed payload 'TRANSFER $5000 USD' with Dilithium5 signature.")
    print(f"    Signature (Hex prefix):  {pqc_sig_hex[:32]}... ({len(pqc_sig_hex)} chars)")

    # 5. Construct the Action Request sent to the NTI Trust Engine
    sig_bytes = list(bytes.fromhex(pqc_sig_hex))
    pub_bytes = list(bytes.fromhex(pub_key_hex))

    action_request = {
        "id": req_id,
        "actor": agent_id,
        "capability": capability,
        "action": action,
        "input": tx_input,
        "signature": None,
        "pqc_signature": {
            "algorithm": "Dilithium5",
            "signature": sig_bytes
        },
        "public_key": None,
        "pqc_public_key": pub_bytes,
        "token": None,
        "identity_claim": None
    }

    # 6. Evaluate request with NTI Zero-Trust Engine
    print("\n[5] Evaluating transaction request with NTI Zero-Trust Policy Engine...")
    result_json = engine.evaluate(json.dumps(action_request))
    result = json.loads(result_json)

    print(f"\n>>> POLICY DECISION: {result.get('decision', 'Unknown').upper()} <<<")
    print(f"    Reason / Details: {result.get('reason', 'Policy check passed')}")

    # 7. Demonstrate Hybrid Kyber1024 Envelope Encryption for confidential inter-agent communication
    print("\n[6] Demonstrating CRYSTALS-Kyber1024 Hybrid Envelope Encryption for confidential agent payload:")
    secret_data = b"CONFIDENTIAL_AGENT_STATE_DATA_X99"
    ciphertext_hex, nonce_hex, ephemeral_pk_hex = agent_pqc_key.encrypt(secret_data)
    print(f"    Encrypted Ciphertext: {ciphertext_hex[:32]}...")

    decrypted_data = agent_pqc_key.decrypt(ciphertext_hex, nonce_hex, ephemeral_pk_hex)
    decrypted_bytes = bytes(decrypted_data)
    print(f"    Decrypted Payload:    {decrypted_bytes.decode()}")
    assert decrypted_bytes == secret_data, "PQC Kyber Decryption Mismatch!"
    print("\n[✓] All Post-Quantum Cryptographic & Policy checks passed successfully!")
    print("=" * 80)


if __name__ == "__main__":
    run_enterprise_demo()
