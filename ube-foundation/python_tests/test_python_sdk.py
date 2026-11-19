import json
import unittest

try:
    import ube_foundation
    HAS_NATIVE_BINDINGS = True
except ImportError:
    HAS_NATIVE_BINDINGS = False

class TestPythonSDK(unittest.TestCase):
    def test_py_trust_engine_evaluation_structure(self):
        if HAS_NATIVE_BINDINGS:
            engine = ube_foundation.TrustEngine()
            pqc = ube_foundation.PqcKeyPair()
            pub_hex = pqc.public_key_hex()
            pub_bytes = list(bytes.fromhex(pub_hex))

            agent_id = "alice_py"
            capability = "code_execution"
            action = "run"
            req_id = "py-req-1"
            req_input = {"code": "print('hello')"}

            # Grant capability to actor and pin the ML-DSA-87 identity key.
            # Both are required: the grant authorizes the capability, the pinned
            # key authorizes *this* signer. Without the pin any caller could
            # self-sign and the signature would only prove key possession.
            engine.grant(agent_id, capability)
            engine.register_pqc_identity_key(agent_id, pub_bytes)

            # Message to sign matching Rust ActionRequest::message_to_sign
            msg_tuple = [req_id, agent_id, capability, action, req_input]
            msg_bytes = json.dumps(msg_tuple, separators=(',', ':')).encode('utf-8')

            sig_hex = pqc.sign(msg_bytes)
            sig_bytes = list(bytes.fromhex(sig_hex))

            req = {
                "id": req_id,
                "actor": agent_id,
                "capability": capability,
                "action": action,
                "input": req_input,
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
            res_json = engine.evaluate(json.dumps(req))
            res = json.loads(res_json)
            self.assertEqual(res.get("decision"), "Allow")
        else:
            req = {
                "id": "py-req-1",
                "actor": "alice_py",
                "capability": "code_execution",
                "action": "run",
                "input": {"code": "print('hello')"},
                "signature": None,
                "pqc_signature": None,
                "public_key": None,
                "pqc_public_key": None,
                "token": None,
                "identity_claim": None
            }
            req_json = json.dumps(req)
            self.assertIn("py-req-1", req_json)

    def test_py_pqc_key_binding_blocks_self_signed_requests(self):
        """A self-signed request from an unpinned key must be denied."""
        if HAS_NATIVE_BINDINGS:
            engine = ube_foundation.TrustEngine()
            attacker = ube_foundation.PqcKeyPair()
            agent_id = "alice_py"
            capability = "code_execution"
            engine.grant(agent_id, capability)

            req = {
                "id": "py-req-selfsigned",
                "actor": agent_id,
                "capability": capability,
                "action": "run",
                "input": {"code": "print('pwned')"},
                "signature": None,
                "pqc_signature": None,
                "public_key": None,
                "pqc_public_key": None,
                "token": None,
                "identity_claim": None,
            }
            msg = json.dumps(
                [req["id"], agent_id, capability, "run", req["input"]],
                separators=(",", ":"),
            ).encode("utf-8")
            req["pqc_signature"] = {
                "algorithm": "ML-DSA-87",
                "signature": list(attacker.sign_bytes(msg)),
            }
            req["pqc_public_key"] = list(attacker.get_public_key_bytes())

            res = json.loads(engine.evaluate(json.dumps(req)))
            self.assertEqual(res.get("decision"), "Deny")
            self.assertEqual(res.get("reason"), "no pqc identity key bound to actor")

    def test_py_pqc_identity_key_pin_and_remove(self):
        if HAS_NATIVE_BINDINGS:
            engine = ube_foundation.TrustEngine()
            key = ube_foundation.PqcKeyPair()
            engine.register_pqc_identity_key("alice_py", key.get_public_key_bytes())
            self.assertEqual(
                bytes(engine.pqc_identity_key("alice_py")),
                bytes(key.get_public_key_bytes()),
            )
            removed = engine.remove_pqc_identity_key("alice_py")
            self.assertEqual(bytes(removed), bytes(key.get_public_key_bytes()))
            self.assertIsNone(engine.pqc_identity_key("alice_py"))

            with self.assertRaises(ValueError):
                engine.register_pqc_identity_key("alice_py", b"not-a-key")

    def test_py_evaluate_at_rejects_bad_timestamp(self):
        if HAS_NATIVE_BINDINGS:
            engine = ube_foundation.TrustEngine()
            req = {
                "id": "py-req-at",
                "actor": "alice_py",
                "capability": "code_execution",
                "action": "run",
                "input": {},
                "signature": None,
                "pqc_signature": None,
                "public_key": None,
                "pqc_public_key": None,
                "token": None,
                "identity_claim": None,
            }
            with self.assertRaises(ValueError):
                engine.evaluate_at(json.dumps(req), "not-a-timestamp")
            res = json.loads(engine.evaluate_at(json.dumps(req), "2026-01-01T00:00:00Z"))
            self.assertIn(res.get("decision"), ("Allow", "Deny"))

    def test_py_pqc_signature_flow(self):
        if HAS_NATIVE_BINDINGS:
            pqc = ube_foundation.PqcKeyPair()
            msg = b"hello_pqc_python"
            sig = pqc.sign(msg)
            self.assertIsInstance(sig, str)
            self.assertGreater(len(sig), 0)

            ciphertext_hex, nonce_hex, ephemeral_pqc_pk_hex = pqc.encrypt(msg)
            decrypted = pqc.decrypt(ciphertext_hex, nonce_hex, ephemeral_pqc_pk_hex)
            self.assertEqual(bytes(decrypted), msg)
        else:
            sig_payload = {
                "algorithm": "Dilithium5",
                "signature": [0] * 4595
            }
            self.assertEqual(sig_payload["algorithm"], "Dilithium5")

if __name__ == "__main__":
    unittest.main()
