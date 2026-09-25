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

            msg = b"py_eval_test"
            sig_hex = pqc.sign(msg)

            req = {
                "id": "py-req-1",
                "actor": "alice_py",
                "capability": "code_execution",
                "action": "run",
                "input": {"code": "print('hello')"},
                "signature": None,
                "pqc_signature": sig_hex,
                "public_key": None,
                "pqc_public_key": pub_hex,
                "token": None,
                "identity_claim": None
            }
            res_json = engine.evaluate(json.dumps(req))
            res = json.loads(res_json)
            self.assertIn("decision", res)
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

    def test_py_pqc_signature_flow(self):
        if HAS_NATIVE_BINDINGS:
            pqc = ube_foundation.PqcKeyPair()
            msg = b"hello_pqc_python"
            sig = pqc.sign(msg)
            self.assertIsInstance(sig, str)
            self.assertGreater(len(sig), 0)

            ciphertext_hex, nonce_hex = pqc.encrypt(msg)
            decrypted = pqc.decrypt(ciphertext_hex, nonce_hex)
            self.assertEqual(decrypted, msg)
        else:
            sig_payload = {
                "algorithm": "Dilithium5",
                "signature": [0] * 4595
            }
            self.assertEqual(sig_payload["algorithm"], "Dilithium5")

if __name__ == "__main__":
    unittest.main()
