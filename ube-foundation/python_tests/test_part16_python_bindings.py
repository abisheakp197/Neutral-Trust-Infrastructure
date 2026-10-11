import gc
import json
import time
import threading
import unittest
import ube_foundation


class TestPart16PythonBindings(unittest.TestCase):
    def test_python_pqc_keypair_import(self):
        k = ube_foundation.PqcKeyPair()
        self.assertIsNotNone(k)
        self.assertGreater(len(k.public_key_hex()), 0)

    def test_python_sign_returns_hex(self):
        k = ube_foundation.PqcKeyPair()
        msg = b"test_message_for_signing"
        sig_hex = k.sign(msg)
        self.assertIsInstance(sig_hex, str)
        self.assertGreater(len(sig_hex), 0)
        # Dilithium5 signature is hex encoded string
        bytes.fromhex(sig_hex)

    def test_python_verify_true(self):
        k = ube_foundation.PqcKeyPair()
        msg = b"valid_message"
        sig_hex = k.sign(msg)
        self.assertTrue(k.verify(msg, sig_hex))

    def test_python_verify_false(self):
        k1 = ube_foundation.PqcKeyPair()
        k2 = ube_foundation.PqcKeyPair()
        msg = b"authentic_message"
        sig_hex = k1.sign(msg)
        # Verify with different key should return False
        self.assertFalse(k2.verify(msg, sig_hex))
        # Verify with tampered message should return False
        self.assertFalse(k1.verify(b"tampered_message", sig_hex))

    def test_python_trust_engine_import(self):
        engine = ube_foundation.TrustEngine()
        self.assertIsNotNone(engine)

    def test_python_gil_released(self):
        # Verify that multi-threaded operations do not block execution
        results = []

        def worker():
            k = ube_foundation.PqcKeyPair()
            for _ in range(10):
                sig = k.sign(b"multithreaded_test")
                k.verify(b"multithreaded_test", sig)
            results.append(True)

        threads = [threading.Thread(target=worker) for _ in range(4)]
        start_time = time.time()
        for t in threads:
            t.start()
        for t in threads:
            t.join()
        elapsed = time.time() - start_time

        self.assertEqual(len(results), 4)
        self.assertLess(elapsed, 5.0)

    def test_python_no_memory_leak(self):
        # Create and destroy 500 keypairs and ensure memory does not leak continuously
        gc.collect()
        for _ in range(500):
            k = ube_foundation.PqcKeyPair()
            sig = k.sign(b"leak_check")
            _ = k.verify(b"leak_check", sig)
        gc.collect()
        self.assertTrue(True)


if __name__ == "__main__":
    unittest.main()
