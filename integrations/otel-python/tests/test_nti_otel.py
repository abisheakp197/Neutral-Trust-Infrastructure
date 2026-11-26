import json
import os
import subprocess
import sys
import tempfile
import unittest

from opentelemetry.sdk.resources import Resource
from opentelemetry.sdk.trace import TracerProvider

REPO_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
sys.path.insert(0, os.path.join(REPO_ROOT, "src"))

import nti_otel  # noqa: E402
from nti_otel import (  # noqa: E402
    NTIRecordProcessor,
    canonical_json,
    generate_signer,
    read_entries,
    verify,
)


def build(path, **kwargs):
    provider = TracerProvider(resource=Resource.create({"service.name": "checkout-agent"}))
    processor = NTIRecordProcessor(path=path, **kwargs)
    provider.add_span_processor(processor)
    return provider, processor


def record_two_decisions(provider):
    tracer = provider.get_tracer("test")
    with tracer.start_as_current_span("tool.invoke") as span:
        span.set_attribute("nti.actor", "agent-1")
        span.set_attribute("nti.capability", "payments:charge")
        span.set_attribute("nti.decision", "Allow")
        span.set_attribute("gen_ai.tool.name", "charge_card")
    with tracer.start_as_current_span("tool.invoke") as span:
        span.set_attribute("nti.actor", "agent-1")
        span.set_attribute("nti.capability", "payments:refund")
        span.set_attribute("nti.decision", "Deny")
        span.set_attribute("nti.reason", "capability_not_granted")


class TestCanonicalJson(unittest.TestCase):
    def test_key_order_is_irrelevant(self):
        self.assertEqual(
            canonical_json({"b": 1, "a": 2}), canonical_json({"a": 2, "b": 1})
        )

    def test_no_whitespace(self):
        self.assertEqual(canonical_json({"a": [1, 2]}), b'{"a":[1,2]}')

    def test_non_ascii_is_preserved_and_normalized(self):
        self.assertEqual(canonical_json({"n": "e\u0301"}), canonical_json({"n": "\u00e9"}))

    def test_nan_is_rejected_not_stringified(self):
        with self.assertRaises(ValueError):
            canonical_json({"x": float("nan")})


class TestChain(unittest.TestCase):
    def test_records_only_decision_spans(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = os.path.join(tmp, "r.jsonl")
            provider, processor = build(path)
            tracer = provider.get_tracer("test")
            with tracer.start_as_current_span("noise"):
                pass
            record_two_decisions(provider)
            self.assertEqual(processor.recorded, 2)
            self.assertEqual(processor.skipped, 1)

    def test_chain_verifies_and_links(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = os.path.join(tmp, "r.jsonl")
            provider, _ = build(path)
            record_two_decisions(provider)
            entries = list(read_entries(path))
            self.assertEqual(len(entries), 2)
            self.assertIsNone(entries[0]["prev_hash"])
            self.assertEqual(entries[0]["record_hash"], entries[1]["prev_hash"])
            self.assertEqual(verify(entries), [])

    def test_records_are_canonical_single_line_json(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = os.path.join(tmp, "r.jsonl")
            provider, _ = build(path)
            record_two_decisions(provider)
            with open(path, encoding="utf-8") as f:
                lines = [line for line in f.read().splitlines() if line]
            self.assertEqual(len(lines), 2)
            for line in lines:
                self.assertEqual(canonical_json(json.loads(line)), line.encode())

    def test_altering_a_decision_is_detected(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = os.path.join(tmp, "r.jsonl")
            provider, _ = build(path)
            record_two_decisions(provider)
            entries = list(read_entries(path))
            entries[0]["attributes"]["nti.decision"] = "Deny"
            problems = verify(entries)
            self.assertTrue(problems)
            self.assertIn("record_hash mismatch", problems[0])

    def test_removing_an_entry_breaks_the_chain(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = os.path.join(tmp, "r.jsonl")
            provider, _ = build(path)
            record_two_decisions(provider)
            entries = list(read_entries(path))
            problems = verify([entries[0]])
            self.assertEqual(problems, [])

            provider2, _ = build(path)
            record_two_decisions(provider2)
            four = list(read_entries(path))
            self.assertEqual(len(four), 4)
            problems = verify([four[0], four[2], four[3]])
            self.assertTrue(any("does not follow" in p for p in problems))

    def test_reopening_appends_rather_than_restarts(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = os.path.join(tmp, "r.jsonl")
            provider, _ = build(path)
            record_two_decisions(provider)
            provider2, _ = build(path)
            record_two_decisions(provider2)
            entries = list(read_entries(path))
            self.assertEqual(len(entries), 4)
            self.assertEqual(verify(entries), [])

    def test_empty_chain_is_reported(self):
        self.assertEqual(verify([]), ["chain is empty"])


class TestSigning(unittest.TestCase):
    def test_signature_over_hash_and_not_inside_it(self):
        signer, public_key_hex = generate_signer()
        if signer is None:
            self.skipTest("ube-foundation not installed")
        self.assertTrue(public_key_hex)
        with tempfile.TemporaryDirectory() as tmp:
            path = os.path.join(tmp, "r.jsonl")
            provider, _ = build(path, signer=signer)
            record_two_decisions(provider)
            entries = list(read_entries(path))
            self.assertTrue(entries[0]["signature"].startswith("ml-dsa-87:"))
            self.assertEqual(verify(entries), [])
            entries[0]["attributes"]["nti.decision"] = "Deny"
            self.assertTrue(verify(entries))


class TestCli(unittest.TestCase):
    def test_cli_accepts_a_valid_log_and_rejects_an_edited_one(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = os.path.join(tmp, "r.jsonl")
            provider, _ = build(path)
            record_two_decisions(provider)

            ok = subprocess.run(
                [sys.executable, "-m", "nti_otel.cli", path],
                capture_output=True,
                text=True,
                env={**os.environ, "PYTHONPATH": os.path.join(REPO_ROOT, "src")},
            )
            self.assertEqual(ok.returncode, 0, ok.stderr)
            self.assertIn("chain intact", ok.stdout)

            entries = list(read_entries(path))
            entries[1]["attributes"]["nti.capability"] = "payments:charge"
            with open(path, "w", encoding="utf-8") as f:
                for entry in entries:
                    f.write(canonical_json(entry).decode() + "\n")

            bad = subprocess.run(
                [sys.executable, "-m", "nti_otel.cli", path, "--json"],
                capture_output=True,
                text=True,
                env={**os.environ, "PYTHONPATH": os.path.join(REPO_ROOT, "src")},
            )
            self.assertEqual(bad.returncode, 1)
            self.assertFalse(json.loads(bad.stdout)["ok"])


if __name__ == "__main__":
    unittest.main()
