"""Token issuance through the Python binding.

Before 0.3.0 the binding could not issue a signed token, so a Python
deployment could not attach a caveat for the engine to enforce. These tests
cover that path end to end: build the token, sign it with the issuer key, and
let the engine decide.

Written as unittest so both `python -m unittest` and `pytest` collect it.
"""

import json
import unittest

import ube_foundation

ISSUER = "issuer"
ACTOR = "recipient"
CAPABILITY = "tool:shell"
NOW = "2026-11-26T10:00:00Z"


class TokenBuilderTest(unittest.TestCase):
    def setUp(self):
        self.key = ube_foundation.Ed25519KeyPair()
        self.engine = ube_foundation.TrustEngine()
        self.engine.register_issuer_key(ISSUER, self.key.public_key_bytes())
        self.engine.grant(ISSUER, CAPABILITY)

    def issue(self, threshold_bps):
        builder = ube_foundation.TokenBuilder("tok-1", ISSUER, CAPABILITY)
        builder.risk_below(threshold_bps)
        return builder.sign(self.key.private_key_bytes())

    def evaluate(self, token_json, risk_score):
        request = {
            "id": "r-1",
            "actor": ACTOR,
            "capability": CAPABILITY,
            "action": "bash",
            "input": {"command": "ls", "risk_score": risk_score},
            "token": json.loads(token_json),
        }
        return json.loads(self.engine.evaluate_at(json.dumps(request), NOW, ""))

    def test_token_carries_the_caveat_in_the_documented_shape(self):
        token = json.loads(self.issue(6500))
        self.assertEqual(token["caveats"], [{"location": None, "condition": {"RiskBelow": 6500}}])
        self.assertEqual(len(token["signature"]), 64)

    def test_low_risk_is_allowed(self):
        out = self.evaluate(self.issue(6500), 0.12)
        self.assertEqual(out["decision"], "Allow", out)

    def test_score_at_the_threshold_is_denied(self):
        out = self.evaluate(self.issue(6500), 0.65)
        self.assertEqual(out["decision"], "Deny", out)
        self.assertIn("6500 bps", out["reason"])

    def test_high_risk_is_denied(self):
        out = self.evaluate(self.issue(6500), 0.91)
        self.assertEqual(out["decision"], "Deny", out)
        self.assertIn("9100 bps", out["reason"])

    def test_score_off_the_scale_is_denied(self):
        # 65 means 65 percent to a human; reading it as a 0..1 score would allow.
        out = self.evaluate(self.issue(6500), 65.0)
        self.assertEqual(out["decision"], "Deny", out)
        self.assertIn("0.0..=1.0", out["reason"])

    def test_threshold_out_of_range_is_rejected_when_building(self):
        builder = ube_foundation.TokenBuilder("tok-1", ISSUER, CAPABILITY)
        with self.assertRaises(ValueError):
            builder.risk_below(20_000)

    def test_bad_timestamp_is_rejected_when_building(self):
        builder = ube_foundation.TokenBuilder("tok-1", ISSUER, CAPABILITY)
        with self.assertRaises(ValueError):
            builder.expires("next tuesday")

    def test_token_from_an_unpinned_issuer_is_denied(self):
        # The signature is valid, but the engine does not trust this key.
        engine = ube_foundation.TrustEngine()
        engine.grant(ISSUER, CAPABILITY)
        request = {
            "id": "r-1",
            "actor": ACTOR,
            "capability": CAPABILITY,
            "action": "bash",
            "input": {"risk_score": 0.12},
            "token": json.loads(self.issue(6500)),
        }
        out = json.loads(engine.evaluate_at(json.dumps(request), NOW, ""))
        self.assertEqual(out["decision"], "Deny", out)
        self.assertIn("untrusted token issuer", out["reason"])

    def test_tampering_with_the_caveat_invalidates_the_token(self):
        # Raising the threshold after signing is the obvious attack.
        token = json.loads(self.issue(6500))
        token["caveats"][0]["condition"]["RiskBelow"] = 10_000
        out = self.evaluate(json.dumps(token), 0.91)
        self.assertEqual(out["decision"], "Deny", out)
        self.assertIn("signature", out["reason"])


if __name__ == "__main__":
    unittest.main()
