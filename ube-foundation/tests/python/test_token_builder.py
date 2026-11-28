"""End-to-end tests for issuing capability tokens from Python.

Run after `maturin develop` in a virtualenv:

    pip install pytest
    maturin develop
    pytest tests/python -q

These exercise the real engine through the compiled extension, not a stub.
"""

import json

import pytest

import ube_foundation

ISSUER = "issuer"
ACTOR = "recipient"
CAPABILITY = "tool:shell"
NOW = "2026-11-26T10:00:00Z"


def make_engine(pin_issuer=True):
    engine = ube_foundation.TrustEngine()
    key = ube_foundation.Ed25519KeyPair()
    if pin_issuer:
        engine.register_issuer_key(ISSUER, key.public_key_bytes())
    engine.grant(ISSUER, CAPABILITY)
    return engine, key


def evaluate(engine, token_json, risk_score):
    request = {
        "id": "r-1",
        "actor": ACTOR,
        "capability": CAPABILITY,
        "action": "bash",
        "input": {"command": "ls", "risk_score": risk_score},
        "token": json.loads(token_json),
    }
    return json.loads(engine.evaluate_at(json.dumps(request), NOW, ""))


def risk_token(key, threshold_bps):
    builder = ube_foundation.TokenBuilder("tok-1", ISSUER, CAPABILITY)
    builder.risk_below(threshold_bps)
    return builder.sign(key.private_key_bytes())


def test_token_carries_the_caveat_in_the_documented_shape():
    engine, key = make_engine()
    token = json.loads(risk_token(key, 6500))
    assert token["caveats"] == [{"location": None, "condition": {"RiskBelow": 6500}}]
    assert len(token["signature"]) == 64


def test_low_risk_is_allowed():
    engine, key = make_engine()
    out = evaluate(engine, risk_token(key, 6500), 0.12)
    assert out["decision"] == "Allow", out


def test_score_at_the_threshold_is_denied():
    engine, key = make_engine()
    out = evaluate(engine, risk_token(key, 6500), 0.65)
    assert out["decision"] == "Deny", out
    assert "6500 bps" in out["reason"], out


def test_high_risk_is_denied():
    engine, key = make_engine()
    out = evaluate(engine, risk_token(key, 6500), 0.91)
    assert out["decision"] == "Deny", out
    assert "9100 bps" in out["reason"], out


def test_score_off_the_scale_is_denied():
    # 65 means 65 percent to a human; it must not be read as a 0..1 score.
    engine, key = make_engine()
    out = evaluate(engine, risk_token(key, 6500), 65.0)
    assert out["decision"] == "Deny", out
    assert "0.0..=1.0" in out["reason"], out


def test_threshold_out_of_range_is_rejected_when_building():
    builder = ube_foundation.TokenBuilder("tok-1", ISSUER, CAPABILITY)
    with pytest.raises(ValueError):
        builder.risk_below(20_000)


def test_bad_timestamp_is_rejected_when_building():
    builder = ube_foundation.TokenBuilder("tok-1", ISSUER, CAPABILITY)
    with pytest.raises(ValueError):
        builder.expires("next tuesday")


def test_token_from_an_unpinned_issuer_is_denied():
    # The signature is valid, but the engine does not trust the key.
    engine, key = make_engine(pin_issuer=False)
    out = evaluate(engine, risk_token(key, 6500), 0.12)
    assert out["decision"] == "Deny", out
    assert "untrusted token issuer" in out["reason"], out


def test_tampering_with_the_caveat_invalidates_the_token():
    # Raising the threshold after signing is the obvious attack.
    engine, key = make_engine()
    token = json.loads(risk_token(key, 6500))
    token["caveats"][0]["condition"]["RiskBelow"] = 10_000
    out = evaluate(engine, json.dumps(token), 0.91)
    assert out["decision"] == "Deny", out
    assert "signature" in out["reason"], out
