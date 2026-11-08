#!/usr/bin/env python3
"""Verify an NTI receipt for the joint NTI-VATE recovery test (Issue #64).

Self-contained: only the Python standard library and `openssl` are required.
No third-party Python packages, no ML-DSA library: the ML-DSA-87 signature is
checked with the `openssl` binary, which has native ML-DSA-87 support
(OpenSSL >= 3.5).

What this checks
----------------
1. Schema          - the receipt has the required fields (including the
                     authoritative identifiers) and an ML-DSA-87 tag.
2. Payload binding - action_payload_sha256 is the SHA-256 of action_payload.
3. Merkle root     - delegation_chain_root is recomputed from delegation_chain
                     (RFC 6962, odd node promoted, never duplicated).
4. Merkle proof    - the inclusion proof for the leaf at leaf_index folds to
                     delegation_chain_root.
5. ML-DSA-87 sig   - the signature verifies over the domain-separated,
                     length-prefixed signing payload, with the public key. The
                     payload binds the authoritative identifiers (receipt_id,
                     recovery.attempt_id, recovery.idempotency_key) as well as
                     the DID, key, delegation root, payload digest, and time, so
                     altering any of them fails closed.

What this does NOT check
------------------------
* DID authorization (Layer 0a) and VC issuer identity (Layer 0b). Those need
  the DID log and the VC; see docs/NTI-Agent-DID-INTEROP.md sections 2.1-2.2.
  This script verifies Layer 1 (the NTI proofs) only.
* Whether the action actually took effect. The receipt is evidence of signing,
  not of downstream completion. That gap is the point of the recovery test.

Usage
-----
    python3 verify_receipt.py nti_receipt.json
    python3 verify_receipt.py nti_receipt.json --public-key pinned_pub.pem
    python3 verify_receipt.py nti_receipt.json --expect-payload-sha256 <hex>

Exit codes: 0 all checks pass, 1 a check failed, 2 the receipt could not be read.
"""
import argparse
import base64
import hashlib
import json
import pathlib
import struct
import subprocess
import sys
import tempfile

DOMAIN_LEAF = b"nti-delegation-leaf-v1:"
DOMAIN_NODE = b"nti-delegation-node-v1:"
# Bumped to v2 when the signing payload gained the authoritative identifiers
# (receipt_id, recovery.attempt_id, recovery.idempotency_key). The domain
# separates the two layouts so a receipt signed under v1 can never verify as v2.
DOMAIN_SIGN = b"nti-vate-receipt-v2:"

REQUIRED_FIELDS = [
    "receipt_id", "agent_did", "verification_method", "delegation_chain_root",
    "action_payload_sha256", "signed_at", "merkle_proof", "ml_dsa_87_signature",
    "recovery",
]

# Authoritative identifiers the signature MUST bind. Each is a dotted path into
# the receipt. If any is absent the receipt is malformed and verification fails
# closed; if any is altered, the signature no longer verifies.
SIGNED_IDENTIFIER_PATHS = [
    ("receipt_id",),
    ("recovery", "attempt_id"),
    ("recovery", "idempotency_key"),
]


def canon(obj) -> bytes:
    """Canonical JSON: sorted keys, no insignificant whitespace."""
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode()


def sha256(b: bytes) -> bytes:
    return hashlib.sha256(b).digest()


def u32(n: int) -> bytes:
    return struct.pack(">I", n)


def leaf_hash(record: dict) -> bytes:
    return sha256(DOMAIN_LEAF + canon(record))


def node_hash(a: bytes, b: bytes) -> bytes:
    return sha256(DOMAIN_NODE + a + b)


def merkle_root(leaves: list) -> bytes:
    """RFC 6962 Merkle Tree Hash. Odd node promoted, never duplicated."""
    lv = list(leaves)
    if not lv:
        raise ValueError("no leaves")
    while len(lv) > 1:
        nxt = [node_hash(lv[i], lv[i + 1]) for i in range(0, len(lv) - 1, 2)]
        if len(lv) % 2 == 1:
            nxt.append(lv[-1])
        lv = nxt
    return lv[0]


def fold_proof(leaf: bytes, siblings: list) -> bytes:
    """Fold an inclusion proof into a candidate root."""
    acc = leaf
    for sib in siblings:
        pos = sib["position"]
        s = bytes.fromhex(sib["sha256"])
        if pos == "left":
            acc = node_hash(s, acc)
        elif pos == "right":
            acc = node_hash(acc, s)
        elif pos == "promoted":
            # A promoted node carries the accumulator up unchanged; the sibling
            # must be the accumulator itself.
            if s != acc:
                raise ValueError("promoted sibling does not equal the accumulator")
        else:
            raise ValueError(f"unknown sibling position: {pos!r}")
    return acc


def resolve_path(obj: dict, path: tuple):
    """Resolve a dotted path into the receipt. Raises KeyError if absent."""
    cur = obj
    for key in path:
        if not isinstance(cur, dict) or key not in cur:
            raise KeyError(".".join(path))
        cur = cur[key]
    if not isinstance(cur, str) or not cur:
        raise KeyError(".".join(path))
    return cur


def signing_payload(r: dict) -> bytes:
    """The exact bytes NTI signed: domain-separated and length-prefixed.

    Binds the authoritative identifiers (receipt_id, recovery.attempt_id,
    recovery.idempotency_key) together with the DID, key, delegation root,
    payload digest, and timestamp, so altering any of them breaks the signature.
    """
    def lp(s: str) -> bytes:
        b = s.encode()
        return u32(len(b)) + b
    identifiers = [resolve_path(r, p) for p in SIGNED_IDENTIFIER_PATHS]
    return (DOMAIN_SIGN
            + lp(identifiers[0])            # receipt_id
            + lp(r["agent_did"])
            + lp(r["verification_method"])
            + lp(r["delegation_chain_root"])
            + lp(r["action_payload_sha256"])
            + lp(r["signed_at"])
            + lp(identifiers[1])            # recovery.attempt_id
            + lp(identifiers[2]))           # recovery.idempotency_key


def parse_tagged_signature(tag: str):
    """Parse `ml-dsa-87:{length}:{hex}`. Returns (algorithm, length, sig_bytes)."""
    parts = tag.split(":")
    if len(parts) != 3:
        raise ValueError("signature tag must be ml-dsa-87:{length}:{hex}")
    algo, length, hexsig = parts
    if algo != "ml-dsa-87":
        raise ValueError(f"unexpected signature algorithm tag: {algo!r}")
    if any(c in hexsig for c in "-= \t\n"):
        raise ValueError("signature is not raw hex (looks DER/base64 encoded)")
    sig = bytes.fromhex(hexsig)
    if int(length) != len(sig):
        raise ValueError(f"tagged length {length} != actual {len(sig)} bytes")
    return algo, len(sig), sig


def openssl_verify(pubkey_pem_path: pathlib.Path, sig: bytes, msg: bytes) -> bool:
    with tempfile.TemporaryDirectory() as td:
        m = pathlib.Path(td) / "m"
        s = pathlib.Path(td) / "s"
        m.write_bytes(msg)
        s.write_bytes(sig)
        p = subprocess.run(
            ["openssl", "pkeyutl", "-verify", "-pubin", "-inkey", str(pubkey_pem_path),
             "-rawin", "-in", str(m), "-sigfile", str(s)],
            capture_output=True)
    return p.returncode == 0


class Report:
    def __init__(self):
        self.failed = 0

    def ok(self, label, detail=""):
        print(f"   OK   : {label}" + (f"  {detail}" if detail else ""))

    def fail(self, label, detail=""):
        print(f"   FAIL : {label}" + (f"  {detail}" if detail else ""))
        self.failed += 1

    def warn(self, label, detail=""):
        print(f"   WARN : {label}" + (f"  {detail}" if detail else ""))


def main():
    ap = argparse.ArgumentParser(description="Verify an NTI receipt (Layer 1 proofs).")
    ap.add_argument("receipt", help="path to nti_receipt.json")
    ap.add_argument("--public-key", help="pin the ML-DSA-87 public key (PEM). Overrides the "
                                        "embedded key, which is self-asserted.")
    ap.add_argument("--expect-payload-sha256", help="the action_payload_sha256 this receipt MUST "
                                                    "commit to, to bind it to the original attempt")
    args = ap.parse_args()

    rp = pathlib.Path(args.receipt)
    try:
        r = json.loads(rp.read_text())
    except (OSError, json.JSONDecodeError) as e:
        print(f"cannot read receipt: {e}", file=sys.stderr)
        return 2

    rep = Report()

    print("== 1. Schema ==")
    missing = [f for f in REQUIRED_FIELDS if f not in r]
    if missing:
        rep.fail("required fields present", f"missing {missing}")
    else:
        rep.ok("required fields present")
    if r.get("algorithm") != "ML-DSA-87":
        rep.fail("algorithm is ML-DSA-87", f"got {r.get('algorithm')!r}")
    else:
        rep.ok("algorithm is ML-DSA-87")
    # The authoritative identifiers must be present; they are part of the signed
    # payload, so an absent one is a malformed receipt (fail closed).
    missing_ids = []
    for path in SIGNED_IDENTIFIER_PATHS:
        try:
            resolve_path(r, path)
        except KeyError:
            missing_ids.append(".".join(path))
    if missing_ids:
        rep.fail("authoritative identifiers present", f"missing {missing_ids}")
    else:
        rep.ok("authoritative identifiers present",
               ", ".join(".".join(p) for p in SIGNED_IDENTIFIER_PATHS))

    print("== 2. Action payload binding ==")
    if "action_payload" in r and r.get("action_payload_sha256"):
        got = sha256(canon(r["action_payload"])).hex()
        if got == r["action_payload_sha256"]:
            rep.ok("action_payload_sha256 matches action_payload", got[:16])
        else:
            rep.fail("action_payload_sha256 matches action_payload",
                     f"recomputed {got[:16]} != field {r['action_payload_sha256'][:16]}")
    else:
        rep.warn("action_payload not present", "cannot re-derive the digest; only the field is bound")
    if args.expect_payload_sha256:
        if args.expect_payload_sha256 == r.get("action_payload_sha256"):
            rep.ok("payload digest matches the expected attempt", args.expect_payload_sha256[:16])
        else:
            rep.fail("payload digest matches the expected attempt",
                     f"expected {args.expect_payload_sha256[:16]} != receipt "
                     f"{str(r.get('action_payload_sha256'))[:16]}")

    print("== 3. Merkle root over the delegation chain ==")
    chain = r.get("delegation_chain")
    if not chain:
        rep.fail("delegation_chain present", "cannot recompute the root")
    else:
        leaves = [leaf_hash(rec) for rec in chain]
        root = merkle_root(leaves).hex()
        if root == r.get("delegation_chain_root"):
            rep.ok("delegation_chain_root recomputed", root[:16])
        else:
            rep.fail("delegation_chain_root recomputed",
                     f"got {root[:16]} != field {str(r.get('delegation_chain_root'))[:16]}")

    print("== 4. Merkle inclusion proof ==")
    proof = r.get("merkle_proof") or {}
    siblings = proof.get("siblings")
    if not siblings:
        rep.fail("merkle_proof.siblings present")
    else:
        leaf = bytes.fromhex(proof["leaf_sha256"])
        # The leaf digest must match the record at leaf_index in the chain.
        idx = proof.get("leaf_index")
        if chain and isinstance(idx, int) and 0 <= idx < len(chain):
            expected_leaf = leaf_hash(chain[idx])
            if expected_leaf == leaf:
                rep.ok("leaf_sha256 matches the record at leaf_index", f"index {idx}")
            else:
                rep.fail("leaf_sha256 matches the record at leaf_index",
                         f"index {idx} hashes to {expected_leaf.hex()[:16]}")
        else:
            rep.fail("leaf_index is within the chain", f"got {idx!r}")
        try:
            folded = fold_proof(leaf, siblings).hex()
        except ValueError as e:
            folded = None
            rep.fail("proof folds cleanly", str(e))
        if folded is not None:
            if folded == proof.get("root_sha256"):
                rep.ok("proof folds to merkle_proof.root_sha256", folded[:16])
            else:
                rep.fail("proof folds to merkle_proof.root_sha256",
                         f"got {folded[:16]} != {str(proof.get('root_sha256'))[:16]}")
            if folded != r.get("delegation_chain_root"):
                rep.fail("proof root equals delegation_chain_root",
                         f"{folded[:16]} != {str(r.get('delegation_chain_root'))[:16]}")
            else:
                rep.ok("proof root equals delegation_chain_root")

    print("== 5. ML-DSA-87 signature ==")
    tag = r.get("ml_dsa_87_signature", "")
    try:
        _algo, sig_len, sig = parse_tagged_signature(tag)
        rep.ok("signature is tagged ML-DSA-87", f"{sig_len} bytes")
    except ValueError as e:
        sig = None
        rep.fail("signature is tagged ML-DSA-87", str(e))
    if sig is not None:
        if args.public_key:
            pub_path = pathlib.Path(args.public_key)
            rep.ok("using pinned public key", str(pub_path))
        else:
            pem = r.get("public_key", {}).get("public_key_pem")
            if not pem:
                rep.fail("public key available", "no embedded key and no --public-key")
                pub_path = None
            else:
                pub_path = pathlib.Path(tempfile.mkdtemp()) / "embedded_pub.pem"
                pub_path.write_text(pem)
                rep.warn("using the embedded public key",
                         "self-asserted; pin it out of band for a real decision")
        if pub_path is not None:
            try:
                msg = signing_payload(r)
            except KeyError as e:
                rep.fail("signing payload reconstructed",
                         f"missing field {e}; cannot verify (fail closed)")
                msg = None
            if msg is not None:
                if openssl_verify(pub_path, sig, msg):
                    rep.ok("ML-DSA-87 signature verifies over the signing payload",
                           "binds identifiers + DID + delegation root + payload digest + time")
                else:
                    rep.fail("ML-DSA-87 signature verifies over the signing payload",
                             "signature does not verify with this key over the reconstructed "
                             "payload (a bound field was altered, or the key is wrong)")

    print()
    if rep.failed == 0:
        print("RESULT: receipt verified (Layer 1: payload binding + Merkle proof + ML-DSA-87 signature).")
        print("NOTE:   this proves NTI signed the action. It does NOT prove the action took effect.")
        return 0
    print(f"RESULT: VERIFICATION FAILED ({rep.failed} check(s)).")
    return 1


if __name__ == "__main__":
    sys.exit(main())
