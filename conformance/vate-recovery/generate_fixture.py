#!/usr/bin/env python3
"""Generate the NTI receipt fixture for the joint NTI-VATE recovery test (Issue #64).

This is the *producer* counterpart to `verify_receipt.py`. It rebuilds the
`nti_receipt.json` fixture from source: a fresh disposable keypair, the exact
VATE case-01 `action_payload`/`resource`, a delegation chain and Merkle
inclusion proof, and a signature over the canonical signing payload.

Because it is deterministic apart from the keypair, anyone can regenerate the
fixture and independently check the signature and the payload binding, rather
than trusting the committed bytes. `--signed-at` moves the receipt onto the
VATE timeline; `--tamper` emits the negative cases.

Algorithm note (important)
--------------------------
The task brief for this script says "Ed25519 keypair". NTI receipts are signed
with **ML-DSA-87**, not Ed25519: the receipt schema, the verifier
(`verify_receipt.py`), `docs/NTI-Agent-DID-INTEROP.md` (sections 1.1-1.2), and
every committed fixture all require an ML-DSA-87 signature tagged
`ml-dsa-87:{length}:{hex}` (4627 bytes). An Ed25519 signature cannot verify
against any of them and is explicitly rejected ("Ed25519 keys can never verify
an ML-DSA-87 receipt"). This generator therefore produces ML-DSA-87, matching
the verifier. `--algorithm ed25519` is offered only for experimentation and
warns that the result is not a conforming NTI receipt.

Usage
-----
    # Reproduce the committed fixture (default timestamp reproduces its digests).
    python3 generate_fixture.py --out-dir ./pinned

    # Align to the VATE timeline.
    python3 generate_fixture.py --signed-at "2026-10-25T00:00:00Z" --out-dir ./pinned

    # Negative cases for Larry's requirements (wrong operation, wrong attempt).
    python3 generate_fixture.py --tamper all --out-dir ./pinned

Exit codes: 0 success, 2 a generation error.
"""
import argparse
import base64
import datetime
import json
import pathlib
import subprocess
import sys
import tempfile

# Reuse the verifier's primitives so the producer and the checker cannot drift.
# If verify_receipt.py cannot be imported (e.g. it was moved), fail loudly rather
# than silently reimplementing the encoding and risking a mismatch.
sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent))
try:
    from verify_receipt import (  # noqa: E402
        DOMAIN_SIGN, canon, leaf_hash, merkle_root, node_hash, sha256,
        signing_payload,
    )
except ImportError as exc:  # pragma: no cover
    print(f"cannot import verify_receipt.py (keep it beside this script): {exc}",
          file=sys.stderr)
    raise SystemExit(2)

# --- Exact VATE case-01 operation (Poke-nushi/Verifiable-Agent-Trust-Envelope
#     @ c7533ad, with-unknown-observation/operation.json). These strings are the
#     binding target: do not paraphrase them.
VATE_RESOURCE = ("urn:vate:handoff:store-e3aa81d38ad34697867ee350932c46b2:"
                 "resource-6d36e653fa774434a64b99885539fb3b")
VATE_FILES = [
    {"name": "first.txt", "text": "first local effect\n"},
    {"name": "second.txt", "text": "second local effect\n"},
]
VATE_CONTRACT = "vate-demo-file-set-v1"

AGENT_DID = "did:webvh:z6MkExampleAgentSCID0000000000000000000000:agents.example.com"
ISSUER_DID = "did:webvh:z6MkExampleIssuerSCID0000000000000000000000:issuer.example.com"
VM_ID = f"{AGENT_DID}#ml-dsa-87-1"

DEFAULT_SIGNED_AT = "2026-11-08T06:31:07Z"
DEFAULT_NONCE = "3f9c1a2b7d4e50618a9b0c1d2e3f4051"

# Tamper variants: (label, mutator). Each mutator makes the receipt describe a
# *different* operation or attempt while keeping the signature self-consistent,
# i.e. "validly signed evidence for the wrong context". This is deliberately
# distinct from signature tampering (flip a byte), which would fail earlier and
# must not be able to hide a missing binding check (Larry's point). The receipt
# is re-signed after mutation, so the signature always verifies: the receiver
# must catch these by binding, not by the signature.
def _wrong_operation(receipt):
    payload = receipt["action_payload"]
    payload["type"] = "demo.delete_file_set"
    payload["resource"] = VATE_RESOURCE.replace("resource-", "resource-other-")


def _wrong_attempt(receipt):
    # A different attempt of the *same* logical operation: a new per-attempt
    # nonce (the token that maps to the VATE attempt_id) plus new recovery
    # identifiers. Same action_id, resource and files.
    receipt["action_payload"]["nonce"] = "9d2e4f60718293a4b5c6d7e8f9012345"
    receipt["recovery"]["attempt_id"] = "act-20261025-0064-0002"
    receipt["recovery"]["idempotency_key"] = "act-20261025-0064-0002"


TAMPER_VARIANTS = {
    "wrong-operation": ("mutate the action to a different operation "
                        "(type + resource)", _wrong_operation),
    "wrong-attempt": ("re-point to a different attempt of the same operation "
                      "(nonce + attempt_id/idempotency_key)", _wrong_attempt),
}


# --------------------------------------------------------------------------- #
# Key material
# --------------------------------------------------------------------------- #
def openssl(args, **kw):
    return subprocess.run(["openssl", *args], check=True,
                          capture_output=True, **kw)


def generate_keypair(algorithm, key_out: pathlib.Path):
    """Create a disposable keypair. Returns (private_path, public_pem, spki_der)."""
    openssl(["genpkey", "-algorithm", algorithm, "-out", str(key_out)])
    pem = openssl(["pkey", "-in", str(key_out), "-pubout"]).stdout.decode()
    der = openssl(["pkey", "-in", str(key_out), "-pubout", "-outform", "DER"]).stdout
    return key_out, pem, der


def raw_public_key(spki_der: bytes, size: int) -> bytes:
    """Strip the SPKI header, leaving the raw public key bytes."""
    return spki_der[-size:]


def public_key_multibase(spki_der: bytes, key_size: int, multicodec_varint: bytes) -> str:
    raw = raw_public_key(spki_der, key_size)
    return "u" + base64.urlsafe_b64encode(multicodec_varint + raw).decode().rstrip("=")


def sign(private_path: pathlib.Path, message: bytes) -> bytes:
    with tempfile.TemporaryDirectory() as td:
        m, s = pathlib.Path(td) / "m", pathlib.Path(td) / "s"
        m.write_bytes(message)
        openssl(["pkeyutl", "-sign", "-inkey", str(private_path),
                 "-rawin", "-in", str(m), "-out", str(s)])
        return s.read_bytes()


# --------------------------------------------------------------------------- #
# Fixture construction
# --------------------------------------------------------------------------- #
def iso_shift(base: str, **delta) -> str:
    """Parse an RFC 3339 UTC instant and shift it, preserving the Z form."""
    dt = datetime.datetime.fromisoformat(base.replace("Z", "+00:00"))
    dt = dt + datetime.timedelta(**delta)
    return dt.astimezone(datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def build_action_payload(signed_at: str, nonce: str) -> dict:
    """The VATE operation, with a timeline derived from signed_at.

    requested_at is 5s before signing, matching the committed fixture, so the
    default signed_at reproduces the committed action_payload_sha256 exactly.
    """
    return {
        "action_id": "act-20261108-0064-0001",
        "type": "demo.create_file_set",
        "contract": VATE_CONTRACT,
        "actor": AGENT_DID,
        "resource": VATE_RESOURCE,
        "files": VATE_FILES,
        "nonce": nonce,
        "requested_at": iso_shift(signed_at, seconds=-5),
    }


def build_delegation_chain(signed_at: str) -> list:
    """A three-record chain (issuer -> agent -> leaf) authorising the action.

    All records are issued before signing (T-7min, T-4min, T-1min), so the
    delegation window is consistent with the signing time.
    """
    d0 = "sha256:" + sha256(b"nti-delegation-record-0:" + signed_at.encode()).hex()
    d1 = "sha256:" + sha256(b"nti-delegation-record-1:" + signed_at.encode()).hex()
    d2 = "sha256:" + sha256(b"nti-delegation-record-2:" + signed_at.encode()).hex()
    return [
        {
            "delegation_id": d0,
            "parent_delegation_id": None,
            "issuer": ISSUER_DID,
            "subject": AGENT_DID,
            "scope": ["store:read", "demo:create_file_set"],
            "issued_at": iso_shift(signed_at, minutes=-7),
            "depth_remaining": 1,
        },
        {
            "delegation_id": d1,
            "parent_delegation_id": d0,
            "issuer": AGENT_DID,
            "subject": AGENT_DID,
            "scope": ["demo:create_file_set"],
            "issued_at": iso_shift(signed_at, minutes=-4),
            "depth_remaining": 0,
        },
        {
            "delegation_id": d2,
            "parent_delegation_id": d1,
            "issuer": AGENT_DID,
            "subject": AGENT_DID,
            "scope": ["demo:create_file_set"],
            "issued_at": iso_shift(signed_at, minutes=-1),
            "depth_remaining": 0,
            "note": "leaf delegation authorising the action in this receipt",
        },
    ]


def build_merkle_proof(chain: list, leaf_index: int) -> dict:
    """RFC 6962 inclusion proof for the leaf at leaf_index (odd node promoted)."""
    leaves = [leaf_hash(rec) for rec in chain]
    root = merkle_root(leaves)
    lv = list(leaves)
    siblings = []
    i = leaf_index
    while len(lv) > 1:
        if i % 2 == 1:
            siblings.append({"position": "left", "sha256": lv[i - 1].hex()})
        elif i + 1 < len(lv):
            siblings.append({"position": "right", "sha256": lv[i + 1].hex()})
        else:
            siblings.append({"position": "promoted", "sha256": lv[i].hex()})
        nxt = [node_hash(lv[j], lv[j + 1]) for j in range(0, len(lv) - 1, 2)]
        if len(lv) % 2 == 1:
            nxt.append(lv[-1])
        lv = nxt
        i //= 2
    return {
        "hash_algorithm": "sha256",
        "leaf_encoding": 'sha256(b"nti-delegation-leaf-v1:" || canonical_json(record))',
        "node_encoding": 'sha256(b"nti-delegation-node-v1:" || left || right)',
        "odd_node_rule": "last node promoted unchanged, never duplicated (RFC 6962)",
        "leaf_index": leaf_index,
        "leaf_sha256": leaves[leaf_index].hex(),
        "siblings": siblings,
        "root_sha256": root.hex(),
    }


def build_receipt(signed_at: str, nonce: str, pem: str, der: bytes,
                  profile: dict) -> dict:
    """Build the receipt with an empty signature; write_receipt() signs it."""
    chain = build_delegation_chain(signed_at)
    payload = build_action_payload(signed_at, nonce)
    leaf_index = 2
    proof = build_merkle_proof(chain, leaf_index)
    receipt = {
        "receipt_version": "nti-receipt/1.0",
        "classification": "SYNTHETIC - joint NTI-VATE recovery fixture (Issue #64); not production evidence",
        "receipt_id": "rcpt-20261108-0064-a2b1",
        "agent_did": AGENT_DID,
        "verification_method": VM_ID,
        "algorithm": profile["receipt_name"],
        "signed_at": signed_at,
        "delegation_chain_root": proof["root_sha256"],
        "action_payload_sha256": sha256(canon(payload)).hex(),
        "action_payload": payload,
        "delegation_chain": chain,
        "merkle_proof": proof,
        "ml_dsa_87_signature": "",
        "signing": {
            "domain": DOMAIN_SIGN.decode(),
            "canonical_form": (
                'b"nti-vate-receipt-v2:" || uint32_be(len(s)) || s  for each of, in order: '
                "receipt_id, agent_did, verification_method, delegation_chain_root, "
                "action_payload_sha256, signed_at, recovery.attempt_id, "
                "recovery.idempotency_key  (each s is the UTF-8 encoding of the field's "
                "exact string value)"
            ),
            "signed_fields": [
                "receipt_id", "agent_did", "verification_method",
                "delegation_chain_root", "action_payload_sha256", "signed_at",
                "recovery.attempt_id", "recovery.idempotency_key",
            ],
            "note": ("Domain-separated and length-prefixed. Binds the authoritative "
                     "identifiers so receipt_id, attempt_id, or idempotency_key cannot be "
                     "altered without invalidating the signature."),
        },
        "public_key": {
            "algorithm": profile["receipt_name"],
            "public_key_pem": pem,
            "public_key_multibase": public_key_multibase(der, profile["key_size"],
                                                         profile["varint"]),
            "multicodec": profile["multicodec"],
            "fingerprint_sha256": sha256(der).hex(),
        },
        "recovery": {
            "scenario": "lost-response",
            "attempt_id": "act-20261108-0064-0001",
            "response_lost": True,
            "idempotency_key": "act-20261108-0064-0001",
            "what_the_receipt_proves": [
                "NTI signed an action over exactly action_payload_sha256 at signed_at",
                "the delegation chain committed by delegation_chain_root was intact at signing",
                "the signature binds receipt_id, recovery.attempt_id and recovery.idempotency_key, so the attempt identity cannot be swapped",
            ],
            "what_the_receipt_does_not_prove": [
                "that the agent's DID authorised the ML-DSA-87 key (Layer 0a): the key embedded here is self-asserted",
                "that the key was valid or unrevoked at signed_at (Layer 0a)",
                "which VC issued the authority (Layer 0b)",
            ],
            "what_remains_unknown": [
                "whether the action's downstream effect (the local file-set creation) completed",
                "whether the action was applied exactly once",
                "whether the counterparty observed the effect",
            ],
        },
    }
    return receipt


# --------------------------------------------------------------------------- #
# Driver
# --------------------------------------------------------------------------- #
ALGORITHMS = {
    "ml-dsa-87": {"openssl_name": "ML-DSA-87", "receipt_name": "ML-DSA-87",
                  "tag": "ml-dsa-87", "key_size": 2592, "varint": b"\x92\x24",
                  "multicodec": "0x1212", "conforming": True},
    "ed25519": {"openssl_name": "ED25519", "receipt_name": "Ed25519",
                "tag": "ed25519", "key_size": 32, "varint": b"\xed\x01",
                "multicodec": "0xed01", "conforming": False},
}


def apply_tamper(receipt: dict, variant: str) -> dict:
    """Mutate the receipt into a wrong-context case and re-derive the digest.

    The signature is refreshed by the caller, so the result is self-consistent
    and passes a naive signature check. If the mutation changed the
    action_payload, its digest is recomputed so the receipt stays internally
    consistent; the mismatch is only visible when bound to the *expected*
    attempt (--expect-payload-sha256) or compared to the recorded identifiers.
    """
    _desc, mutate = TAMPER_VARIANTS[variant]
    before = canon(receipt["action_payload"])
    mutate(receipt)
    if canon(receipt["action_payload"]) != before:
        receipt["action_payload_sha256"] = sha256(canon(receipt["action_payload"])).hex()
    return receipt


def write_receipt(receipt: dict, private_path: pathlib.Path, out_dir: pathlib.Path,
                  name: str, tag: str) -> pathlib.Path:
    sig = sign(private_path, signing_payload(receipt))
    receipt["ml_dsa_87_signature"] = f"{tag}:{len(sig)}:{sig.hex()}"
    path = out_dir / name
    path.write_text(json.dumps(receipt, indent=2) + "\n")
    return path


def main() -> int:
    ap = argparse.ArgumentParser(
        description="Generate the NTI-VATE recovery receipt fixture (Issue #64).")
    ap.add_argument("--signed-at", default=DEFAULT_SIGNED_AT,
                    help=f"RFC 3339 signing instant (default: {DEFAULT_SIGNED_AT})")
    ap.add_argument("--nonce", default=DEFAULT_NONCE,
                    help="per-attempt token (maps to the VATE attempt_id)")
    ap.add_argument("--out-dir", required=True,
                    help="directory to write nti_receipt.json and test_key.pem into")
    ap.add_argument("--algorithm", choices=sorted(ALGORITHMS), default="ml-dsa-87",
                    help="signature algorithm (default: ml-dsa-87; see the algorithm note)")
    ap.add_argument("--tamper", choices=[*sorted(TAMPER_VARIANTS), "all"],
                    help="also emit the negative cases (wrong-operation / wrong-attempt) "
                         "alongside the valid receipt; 'all' emits both")
    args = ap.parse_args()

    try:
        datetime.datetime.fromisoformat(args.signed_at.replace("Z", "+00:00"))
    except ValueError:
        print(f"--signed-at is not RFC 3339: {args.signed_at!r}", file=sys.stderr)
        return 2

    out_dir = pathlib.Path(args.out_dir).expanduser().resolve()
    out_dir.mkdir(parents=True, exist_ok=True)

    alg = ALGORITHMS[args.algorithm]
    if args.algorithm == "ed25519":
        print("WARNING: --algorithm ed25519 produces a NON-conforming NTI receipt.",
              file=sys.stderr)
        print("         verify_receipt.py requires ML-DSA-87; this is for experimentation only.",
              file=sys.stderr)

    key_path = out_dir / "test_key.pem"
    _, pem, der = generate_keypair(alg["openssl_name"], key_path)

    receipt = build_receipt(args.signed_at, args.nonce, pem, der, alg)

    written = []
    if args.tamper is None:
        written.append(write_receipt(receipt, key_path, out_dir, "nti_receipt.json",
                                     alg["tag"]))
    else:
        # A valid receipt is still written alongside the tampered ones so the
        # receiver can run the positive and negative cases in one directory.
        written.append(write_receipt(receipt, key_path, out_dir, "nti_receipt.json",
                                     alg["tag"]))
        variants = sorted(TAMPER_VARIANTS) if args.tamper == "all" else [args.tamper]
        for variant in variants:
            tampered = apply_tamper(json.loads(json.dumps(receipt)), variant)
            written.append(write_receipt(tampered, key_path, out_dir,
                                         f"nti_receipt.tampered.{variant}.json",
                                         alg["tag"]))

    print(f"algorithm : {args.algorithm} ({'conforming' if alg['conforming'] else 'NON-conforming'})")
    print(f"signed_at : {args.signed_at}")
    print(f"key       : {key_path}")
    print(f"wrote     :")
    for p in written:
        print(f"            {p}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
