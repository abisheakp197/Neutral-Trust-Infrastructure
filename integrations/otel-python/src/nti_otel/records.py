"""Canonical serialization and record construction.

Records are the unit of evidence: a decision that was observed at a trust
boundary, serialized deterministically so that a hash over it is stable across
processes, machines and Python versions.
"""

from __future__ import annotations

import datetime as _dt
import hashlib
import json
import unicodedata
from typing import Any, Mapping

RECORD_VERSION = "nti-otel/1"

# Attributes worth carrying into a record. Everything else on a span is
# dropped: a record should be small enough to keep for years, and a decision's
# evidence should not depend on telemetry that changes every deploy.
DECISION_ATTRIBUTES = (
    "nti.actor",
    "nti.capability",
    "nti.decision",
    "nti.reason",
    "nti.policy",
    "gen_ai.operation.name",
    "gen_ai.tool.name",
    "gen_ai.agent.name",
    "mcp.server.name",
    "rpc.method",
    "http.request.method",
    "http.route",
)


def canonical_json(value: Any) -> bytes:
    """RFC 8785-style canonical JSON: sorted keys, no whitespace, UTF-8.

    Floats are rendered by Python's repr, which is shortest-round-trip and
    therefore stable. Structurally invalid inputs raise instead of being
    stringified, because a record that cannot be canonicalized cannot be
    hashed, and an unhashable record must not be silently accepted.
    """
    return json.dumps(
        _normalize(value),
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
        allow_nan=False,
    ).encode("utf-8")


def _normalize(value: Any) -> Any:
    if isinstance(value, str):
        return unicodedata.normalize("NFC", value)
    if isinstance(value, Mapping):
        return {str(k): _normalize(v) for k, v in value.items()}
    if isinstance(value, (list, tuple)):
        return [_normalize(v) for v in value]
    if isinstance(value, bool) or value is None:
        return value
    if isinstance(value, int):
        return value
    if isinstance(value, float):
        return value
    if isinstance(value, (bytes, bytearray)):
        return value.hex()
    return str(value)


def sha256_hex(payload: bytes) -> str:
    return "sha256:" + hashlib.sha256(payload).hexdigest()


def _ns_to_iso(ns: int) -> str:
    return (
        _dt.datetime.fromtimestamp(ns / 1_000_000_000, tz=_dt.timezone.utc)
        .isoformat(timespec="microseconds")
        .replace("+00:00", "Z")
    )


def record_from_span(span, service_name: str = "") -> dict:
    """Build a record from an ended OpenTelemetry span.

    Reads only the attributes named in DECISION_ATTRIBUTES, so a change of
    instrumentation vocabulary is visible in the record rather than silently
    altering what is hashed.
    """
    ctx = span.get_span_context()
    parent = span.parent
    attrs = span.attributes or {}
    return {
        "record_version": RECORD_VERSION,
        "trace_id": format(ctx.trace_id, "032x"),
        "span_id": format(ctx.span_id, "016x"),
        "parent_span_id": format(parent.span_id, "016x") if parent else None,
        "name": span.name,
        "service": service_name or "",
        "started_at": _ns_to_iso(span.start_time),
        "ended_at": _ns_to_iso(span.end_time),
        "status": span.status.status_code.name if span.status else "UNSET",
        "attributes": {
            key: _normalize(attrs[key]) for key in DECISION_ATTRIBUTES if key in attrs
        },
    }
