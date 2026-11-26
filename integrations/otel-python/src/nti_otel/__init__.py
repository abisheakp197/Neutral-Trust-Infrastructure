"""Tamper-evident records for AI agent tool calls, built on OpenTelemetry.

An agent that already emits spans gets a hash-chained evidence log with one
line of configuration. The log answers one question: has this record been
altered since it was written?
"""

from .chain import ReceiptChain, read_entries, verify
from .processor import NTIRecordProcessor, install
from .records import RECORD_VERSION, canonical_json, record_from_span
from .signing import generate_signer

__all__ = [
    "RECORD_VERSION",
    "NTIRecordProcessor",
    "ReceiptChain",
    "canonical_json",
    "generate_signer",
    "install",
    "read_entries",
    "record_from_span",
    "verify",
]

__version__ = "0.1.0"
