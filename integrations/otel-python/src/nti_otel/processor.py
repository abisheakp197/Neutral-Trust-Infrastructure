"""OpenTelemetry span processor that turns ended spans into chained records.

Wire it into any existing OTel pipeline. Nothing in the agent changes: no new
SDK, no new decorator, no new export path. If a service already emits spans for
its tool calls, it starts producing evidence the moment this is registered.
"""

from __future__ import annotations

import os

from opentelemetry.sdk.trace import SpanProcessor

from .chain import ReceiptChain
from .records import record_from_span
from .signing import signer_from_env


class NTIRecordProcessor(SpanProcessor):
    """Records ended spans into a hash chain.

    Only spans that carry a decision attribute are recorded. Tracing furniture
    (HTTP client spans, connection pools) outnumbers decisions by orders of
    magnitude, and recording all of it would make the evidence file useless.
    Override `decision_attributes` to record something else.
    """

    def __init__(
        self,
        path: str | None = None,
        service_name: str | None = None,
        decision_attributes: tuple[str, ...] = ("nti.decision", "nti.capability"),
        signer=None,
        require_decision: bool = True,
    ):
        self.chain = ReceiptChain(path=path, signer=signer)
        self.service_name = (
            service_name
            or os.environ.get("OTEL_SERVICE_NAME")
            or os.environ.get("OTEL_RESOURCE_ATTRIBUTES", "").partition("service.name=")[2].partition(",")[0]
            or ""
        )
        self.decision_attributes = decision_attributes
        self.require_decision = require_decision
        self.recorded = 0
        self.skipped = 0

    def on_start(self, span, parent_context=None) -> None:  # noqa: D102 - interface method
        return None

    def on_end(self, span) -> None:
        if self.require_decision and not any(
            key in (span.attributes or {}) for key in self.decision_attributes
        ):
            self.skipped += 1
            return
        self.chain.append(record_from_span(span, self.service_name))
        self.recorded += 1

    def shutdown(self) -> None:  # noqa: D102 - interface method
        return None

    def force_flush(self, timeout_millis: int = 30000) -> bool:  # noqa: D102
        return True


def install(tracer_provider=None, path: str | None = None, **kwargs) -> NTIRecordProcessor:
    """Register a processor on a TracerProvider and return it.

    Reads NTI_OTEL_LOG to pick the log path, so a deployment can enable evidence
    with an environment variable instead of a code change.
    """
    from opentelemetry import trace

    provider = tracer_provider or trace.get_tracer_provider()
    processor = NTIRecordProcessor(
        path=path or os.environ.get("NTI_OTEL_LOG"),
        signer=kwargs.pop("signer", None) or signer_from_env(),
        **kwargs,
    )
    provider.add_span_processor(processor)
    return processor
