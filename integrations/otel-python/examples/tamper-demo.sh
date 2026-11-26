#!/usr/bin/env bash
# Tamper demo for nti-otel: record a decision, verify it, alter one word, verify again.
#
#   pip install nti-otel
#   bash tamper-demo.sh
#
# The second verification must fail. If it passes, the chain is not detecting
# modification and you should not trust it.
set -uo pipefail

DIR="$(mktemp -d)"
CHAIN="$DIR/decisions.jsonl"
BAR="────────────────────────────────────────────────────────────"

echo "$BAR"
echo " 1. Record a tool decision from an ordinary OpenTelemetry pipeline"
echo "$BAR"
python3 - "$CHAIN" <<'PY'
import sys
from opentelemetry.sdk.trace import TracerProvider
from nti_otel import install

provider = TracerProvider()
processor = install(provider, path=sys.argv[1])
tracer = provider.get_tracer("nti-demo")

with tracer.start_as_current_span("tool.invoke") as span:
    span.set_attribute("nti.capability", "payments:charge")
    span.set_attribute("nti.decision", "Allow")
    span.set_attribute("gen_ai.tool.name", "stripe.charge")

print(f"   recorded {processor.recorded} hash-chained record(s) -> {sys.argv[1]}")
PY

echo
echo "$BAR"
echo " 2. Verify the chain"
echo "$BAR"
nti-otel "$CHAIN"
echo "   exit status: $?"

echo
echo "$BAR"
echo " 3. Change one word in the record: Allow -> Deny"
echo "$BAR"
echo "   before: $(grep -o '"nti.decision": *"[A-Za-z]*"' "$CHAIN")"
sed -i 's/"Allow"/"Deny"/' "$CHAIN"
echo "   after : $(grep -o '"nti.decision": *"[A-Za-z]*"' "$CHAIN")"

echo
echo "$BAR"
echo " 4. Verify again"
echo "$BAR"
nti-otel "$CHAIN"
STATUS=$?
echo "   exit status: $STATUS"

echo
if [ "$STATUS" -eq 0 ]; then
  echo "   UNEXPECTED: the modification was not detected."
  rm -rf "$DIR"
  exit 1
fi
echo "   Detected. The record now claims an authorization that was never recorded."
rm -rf "$DIR"
