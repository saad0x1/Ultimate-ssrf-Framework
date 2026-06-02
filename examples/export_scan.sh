#!/bin/bash

set -e

TARGET="${TARGET:-example.com}"
CALLBACK="${CALLBACK:-your-callback.oastify.com}"
OUTPUT="${OUTPUT:-reports-export}"

echo "[*] Starting export-focused SSRF scan"
echo "[*] Target: $TARGET"
echo "[*] Callback: $CALLBACK"
echo "[*] Output: $OUTPUT"
echo

python ssrf_arsenal.py \
  --target "$TARGET" \
  --callback "$CALLBACK" \
  --output "$OUTPUT" \
  --export-json-api \
  --export-nuclei \
  --export-siem \
  --attack-map \
  --no-ai
