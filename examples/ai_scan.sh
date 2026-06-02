#!/bin/bash

# Small helper to run Ultimate SSRF Framework with optional AI support.
# Defaults to Ollama because it works locally and does not need an API key.
#
# Usage examples:
#
#   ./ai_scan.sh
#
#   TARGET=example.com CALLBACK=abc.oastify.com ./ai_scan.sh
#
#   AI_PROVIDER=ollama AI_MODEL=qwen2.5:1.5b ./ai_scan.sh
#
#   AI_PROVIDER=sheep AI_MODEL=hunter AI_KEY=shp_YOUR_TOKEN ./ai_scan.sh
#
#   AI_PROVIDER=openai AI_MODEL=gpt-4o AI_KEY=YOUR_OPENAI_KEY ./ai_scan.sh
#
#   AI_PROVIDER=claude AI_MODEL=claude-3-5-sonnet-20241022 AI_KEY=YOUR_CLAUDE_KEY ./ai_scan.sh
#
#   AI_PROVIDER=gemini AI_MODEL=gemini-2.0-flash-exp AI_KEY=YOUR_GEMINI_KEY ./ai_scan.sh
#
#   AI_PROVIDER=mistral AI_MODEL=mistral-large-latest AI_KEY=YOUR_MISTRAL_KEY ./ai_scan.sh
#
#   AI_PROVIDER=deepseek AI_MODEL=deepseek-chat AI_KEY=YOUR_DEEPSEEK_KEY ./ai_scan.sh
#
#   AI_PROVIDER=none ./ai_scan.sh

set -e

TARGET="${TARGET:-example.com}"
CALLBACK="${CALLBACK:-your-callback.oastify.com}"
OUTPUT="${OUTPUT:-reports-ai}"

AI_PROVIDER="${AI_PROVIDER:-ollama}"
AI_MODEL="${AI_MODEL:-}"
AI_KEY="${AI_KEY:-}"

cmd=(
  python ssrf_arsenal.py
  --target "$TARGET"
  --callback "$CALLBACK"
  --output "$OUTPUT"
  --export-json-api
)

if [ "$AI_PROVIDER" = "none" ]; then
  cmd+=(--no-ai)
else
  cmd+=(--ai-provider "$AI_PROVIDER")

  if [ -n "$AI_MODEL" ]; then
    cmd+=(--ai-model "$AI_MODEL")
  fi

  if [ "$AI_PROVIDER" != "ollama" ]; then
    if [ -z "$AI_KEY" ]; then
      echo "[!] Missing AI_KEY for provider: $AI_PROVIDER"
      echo
      echo "Example:"
      echo "  AI_PROVIDER=$AI_PROVIDER AI_MODEL=hunter AI_KEY=YOUR_TOKEN ./ai_scan.sh"
      exit 1
    fi

    cmd+=(--ai-key "$AI_KEY")
  fi
fi

echo "[*] Starting AI-assisted scan"
echo "[*] Target: $TARGET"
echo "[*] Callback: $CALLBACK"
echo "[*] Output: $OUTPUT"
echo "[*] AI provider: $AI_PROVIDER"

if [ -n "$AI_MODEL" ]; then
  echo "[*] AI model: $AI_MODEL"
fi

echo

"${cmd[@]}"
