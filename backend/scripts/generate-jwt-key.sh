#!/usr/bin/env bash
# Generates one RSA signing key entry for IAM_JWT_KEYS.
# Usage: ./scripts/generate-jwt-key.sh <kid>
set -euo pipefail
KID="${1:-key-$(date +%Y%m%d)}"
TMP="$(mktemp -d)"
trap 'rm -rf "$TMP"' EXIT

openssl genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:2048 -out "$TMP/private.pem" 2>/dev/null
openssl rsa -in "$TMP/private.pem" -pubout -out "$TMP/public.pem" 2>/dev/null

strip() { grep -v -- "-----" "$1" | tr -d '\n'; }

printf '[{"kid":"%s","active":true,"privateKey":"%s","publicKey":"%s"}]\n' \
  "$KID" "$(strip "$TMP/private.pem")" "$(strip "$TMP/public.pem")"
