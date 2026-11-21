#!/usr/bin/env bash
set -euo pipefail
: "${VAULT_ADDR:=http://127.0.0.1:8200}"
: "${VAULT_TOKEN:=local-vault-dev-token}"
: "${JWK_SET_FILE:=./secrets/securemcp-jwks.json}"
command -v vault >/dev/null || { echo 'Install the Vault CLI first.' >&2; exit 1; }
[[ -f "$JWK_SET_FILE" ]] || { echo "Missing JWK set: $JWK_SET_FILE" >&2; exit 1; }
export VAULT_ADDR VAULT_TOKEN
vault secrets enable -path=secret kv-v2 2>/dev/null || true
vault kv put secret/securemcp/signing jwkSet="$(cat "$JWK_SET_FILE")"
echo 'Stored signing JWK set in Vault KV v2. Dev Vault is not suitable for production.'
