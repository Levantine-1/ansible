#!/bin/bash
# Git credential helper for github.com -- fetches the ansible-repo-scoped
# GitHub PAT from HashiCorp Vault via the service-host AppRole instead of
# storing it anywhere on disk. Configured via:
#   git config --global credential.https://github.com.helper \
#     "!/usr/local/bin/git-credential-vault-github"
# Git invokes credential helpers with get/store/erase; we only answer "get".
set -euo pipefail

if [ "${1:-}" != "get" ]; then
  exit 0
fi

source /etc/vault-approle.env

TOKEN=$(curl -s -X POST \
  -d "{\"role_id\":\"${VAULT_ROLE_ID}\",\"secret_id\":\"${VAULT_SECRET_ID}\"}" \
  "${VAULT_ADDR}/v1/auth/approle/login" | python3 -c "import sys,json; print(json.load(sys.stdin)['auth']['client_token'])")

PAT=$(curl -s -H "X-Vault-Token: ${TOKEN}" \
  "${VAULT_ADDR}/v1/kv/data/github/ansible_repo_pat" | \
  python3 -c "import sys,json; print(json.load(sys.stdin)['data']['data']['token'])")

echo "username=x-access-token"
echo "password=${PAT}"
