#!/usr/bin/env python3
"""Set GitHub Actions repository secrets from values held in Vault.

GitHub's secrets API doesn't take plaintext: each value has to be encrypted
with the repository's own public key using a libsodium sealed box before it
can be PUT. That's why this is a script rather than a couple of `uri` tasks
-- everything else here (Vault AppRole login, GitHub API calls) follows the
same patterns already used elsewhere in this role.

Reads a JSON spec on stdin:

  [
    {"repo": "Levantine-1/livecam",
     "secret": "AWS_ACCESS_KEY",
     "vault_path": "kv/data/aws/iam_access_keys/terraform_livecam",
     "vault_key": "access_key"}
  ]

Secret values are read from Vault and handed straight to encryption -- they
are never logged, printed, or written to disk. Output is limited to the
secret's *name* and the resulting HTTP status.

Exit codes: 0 all set, 1 one or more failed.
"""

import json
import sys
import urllib.request
import urllib.error
from base64 import b64encode

from nacl import encoding, public


def _req(url, token_header, method="GET", data=None):
    req = urllib.request.Request(url, method=method)
    for k, v in token_header.items():
        req.add_header(k, v)
    if data is not None:
        req.add_header("Content-Type", "application/json")
        data = json.dumps(data).encode()
    return urllib.request.urlopen(req, data)


def vault_login(addr, role_id, secret_id):
    resp = _req(
        f"{addr}/v1/auth/approle/login",
        {},
        method="POST",
        data={"role_id": role_id, "secret_id": secret_id},
    )
    return json.load(resp)["auth"]["client_token"]


def vault_read(addr, token, path, key):
    resp = _req(f"{addr}/v1/{path}", {"X-Vault-Token": token})
    return json.load(resp)["data"]["data"][key]


def encrypt(public_key_b64: str, secret_value: str) -> str:
    """libsodium sealed box, which is what GitHub's secrets API requires."""
    pk = public.PublicKey(public_key_b64.encode(), encoding.Base64Encoder())
    return b64encode(public.SealedBox(pk).encrypt(secret_value.encode())).decode()


def main():
    spec = json.load(sys.stdin)

    env = {}
    with open("/etc/vault-approle.env") as f:
        for line in f:
            line = line.strip()
            if "=" in line and not line.startswith("#"):
                k, v = line.split("=", 1)
                env[k] = v

    vault_addr = env["VAULT_ADDR"]
    vault_token = vault_login(vault_addr, env["VAULT_ROLE_ID"], env["VAULT_SECRET_ID"])
    pat = vault_read(vault_addr, vault_token, "kv/data/github/levantine1", "pat")

    gh = {
        "Authorization": f"Bearer {pat}",
        "Accept": "application/vnd.github+json",
    }

    # One public key per repo, not per secret.
    pubkeys = {}
    failures = 0

    for item in spec:
        repo, name = item["repo"], item["secret"]
        try:
            if repo not in pubkeys:
                resp = _req(
                    f"https://api.github.com/repos/{repo}/actions/secrets/public-key", gh
                )
                pubkeys[repo] = json.load(resp)

            value = vault_read(
                vault_addr, vault_token, item["vault_path"], item["vault_key"]
            )

            resp = _req(
                f"https://api.github.com/repos/{repo}/actions/secrets/{name}",
                gh,
                method="PUT",
                data={
                    "encrypted_value": encrypt(pubkeys[repo]["key"], value),
                    "key_id": pubkeys[repo]["key_id"],
                },
            )
            print(f"  {repo} {name}: HTTP {resp.status}")
        except urllib.error.HTTPError as e:
            print(f"  {repo} {name}: FAILED HTTP {e.code} {e.reason}")
            failures += 1
        except Exception as e:  # noqa: BLE001 - report which secret, not the value
            print(f"  {repo} {name}: FAILED {type(e).__name__}")
            failures += 1

    print("DONE" if not failures else f"DONE with {failures} failure(s)")
    return 1 if failures else 0


if __name__ == "__main__":
    sys.exit(main())
