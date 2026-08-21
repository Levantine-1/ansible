#!/usr/bin/env python3
"""Dump every secret in Vault's kv/ mount and commit an ansible-vault
encrypted copy into the ansible repo.

Vault's own storage is local `file` backend on a single VM with no
snapshot/replication -- losing that VM loses every secret in the fleet
permanently (DB passwords, AWS keys, GitHub PATs), not just "needs
re-unsealing". This is that VM's safety net, mirroring the pattern already
used for OPNsense's config.xml backup (same systemd-timer convention, same
git-credential-vault-github.sh helper, same "don't fail on an unrelated
dirty tree" git handling).

The dump is piped straight into `ansible-vault encrypt` via stdin -- it
never touches disk in plaintext. Restoring is `restore_vault_secrets.py`
in this same directory.
"""
import json
import os
import subprocess
import sys
import datetime
import requests

VAULT_ADDR = os.environ["VAULT_ADDR"]
ROLE_ID = os.environ["VAULT_ROLE_ID"]
SECRET_ID = os.environ["VAULT_SECRET_ID"]
REPO_DIR = "/home/automation/ansible"
BACKUP_FILE = os.path.join(REPO_DIR, "roles/applications/vault_backup/backups/secrets.json.vault")
VAULT_PASSWORD_FILE = "/etc/ansible-vault-password.txt"
KV_MOUNT = "kv"


def vault_login():
    r = requests.post(
        f"{VAULT_ADDR}/v1/auth/approle/login",
        json={"role_id": ROLE_ID, "secret_id": SECRET_ID},
        timeout=10,
    )
    r.raise_for_status()
    return r.json()["auth"]["client_token"]


def vault_list(token, path):
    r = requests.request(
        "LIST", f"{VAULT_ADDR}/v1/{KV_MOUNT}/metadata/{path}",
        headers={"X-Vault-Token": token}, timeout=10,
    )
    if r.status_code == 404:
        return []
    r.raise_for_status()
    return r.json()["data"]["keys"]


def vault_read(token, path):
    r = requests.get(
        f"{VAULT_ADDR}/v1/{KV_MOUNT}/data/{path}",
        headers={"X-Vault-Token": token}, timeout=10,
    )
    r.raise_for_status()
    return r.json()["data"]["data"]


def walk(token, path=""):
    """Recursively walk every KV path, returning {full_path: secret_dict}."""
    secrets = {}
    for key in vault_list(token, path):
        full_path = f"{path}{key}"
        if key.endswith("/"):
            secrets.update(walk(token, full_path))
        else:
            secrets[full_path] = vault_read(token, full_path)
    return secrets


def main():
    token = vault_login()
    print("walking kv/ ...", file=sys.stderr)
    secrets = walk(token)
    print(f"found {len(secrets)} secret paths", file=sys.stderr)

    dump = json.dumps(
        {
            "exported_at": datetime.datetime.utcnow().strftime("%Y-%m-%dT%H:%M:%SZ"),
            "kv_mount": KV_MOUNT,
            "secrets": secrets,
        },
        indent=2,
        sort_keys=True,
    )

    os.makedirs(os.path.dirname(BACKUP_FILE), exist_ok=True)
    # Encrypt straight from stdin -- the plaintext dump only ever exists in
    # this process's memory and the pipe to ansible-vault, never on disk.
    subprocess.run(
        [
            "ansible-vault", "encrypt",
            "--vault-password-file", VAULT_PASSWORD_FILE,
            "--output", BACKUP_FILE,
            "-",
        ],
        input=dump.encode(),
        check=True,
    )

    # Same rationale as the OPNsense backup job for the git handling here:
    # this job only owns one file, so a dirty unrelated working tree
    # elsewhere shouldn't fail a scheduled run. Only fall back to
    # pull+rebase if the push is actually rejected for being behind.
    subprocess.run(
        ["git", "-C", REPO_DIR, "add", "roles/applications/vault_backup/backups/secrets.json.vault"],
        check=True,
    )
    diff = subprocess.run(["git", "-C", REPO_DIR, "diff", "--cached", "--quiet"])
    if diff.returncode == 0:
        print("no changes to vault secrets, nothing to commit")
        return

    timestamp = datetime.datetime.utcnow().strftime("%Y-%m-%d %H:%M UTC")
    subprocess.run(
        [
            "git", "-C", REPO_DIR, "commit", "-m",
            f"vault: automated secrets backup ({timestamp})",
        ],
        check=True,
    )
    push = subprocess.run(["git", "-C", REPO_DIR, "push"])
    if push.returncode != 0:
        subprocess.run(
            ["git", "-C", REPO_DIR, "pull", "--rebase", "--autostash"], check=True
        )
        subprocess.run(["git", "-C", REPO_DIR, "push"], check=True)
    print(f"committed and pushed updated secrets dump ({timestamp})")


if __name__ == "__main__":
    main()
