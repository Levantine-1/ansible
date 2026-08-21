#!/usr/bin/env python3
"""Restore every secret from the latest committed backup into a fresh,
empty, unsealed Vault.

Companion to backup_vault_secrets.py -- for the disaster-recovery
scenario where Vault's own VM (and its local file-backend storage) was
lost. This is a manual, by-hand recovery step, not something scheduled:
run it once, right after a freshly-installed Vault has been initialized
and unsealed with the operator's own retained unseal keys.

Deliberately does NOT use AppRole login like the backup script does --
in a from-scratch Vault, AppRole auth isn't configured yet (it's one of
the things being restored), so this needs the root token from the fresh
`vault operator init` output, passed directly.

Usage:
    VAULT_ADDR=http://vault.internal.levantine.io:8200 \\
    VAULT_TOKEN=<root token from `vault operator init`> \\
    ./restore_vault_secrets.py [path/to/secrets.json.vault]

If no path is given, defaults to the committed backup file in this repo.
"""
import json
import os
import subprocess
import sys
import requests

VAULT_ADDR = os.environ["VAULT_ADDR"]
VAULT_TOKEN = os.environ["VAULT_TOKEN"]
VAULT_PASSWORD_FILE = os.environ.get("ANSIBLE_VAULT_PASSWORD_FILE", "/etc/ansible-vault-password.txt")
DEFAULT_BACKUP_FILE = os.path.join(
    os.path.dirname(os.path.abspath(__file__)), "..", "backups", "secrets.json.vault"
)


def ensure_kv_mount(mount):
    r = requests.get(
        f"{VAULT_ADDR}/v1/sys/mounts",
        headers={"X-Vault-Token": VAULT_TOKEN}, timeout=10,
    )
    r.raise_for_status()
    if f"{mount}/" in r.json():
        print(f"kv mount '{mount}/' already exists, leaving as-is")
        return
    print(f"enabling kv-v2 mount at '{mount}/'")
    r = requests.post(
        f"{VAULT_ADDR}/v1/sys/mounts/{mount}",
        headers={"X-Vault-Token": VAULT_TOKEN},
        json={"type": "kv", "options": {"version": "2"}},
        timeout=10,
    )
    r.raise_for_status()


def vault_write(path, mount, data):
    r = requests.post(
        f"{VAULT_ADDR}/v1/{mount}/data/{path}",
        headers={"X-Vault-Token": VAULT_TOKEN},
        json={"data": data},
        timeout=10,
    )
    r.raise_for_status()


def main():
    backup_file = sys.argv[1] if len(sys.argv) > 1 else DEFAULT_BACKUP_FILE
    if not os.path.exists(backup_file):
        print(f"backup file not found: {backup_file}", file=sys.stderr)
        sys.exit(1)

    decrypted = subprocess.run(
        [
            "ansible-vault", "decrypt",
            "--vault-password-file", VAULT_PASSWORD_FILE,
            "--output", "-",
            backup_file,
        ],
        capture_output=True, check=True,
    ).stdout
    dump = json.loads(decrypted)

    mount = dump["kv_mount"]
    secrets = dump["secrets"]
    print(f"restoring {len(secrets)} secret paths from backup dated {dump['exported_at']}")

    ensure_kv_mount(mount)

    failed = []
    for path, data in secrets.items():
        try:
            vault_write(path, mount, data)
            print(f"  restored {mount}/{path}")
        except requests.HTTPError as e:
            print(f"  FAILED {mount}/{path}: {e}", file=sys.stderr)
            failed.append(path)

    if failed:
        print(f"\n{len(failed)} path(s) failed to restore:", file=sys.stderr)
        for path in failed:
            print(f"  {path}", file=sys.stderr)
        sys.exit(1)

    print("\nall secrets restored successfully")


if __name__ == "__main__":
    main()
