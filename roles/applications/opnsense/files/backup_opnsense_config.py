#!/usr/bin/env python3
"""Pull OPNsense's live config.xml and commit it into the ansible repo.

OPNsense is intentionally excluded from the terraform destroy/rebuild cycle
(it's a firewall appliance, not a disposable cloud-init VM) -- this is its
backup path instead: if it's ever lost, restore by hand from the latest
committed roles/applications/opnsense/backups/config.xml.

Auth note: OPNsense's API rejects plain HTTP Basic Auth with the admin
username/password (confirmed empirically -- returns 401), so this logs in
through the same session-cookie flow the web UI uses, then calls the
authenticated backup-download API endpoint with that session.
"""
import os
import re
import subprocess
import sys
import datetime
import requests
import urllib3

urllib3.disable_warnings()

VAULT_ADDR = os.environ["VAULT_ADDR"]
ROLE_ID = os.environ["VAULT_ROLE_ID"]
SECRET_ID = os.environ["VAULT_SECRET_ID"]
REPO_DIR = "/home/automation/ansible"
BACKUP_FILE = os.path.join(REPO_DIR, "roles/applications/opnsense/backups/config.xml")
OPNSENSE_BASE = "https://192.168.1.1"


def vault_login():
    r = requests.post(
        f"{VAULT_ADDR}/v1/auth/approle/login",
        json={"role_id": ROLE_ID, "secret_id": SECRET_ID},
        timeout=10,
    )
    r.raise_for_status()
    return r.json()["auth"]["client_token"]


def vault_read(token, path):
    r = requests.get(
        f"{VAULT_ADDR}/v1/{path}", headers={"X-Vault-Token": token}, timeout=10
    )
    r.raise_for_status()
    return r.json()["data"]["data"]


def opnsense_login(session, username, password):
    r = session.get(OPNSENSE_BASE + "/", timeout=10, verify=False)
    # This OPNsense version randomizes the CSRF hidden field's NAME (not
    # just its value) on every request, so it has to be parsed fresh each
    # time rather than assumed to be "csrf_magic".
    m = re.search(
        r'<input type="hidden" name="([^"]+)" value="([^"]+)" autocomplete="new-password"',
        r.text,
    )
    if not m:
        raise RuntimeError("could not find OPNsense login CSRF field")
    csrf_name, csrf_value = m.group(1), m.group(2)
    r2 = session.post(
        OPNSENSE_BASE + "/",
        data={
            "usernamefld": username,
            "passwordfld": password,
            csrf_name: csrf_value,
            "login": "1",
        },
        timeout=10,
        verify=False,
    )
    if "usernamefld" in r2.text:
        raise RuntimeError("OPNsense login failed")


def main():
    vault_token = vault_login()
    creds = vault_read(vault_token, "kv/data/opnsense/admin")

    session = requests.Session()
    opnsense_login(session, creds["username"], creds["password"])

    r = session.get(
        OPNSENSE_BASE + "/api/core/backup/download/this", timeout=20, verify=False
    )
    r.raise_for_status()
    if r.content[:5] != b"<?xml":
        print("unexpected response, not an XML config export", file=sys.stderr)
        sys.exit(1)

    os.makedirs(os.path.dirname(BACKUP_FILE), exist_ok=True)
    with open(BACKUP_FILE, "wb") as f:
        f.write(r.content)

    subprocess.run(["git", "-C", REPO_DIR, "pull", "--rebase"], check=True)
    subprocess.run(
        ["git", "-C", REPO_DIR, "add", "roles/applications/opnsense/backups/config.xml"],
        check=True,
    )
    diff = subprocess.run(["git", "-C", REPO_DIR, "diff", "--cached", "--quiet"])
    if diff.returncode == 0:
        print("no changes to opnsense config, nothing to commit")
        return

    timestamp = datetime.datetime.utcnow().strftime("%Y-%m-%d %H:%M UTC")
    subprocess.run(
        [
            "git",
            "-C",
            REPO_DIR,
            "commit",
            "-m",
            f"opnsense: automated config backup ({timestamp})",
        ],
        check=True,
    )
    subprocess.run(["git", "-C", REPO_DIR, "push"], check=True)
    print(f"committed and pushed updated config.xml ({timestamp})")


if __name__ == "__main__":
    main()
