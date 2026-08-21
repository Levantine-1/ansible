#!/usr/bin/env python3
"""Push the latest committed config.xml back into a freshly-installed
OPNsense and reload it.

Companion to backup_opnsense_config.py -- for the disaster-recovery
scenario where OPNsense's VM was lost and rebuilt: terraform recreates the
VM shell with the installer ISO attached, an operator completes the
interactive install by hand (no unattended-install mechanism exists for
OPNsense), and this script is the last step, restoring the fleet's actual
firewall/interface/DHCP/Unbound-DNS-override config from source control
instead of re-entering it by hand.

Auth uses the same session-cookie flow as the backup script (OPNsense's
API rejects plain HTTP Basic Auth with the admin username/password).

This is a manual, by-hand recovery step, not something scheduled -- run it
once after the fresh OPNsense install has at least LAN connectivity and a
temporary admin password set during the installer.

Usage:
    VAULT_ADDR=http://vault.internal.levantine.io:8200 \\
    VAULT_ROLE_ID=... VAULT_SECRET_ID=... \\
    ./restore_opnsense_config.py [path/to/config.xml]

If no path is given, defaults to the committed backup file in this repo.
"""
import os
import re
import sys
import requests
import urllib3

urllib3.disable_warnings()

VAULT_ADDR = os.environ["VAULT_ADDR"]
ROLE_ID = os.environ["VAULT_ROLE_ID"]
SECRET_ID = os.environ["VAULT_SECRET_ID"]
OPNSENSE_BASE = "https://192.168.1.1"
DEFAULT_CONFIG_FILE = os.path.join(
    os.path.dirname(os.path.abspath(__file__)), "..", "backups", "config.xml"
)


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
    config_file = sys.argv[1] if len(sys.argv) > 1 else DEFAULT_CONFIG_FILE
    if not os.path.exists(config_file):
        print(f"config file not found: {config_file}", file=sys.stderr)
        sys.exit(1)
    with open(config_file, "rb") as f:
        config_xml = f.read()
    if config_xml[:5] != b"<?xml":
        print("refusing to restore: file doesn't look like an XML config export", file=sys.stderr)
        sys.exit(1)

    vault_token = vault_login()
    creds = vault_read(vault_token, "kv/data/opnsense/admin")

    session = requests.Session()
    opnsense_login(session, creds["username"], creds["password"])

    print(f"restoring config from {config_file} ...")
    r = session.post(
        OPNSENSE_BASE + "/api/core/backup/restore",
        files={"restore_config": ("config.xml", config_xml, "text/xml")},
        data={"restore_area": "", "decrypt_password": ""},
        timeout=30,
        verify=False,
    )
    r.raise_for_status()
    print(r.text)
    print(
        "\nrestore request submitted -- OPNsense typically reboots itself to "
        "apply. Verify by reconnecting to the UI/SSH after it comes back up. "
        "NOTE: the exact restore endpoint/payload shape above is unverified "
        "against a live install as of this writing -- confirm against the "
        "OPNsense API docs for the version actually installed before "
        "relying on this in a real recovery."
    )


if __name__ == "__main__":
    main()
