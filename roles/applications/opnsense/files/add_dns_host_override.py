#!/usr/bin/env python3
"""Add (or update) an Unbound host override in OPNsense, i.e. give a VM its
internal DNS name.

Every VM in this fleet resolves as <name>.internal.levantine.io through an
Unbound Host Override on OPNsense -- one entry per host, created through the
web UI by hand. The `dhcpd` static mappings still present in OPNsense's config
are stale ESXi-era leftovers (all VMware `00:0c:29:*` MACs) and are NOT what
resolves anything today, so adding a static mapping instead of an override
would look right and do nothing.

Doing it by hand is why a new VM can end up with no DNS record at all, which
is not a cosmetic problem: Prometheus runs containerised on `service` and
would never scrape an unresolvable target, leaving a permanently firing
InstanceDown -- exactly the always-on alert that hides real ones.

Auth mirrors backup_opnsense_config.py: OPNsense rejects HTTP Basic auth with
the admin username/password (that only works for API key/secret pairs, which
this deployment does not have), so this drives the same session-cookie login
the web UI uses.

Idempotent: an existing override with the same hostname+domain is updated in
place if the address differs, and left alone if it already matches.

  export VAULT_ADDR=http://vault.internal.levantine.io:8200
  source /etc/vault-approle.env
  ./add_dns_host_override.py incident-agent 192.168.1.51
"""
import argparse
import os
import re
import sys

import requests
import urllib3

urllib3.disable_warnings()

OPNSENSE_BASE = "https://192.168.1.1"
DEFAULT_DOMAIN = "internal.levantine.io"


def vault_login(addr, role_id, secret_id):
    r = requests.post(
        addr + "/v1/auth/approle/login",
        json={"role_id": role_id, "secret_id": secret_id},
        timeout=10,
    )
    r.raise_for_status()
    return r.json()["auth"]["client_token"]


def vault_read(addr, token, path):
    r = requests.get(addr + "/v1/" + path, headers={"X-Vault-Token": token}, timeout=10)
    r.raise_for_status()
    return r.json()["data"]["data"]


def opnsense_login(session, username, password):
    r = session.get(OPNSENSE_BASE + "/", timeout=10, verify=False)
    # The CSRF hidden field's NAME (not just its value) is randomized on every
    # request by this OPNsense version, so it must be parsed fresh rather than
    # assumed to be "csrf_magic".
    m = re.search(
        r'<input type="hidden" name="([^"]+)" value="([^"]+)" autocomplete="new-password"',
        r.text,
    )
    if not m:
        raise RuntimeError("could not find OPNsense login CSRF field")
    r2 = session.post(
        OPNSENSE_BASE + "/",
        data={
            "usernamefld": username,
            "passwordfld": password,
            m.group(1): m.group(2),
            "login": "1",
        },
        timeout=10,
        verify=False,
    )
    if "usernamefld" in r2.text:
        raise RuntimeError("OPNsense login failed")


def get_csrf_token(session):
    """Pull the CSRF token a session-authenticated POST needs.

    GETs against /api/ work with just the session cookie, but POSTs return 403
    without this. OPNsense does not expose it as a meta tag or hidden input on
    these pages -- the only place it appears is inlined into the jQuery
    ajaxSetup block that the UI uses to set the header on its own requests, so
    that is what gets scraped.
    """
    page = session.get(OPNSENSE_BASE + "/ui/unbound/overview", timeout=15, verify=False)
    page.raise_for_status()
    m = re.search(r'setRequestHeader\(\s*"X-CSRFToken"\s*,\s*"([^"]+)"', page.text)
    if not m:
        raise RuntimeError("could not find the X-CSRFToken value in the UI page")
    return m.group(1)


def api(session, method, path, payload=None, csrf=None):
    url = OPNSENSE_BASE + path
    kwargs = {"timeout": 20, "verify": False}
    if payload is not None:
        kwargs["json"] = payload
    if csrf:
        kwargs["headers"] = {"X-CSRFToken": csrf}
    r = session.request(method, url, **kwargs)
    r.raise_for_status()
    try:
        return r.json()
    except ValueError:
        raise RuntimeError(f"{path} returned non-JSON: {r.text[:200]}")


def find_existing(session, hostname, domain):
    result = api(session, "GET", "/api/unbound/settings/searchHostOverride")
    for row in result.get("rows", []):
        if row.get("hostname") == hostname and row.get("domain") == domain:
            return row
    return None


def main():
    p = argparse.ArgumentParser(description="Add an Unbound host override to OPNsense.")
    p.add_argument("hostname")
    p.add_argument("address")
    p.add_argument("--domain", default=DEFAULT_DOMAIN)
    p.add_argument("--description", default="")
    p.add_argument("--dry-run", action="store_true")
    args = p.parse_args()

    vault_addr = os.environ.get("VAULT_ADDR", "http://vault.internal.levantine.io:8200")
    try:
        role_id = os.environ["VAULT_ROLE_ID"]
        secret_id = os.environ["VAULT_SECRET_ID"]
    except KeyError:
        print("source /etc/vault-approle.env first", file=sys.stderr)
        return 1

    creds = vault_read(vault_addr, vault_login(vault_addr, role_id, secret_id), "kv/data/opnsense/admin")

    session = requests.Session()
    opnsense_login(session, creds["username"], creds["password"])

    existing = find_existing(session, args.hostname, args.domain)
    fqdn = f"{args.hostname}.{args.domain}"

    if existing and existing.get("server") == args.address:
        print(f"{fqdn} -> {args.address} already present, nothing to do")
        return 0

    payload = {
        "host": {
            "enabled": "1",
            "hostname": args.hostname,
            "domain": args.domain,
            "rr": "A",
            "server": args.address,
            "description": args.description or f"{args.hostname} VM",
        }
    }

    if args.dry_run:
        action = "update" if existing else "add"
        print(f"[dry-run] would {action} {fqdn} -> {args.address}")
        return 0

    csrf = get_csrf_token(session)

    if existing:
        print(f"updating {fqdn}: {existing.get('server')} -> {args.address}")
        result = api(
            session, "POST", f"/api/unbound/settings/setHostOverride/{existing['uuid']}", payload, csrf
        )
    else:
        print(f"adding {fqdn} -> {args.address}")
        result = api(session, "POST", "/api/unbound/settings/addHostOverride", payload, csrf)

    if result.get("result") != "saved":
        raise RuntimeError(f"unexpected API result: {result}")

    # Settings are staged until Unbound is reconfigured -- without this the
    # override is in the config but not being served, which looks like it
    # silently did nothing.
    print("reconfiguring unbound...")
    reconf = api(session, "POST", "/api/unbound/service/reconfigure", {}, csrf)
    print("reconfigure:", reconf)
    return 0


if __name__ == "__main__":
    sys.exit(main())
