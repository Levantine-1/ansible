#!/usr/bin/env python3
"""Relay Alertmanager webhook notifications into Zammad tickets.

Listens for Alertmanager's webhook_configs POST payload. Each alert's
fingerprint is embedded in the ticket title so re-notifications of an
already-firing alert don't create duplicate tickets, and a resolved
notification closes the matching open ticket instead of creating a new
one.

Config via environment (see /etc/zammad-relay.env):
  ZAMMAD_URL        e.g. http://localhost:8080
  ZAMMAD_API_TOKEN
  ZAMMAD_GROUP      default: Users
  LISTEN_PORT       default: 9099
  INCIDENT_AGENT_URL  optional; if set, newly created tickets are handed off
                      to the incident agent for automated triage
"""
import json
import os
import urllib.request
import urllib.error
import urllib.parse
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

ZAMMAD_URL = os.environ["ZAMMAD_URL"].rstrip("/")
ZAMMAD_API_TOKEN = os.environ["ZAMMAD_API_TOKEN"]
ZAMMAD_GROUP = os.environ.get("ZAMMAD_GROUP", "Users")
LISTEN_PORT = int(os.environ.get("LISTEN_PORT", "9099"))
CUSTOMER_EMAIL = os.environ.get("ZAMMAD_CUSTOMER_EMAIL", "zammad-admin@levantine.io")
# Empty disables the handoff entirely, which is the correct behaviour before
# the incident agent exists (or if it is deliberately taken out of service).
INCIDENT_AGENT_URL = os.environ.get("INCIDENT_AGENT_URL", "").rstrip("/")


def zammad_request(method, path, data=None):
    url = f"{ZAMMAD_URL}{path}"
    body = json.dumps(data).encode() if data is not None else None
    req = urllib.request.Request(url, data=body, method=method)
    req.add_header("Authorization", f"Token token={ZAMMAD_API_TOKEN}")
    req.add_header("Content-Type", "application/json")
    req.add_header("Accept", "application/json")
    with urllib.request.urlopen(req, timeout=10) as resp:
        raw = resp.read()
        return json.loads(raw) if raw else None


def find_open_ticket(fingerprint_tag):
    result = zammad_request(
        "GET",
        f"/api/v1/tickets/search?query={urllib.parse.quote(fingerprint_tag)}&limit=5",
    )
    # /api/v1/tickets/search returns a bare list of full ticket objects
    # (not {"tickets": [...]}), loosely matched -- confirm the fingerprint
    # tag is actually a prefix of the title rather than trusting the
    # search match alone.
    if not result:
        return None
    for ticket in result:
        if ticket.get("title", "").startswith(fingerprint_tag) and ticket.get("state_id") not in (4, 5):
            return ticket
    return None


def notify_incident_agent(alert, ticket):
    """Hand a newly created ticket to the incident agent for triage.

    Best-effort by design. Ticket creation is the job that must not fail, and
    the agent is an optional consumer sitting on a different host -- so every
    failure here (agent down, VM rebuilt, network blip, DNS) is swallowed and
    logged. The worst case is that a ticket simply waits for a human, which is
    exactly how this worked before the agent existed.

    Deliberately short-timeout and fire-and-forget: the agent's listener only
    enqueues and returns, and Alertmanager is still waiting on this webhook.
    Anything slower here would risk an Alertmanager timeout and retry, which
    would duplicate the alert rather than help.
    """
    if not INCIDENT_AGENT_URL or not ticket:
        return
    try:
        payload = json.dumps(
            {
                "alert": alert,
                "ticket_id": ticket.get("id"),
                "ticket_number": ticket.get("number"),
            }
        ).encode()
        req = urllib.request.Request(f"{INCIDENT_AGENT_URL}/alert", data=payload, method="POST")
        req.add_header("Content-Type", "application/json")
        with urllib.request.urlopen(req, timeout=5) as resp:
            print(f"Handed ticket {ticket.get('number')} to incident agent: {resp.status}")
    except Exception as e:  # noqa: BLE001 -- must never affect ticketing
        print(f"Incident agent handoff failed (ticket still created): {type(e).__name__}: {e}")


def handle_alert(alert):
    fingerprint = alert.get("fingerprint", "unknown")
    fingerprint_tag = f"[{fingerprint[:12]}]"
    labels = alert.get("labels", {})
    annotations = alert.get("annotations", {})
    alertname = labels.get("alertname", "UnknownAlert")
    instance = labels.get("instance", "unknown-instance")
    summary = annotations.get("summary", f"{alertname} on {instance}")
    status = alert.get("status", "firing")

    existing = find_open_ticket(fingerprint_tag)

    if status == "firing":
        if existing:
            return  # already has an open ticket, don't duplicate
        ticket = zammad_request(
            "POST",
            "/api/v1/tickets",
            {
                "title": f"{fingerprint_tag} {alertname} - {instance}",
                "group": ZAMMAD_GROUP,
                "customer": CUSTOMER_EMAIL,
                "article": {
                    "subject": alertname,
                    # Banner matches incident-agent's own convention (see
                    # incident_agent/zammad.py's _signed()) -- this relay has
                    # no model/Claude involvement, always "script", but
                    # without it there'd be no way to tell which of the
                    # several scripts/tiers posting to the same automation
                    # user wrote a given comment.
                    "body": f"*Comment generated by: script*\n\n{summary}",
                    "type": "note",
                    "internal": False,
                },
            },
        )
        # Only on genuine creation, never on the dedup path above: a
        # re-notification of an alert that already has an open ticket must not
        # kick off a second investigation of the same problem.
        notify_incident_agent(alert, ticket)
    elif status == "resolved" and existing:
        zammad_request(
            "PUT",
            f"/api/v1/tickets/{existing['id']}",
            {
                "state": "closed",
                "article": {
                    "subject": "Alert resolved",
                    "body": f"*Comment generated by: script*\n\nAlertmanager reports this alert as resolved: {summary}",
                    "type": "note",
                    "internal": False,
                },
            },
        )


class Handler(BaseHTTPRequestHandler):
    def log_message(self, fmt, *args):
        print(f"{self.address_string()} - {fmt % args}")

    def do_POST(self):
        length = int(self.headers.get("Content-Length", 0))
        body = self.rfile.read(length)
        try:
            payload = json.loads(body)
            for alert in payload.get("alerts", []):
                try:
                    handle_alert(alert)
                except (urllib.error.HTTPError, urllib.error.URLError) as e:
                    print(f"Failed to relay alert {alert.get('fingerprint')}: {e}")
            self.send_response(200)
            self.end_headers()
            self.wfile.write(b"ok")
        except Exception as e:
            print(f"Error handling webhook: {e}")
            self.send_response(500)
            self.end_headers()
            self.wfile.write(str(e).encode())

    def do_GET(self):
        self.send_response(200)
        self.end_headers()
        self.wfile.write(b"ok")


if __name__ == "__main__":
    server = ThreadingHTTPServer(("127.0.0.1", LISTEN_PORT), Handler)
    print(f"zammad-relay listening on 127.0.0.1:{LISTEN_PORT}")
    server.serve_forever()
