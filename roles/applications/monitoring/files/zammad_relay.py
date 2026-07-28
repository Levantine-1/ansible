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
    if not result:
        return None
    for ticket_id in result.get("tickets", []):
        ticket = zammad_request("GET", f"/api/v1/tickets/{ticket_id}")
        if ticket and ticket.get("state_id") not in (4, 5):  # not closed/merged
            return ticket
    return None


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
        zammad_request(
            "POST",
            "/api/v1/tickets",
            {
                "title": f"{fingerprint_tag} {alertname} - {instance}",
                "group": ZAMMAD_GROUP,
                "customer": CUSTOMER_EMAIL,
                "article": {
                    "subject": alertname,
                    "body": summary,
                    "type": "note",
                    "internal": False,
                },
            },
        )
    elif status == "resolved" and existing:
        zammad_request(
            "PUT",
            f"/api/v1/tickets/{existing['id']}",
            {
                "state": "closed",
                "article": {
                    "subject": "Alert resolved",
                    "body": f"Alertmanager reports this alert as resolved: {summary}",
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
