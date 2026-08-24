#!/usr/bin/env python3
"""HTTP intake for incident handoffs from zammad_relay.py on `service`.

Deliberately does nothing but validate, enqueue and return 200. The relay is a
synchronous responder to Alertmanager's webhook: if triage ran inline here, the
webhook would block for minutes (five-minute grace period, SSH collection, CPU
inference), Alertmanager would time out and retry, and the retry would produce
a duplicate investigation -- and potentially a duplicate restart. Intake must
therefore be fast and unconditional; the work happens in triage.py.

Separate process from the worker for the same reason: a wedged investigation
must not be able to block new alerts from being recorded.

On authentication, or the deliberate lack of it: this port is unauthenticated
and reachable from the LAN, but a forged handoff cannot by itself cause the
agent to touch anything. After the grace period the worker independently asks
Alertmanager whether the alert is actually firing (triage.py), and an invented
alert is not there -- it is recorded as self-resolved and nothing is acted on.
That cross-check against the real monitoring system, not the transport, is what
makes the handoff trustworthy, which is also why it must never be weakened into
"assume firing if Alertmanager cannot be reached".

As of 2026-08-24 this also backs the ops-dashboard control panel on `service`:
GET /status (worker online + what it's currently processing, if anything),
GET /toggles and POST /toggles (the Claude/local-LLM tier switches). These
read/write store.py directly rather than going through triage.py, which has
no HTTP surface of its own -- this stays the one process on this host reached
cross-host, same as it always was for alert intake.
"""
import fcntl
import json
import os
import sys
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from incident_agent import config, store  # noqa: E402
import triage  # noqa: E402 -- for _WORKER_LOCK_PATH only, to derive worker liveness


def log(message):
    print(f"[listener] {time.strftime('%FT%TZ', time.gmtime())} {message}", flush=True)


def _worker_online():
    """Whether the triage worker process is currently running -- derived
    from the SAME flock() triage.py's main() holds for its whole lifetime
    (see triage._acquire_singleton_lock's docstring), not a separate
    heartbeat. Opening with "w" truncates the file, which is harmless here:
    flock() locks are tied to the inode/open-file-description, not file
    content, so truncating it does not disturb a lock another process
    already holds on it."""
    try:
        with open(triage._WORKER_LOCK_PATH, "w") as fh:
            try:
                fcntl.flock(fh, fcntl.LOCK_EX | fcntl.LOCK_NB)
            except OSError:
                return True  # already held elsewhere -- worker is running
            fcntl.flock(fh, fcntl.LOCK_UN)
            return False  # we could acquire it ourselves -- nobody's running
    except OSError:
        # Lock file's directory doesn't exist yet -- worker has never started.
        return False


def _status_payload():
    processing = store.currently_processing()
    return {
        "worker_online": _worker_online(),
        "processing": processing,
    }


def accept(payload):
    """Record one handoff. Returns a short status string for the log."""
    alert = payload.get("alert") or {}
    labels = alert.get("labels") or {}
    alertname = labels.get("alertname", "UnknownAlert")

    host, service = config.resolve_target(alertname, labels)

    # Grace period is stored as a timestamp rather than implemented as a sleep:
    # a worker blocking for five minutes would hold one of only two
    # concurrency slots doing nothing, so under a burst the queue would stall
    # behind idle waits.
    not_before = time.time() + config.grace_seconds()

    incident_id, created = store.enqueue(
        alert=alert,
        ticket_id=payload.get("ticket_id"),
        ticket_number=payload.get("ticket_number"),
        host=host,
        service=service,
        not_before=not_before,
    )
    if not created:
        return f"duplicate of incident {incident_id} ({alertname}) -- already queued or running"
    return f"queued incident {incident_id}: {alertname} host={host or '?'} service={service or '-'}"


class Handler(BaseHTTPRequestHandler):
    def log_message(self, fmt, *args):
        log(f"{self.address_string()} - {fmt % args}")

    def _write_json(self, obj, status=200):
        body = json.dumps(obj).encode()
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.end_headers()
        self.wfile.write(body)

    def do_POST(self):
        try:
            length = int(self.headers.get("Content-Length", 0))
            payload = json.loads(self.rfile.read(length) or b"{}")
        except (ValueError, TypeError) as e:
            self.send_response(400)
            self.end_headers()
            self.wfile.write(f"bad request: {e}".encode())
            return

        if self.path == "/toggles":
            # Dashboard control-panel writes (2026-08-24). Same no-auth
            # convention as everything else on this port (see this file's
            # own docstring) -- a forged toggle flip is a real behavior
            # change, unlike a forged alert handoff, but this dashboard and
            # everything reaching it is LAN-only by the same convention the
            # rest of this repo already relies on.
            try:
                for name in ("claude_enabled", "local_llm_enabled"):
                    if name in payload:
                        store.set_toggle(name, bool(payload[name]))
                self._write_json(store.get_toggles())
            except Exception as e:  # noqa: BLE001
                log(f"ERROR setting toggles: {type(e).__name__}: {e}")
                self._write_json({"error": str(e)}, status=500)
            return

        try:
            status = accept(payload)
            log(status)
            self.send_response(200)
            self.end_headers()
            self.wfile.write(status.encode())
        except Exception as e:  # noqa: BLE001
            # Still answer 200: the relay treats a failure here as non-fatal so
            # ticket creation is never affected, and a 500 would only trigger
            # Alertmanager retries that cannot help.
            log(f"ERROR accepting handoff: {type(e).__name__}: {e}")
            self.send_response(200)
            self.end_headers()
            self.wfile.write(b"accepted-with-error")

    def do_GET(self):
        if self.path == "/status":
            self._write_json(_status_payload())
            return
        if self.path == "/toggles":
            self._write_json(store.get_toggles())
            return
        # Every other path (including the bare "/" the ansible deploy and
        # zammad_relay's own reachability check both poll) -- unchanged
        # shallow liveness check, deliberately not deeper than "is this HTTP
        # server thread accepting connections."
        self.send_response(200)
        self.end_headers()
        self.wfile.write(b"ok")


def main():
    store.init()
    server = ThreadingHTTPServer((config.LISTEN_HOST, config.LISTEN_PORT), Handler)
    log(f"listening on {config.LISTEN_HOST}:{config.LISTEN_PORT}")
    server.serve_forever()


if __name__ == "__main__":
    main()
