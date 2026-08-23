#!/usr/bin/env python3
"""Manually escalate an incident to Claude.

The automatic path runs through triage.py; this is the on-demand entry point
for two real cases: testing the escalation tier without waiting for something
to break, and an operator deciding that a ticket triage handled conservatively
deserves a proper investigation after all.

Usage:
    escalate.py --ticket 42 [--reason "..."]
    escalate.py --incident 7  [--reason "..."]
    escalate.py --ticket 42 --dry-run     # show what would be sent, call nothing
"""
import argparse
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from incident_agent import claude, collect, config, store, zammad  # noqa: E402


def load_incident(args):
    conn = store.connect()
    try:
        if args.incident:
            row = conn.execute("SELECT * FROM incidents WHERE id=?", (args.incident,)).fetchone()
        else:
            row = conn.execute(
                "SELECT * FROM incidents WHERE ticket_id=? ORDER BY received_at DESC LIMIT 1",
                (args.ticket,),
            ).fetchone()
        return dict(row) if row else None
    finally:
        conn.close()


def main():
    parser = argparse.ArgumentParser(description="Escalate an incident to Claude for investigation.")
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument("--ticket", type=int, help="Zammad ticket id")
    group.add_argument("--incident", type=int, help="Local incident id")
    parser.add_argument("--reason", default="Manually escalated by an operator.")
    parser.add_argument("--dry-run", action="store_true", help="Collect and print, but make no API call")
    parser.add_argument("--no-recollect", action="store_true", help="Skip fresh diagnostics; use the alert context only")
    args = parser.parse_args()

    store.init()
    incident = load_incident(args)
    if not incident:
        # Allow escalating a ticket the agent never saw (e.g. one raised before
        # this was deployed, or created by hand) rather than refusing outright.
        if not args.ticket:
            print("No such incident.", file=sys.stderr)
            return 1
        try:
            ticket = zammad.get_ticket(args.ticket)
        except zammad.ZammadError as e:
            print(f"No local incident and could not read ticket {args.ticket}: {e}", file=sys.stderr)
            return 1
        incident = {
            "id": None,
            "ticket_id": args.ticket,
            "ticket_number": ticket.get("number"),
            "alertname": "ManualEscalation",
            "instance": "",
            "host": None,
            "service": None,
            "severity": "",
            "summary": ticket.get("title", ""),
        }
        print(f"No local incident record; escalating ticket {args.ticket} ({ticket.get('title')}) directly.")

    if args.no_recollect:
        bundle = collect.format_bundle(incident, [], ["(diagnostics not re-collected -- --no-recollect)"])
    else:
        print(f"Collecting diagnostics for {incident['alertname']} on {incident.get('host') or '(unknown host)'}...")
        steps = collect.collect(
            incident["alertname"], incident.get("host"), incident.get("service"), incident.get("instance")
        )
        bundle = collect.format_bundle(incident, steps)

    if args.dry_run:
        print("\n===== BUNDLE THAT WOULD BE SENT =====\n")
        print(bundle)
        remaining, spent = claude.budget_remaining()
        print(f"\nEstimated spend this month: ${spent:.2f}; remaining before soft ceiling: ${remaining:.2f}")
        print(f"Model: {config.ANTHROPIC_MODEL}; key configured: {bool(config.ANTHROPIC_API_KEY)}")
        return 0

    result = claude.escalate(incident, bundle, args.reason)
    body = claude.format_result(result)
    print(body)

    if incident.get("ticket_id"):
        try:
            zammad.add_article(incident["ticket_id"], "AI investigation (Claude, manual)", body, internal=False)
        except zammad.ZammadError as e:
            print(f"(could not post to ticket: {e})", file=sys.stderr)

    if incident.get("id"):
        store.finish(
            incident["id"],
            "escalated_resolved" if result.get("resolved") else "escalated_unresolved",
            result.get("rca", "")[:2000],
            escalated=True,
        )
    return 0


if __name__ == "__main__":
    sys.exit(main())
