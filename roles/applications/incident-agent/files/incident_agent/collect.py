"""Run the diagnostic plan from diagnostics.yml and produce a bundle.

The bundle is the single artifact everything downstream consumes: it is what
gets written to the ticket, what the local model summarises, and what Sonnet
receives as starting context so it is not rediscovering basics at API prices.
"""
import time

from . import config, observability, remote, store


def _truncate(text, limit):
    if text is None:
        return "(none)"
    text = str(text)
    if len(text) <= limit:
        return text
    # Mark the cut explicitly. Silent truncation reads as "that is all there
    # was", which is a materially wrong impression to give a human or a model
    # trying to work out why something failed.
    return text[:limit] + f"\n... [truncated, {len(text) - limit} more chars]"


def _substitute(text, ctx):
    if not text:
        return text
    for key, value in ctx.items():
        text = text.replace(f"${key}", str(value if value is not None else ""))
    return text


def history_notes(incident):
    """Prior incidents and automated actions on this host.

    Included in every bundle so the escalation tier starts knowing whether this
    is a first occurrence or the fifth this week, and what has already been
    tried -- questions it would otherwise spend paid turns rediscovering, and
    which change the diagnosis substantially ("restarting fixed it three times
    already" is a different problem from "this has never happened before").
    """
    host = incident.get("host")
    if not host:
        return []
    incidents, actions = store.host_history(host, 7 * 86400, incident["id"])
    if not incidents and not actions:
        return [f"History: no other recorded incidents on {host} in the last 7 days (first occurrence)."]

    lines = [f"History for {host} over the last 7 days:"]
    if incidents:
        for row in incidents[:8]:
            when = time.strftime("%a %H:%M", time.localtime(row["received_at"] or 0))
            lines.append(
                f"  - {when} {row['alertname']} (ticket #{row['ticket_number']}) -> {row['outcome'] or 'unfinished'}"
            )
    else:
        lines.append("  - no other incidents")
    if actions:
        lines.append("  Automated actions already taken on this host:")
        for row in actions[:8]:
            when = time.strftime("%a %H:%M", time.localtime(row["ts"] or 0))
            lines.append(
                f"  - {when} {row['action']} {row['target'] or ''} ({row['alertname']}) -> {row['result']}"
            )
    return lines


def collect(alertname, host, service, instance, vm_id=None):
    """Execute the collection plan for an alert. Returns a list of step dicts."""
    diag = config.diagnostics()
    defaults = diag.get("defaults", {})
    plan = (diag.get("alerts") or {}).get(alertname) or diag.get("fallback") or {"steps": []}

    max_chars = defaults.get("max_output_chars", 4000)
    ssh_timeout = defaults.get("ssh_timeout_seconds", 20)
    loki_limit = defaults.get("loki_limit", 200)
    loki_lookback = defaults.get("loki_lookback_minutes", 30)

    pol = config.host_policy(host) if host else {}
    address = remote.host_address(host) if host else None
    ctx = {
        "HOST": host or "",
        "INSTANCE": instance or "",
        "SERVICE": service or "",
        "VMID": pol.get("vm_id") or vm_id or "",
        "FQDN": address or "",
    }

    results = []
    for step in plan.get("steps", []):
        source = step.get("source")
        description = step.get("description", source)
        started = time.time()
        ok, output = False, "(not run)"

        try:
            if source == "loki":
                query = _substitute(step.get("query", ""), ctx)
                output = observability.loki_query(query, loki_lookback, loki_limit)
                ok = True
            elif source == "prometheus":
                output = observability.prometheus_query(_substitute(step.get("query", ""), ctx))
                ok = True
            elif source == "ssh":
                if not address:
                    ok, output = False, "(no address for host)"
                else:
                    ok, output = remote.ssh(address, _substitute(step.get("command", ""), ctx), timeout=ssh_timeout)
            elif source == "hypervisor":
                command = _substitute(step.get("command", ""), ctx)
                if command.startswith("qm "):
                    ok, output = remote.qm(host, command[3:], timeout=ssh_timeout)
                else:
                    hv = remote.hypervisor_address(host)
                    ok, output = (False, "(no hypervisor recorded)") if not hv else remote.ssh(hv, command, timeout=ssh_timeout)
            elif source == "http_probe":
                ok, output = observability.http_probe(_substitute(step.get("target", ""), ctx))
            else:
                ok, output = False, f"(unknown diagnostic source '{source}')"
        except Exception as e:  # noqa: BLE001
            # One failing step must never abort collection -- a partial bundle
            # is far more useful than none, and which step failed is itself a
            # finding (e.g. Loki unreachable means `service` is affected too).
            ok, output = False, f"({type(e).__name__}: {e})"

        results.append(
            {
                "description": description,
                "source": source,
                "ok": ok,
                "output": _truncate(output, max_chars),
                "seconds": round(time.time() - started, 2),
            }
        )

    return results


def format_bundle(incident, steps, extra_notes=None):
    """Render a bundle as text for a Zammad article and for model context."""
    lines = [
        f"Alert:     {incident.get('alertname')}",
        f"Instance:  {incident.get('instance')}",
        f"Host:      {incident.get('host') or '(unresolved)'}",
        f"Service:   {incident.get('service') or '(n/a)'}",
        f"Severity:  {incident.get('severity') or '(none)'}",
        f"Summary:   {incident.get('summary') or '(none)'}",
        "",
    ]
    if extra_notes:
        lines.extend(extra_notes)
        lines.append("")

    for i, step in enumerate(steps, 1):
        marker = "ok" if step["ok"] else "FAILED"
        lines.append(f"--- [{i}] {step['description']} ({step['source']}, {marker}, {step['seconds']}s) ---")
        lines.append(step["output"])
        lines.append("")
    return "\n".join(lines)
