#!/usr/bin/env python3
"""The triage worker: decides, acts, documents, and escalates when needed.

Decisions here are deterministic. The local model is asked to explain and
classify, never to choose -- so a hallucination costs a badly worded ticket
note rather than a restarted database. The single place the model's opinion
changes an outcome is narrow and one-directional: it can suppress an
escalation only when Alertmanager independently agrees the alert has cleared.
It can never cause an action, and never prevent one.
"""
import json
import os
import sys
import time

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from incident_agent import claude, collect, config, llm, observability, remote, store, zammad  # noqa: E402


def log(message):
    print(f"[triage] {time.strftime('%FT%TZ', time.gmtime())} {message}", flush=True)


def _tag(ticket_id, tag):
    if not ticket_id:
        return
    try:
        zammad.add_tag(ticket_id, tag)
    except zammad.ZammadError as e:
        log(f"could not tag ticket {ticket_id} with '{tag}': {e}")


def _note(ticket_id, subject, body, internal=True):
    if not ticket_id:
        log(f"no ticket to write to; would have posted: {subject}")
        return
    try:
        zammad.add_article(ticket_id, subject, body, internal=internal)
    except zammad.ZammadError as e:
        log(f"could not post article to ticket {ticket_id}: {e}")


def _link_related(incident):
    """Link other recent tickets on the same host.

    Only same-host correlation is done here, deterministically. Subtler
    cross-host causation is left to the escalation tier, which can actually
    investigate -- guessing at it with string similarity would produce
    confident, wrong links, which are worse than none.
    """
    host = incident.get("host")
    if not host or not incident.get("ticket_number"):
        return []
    linked = []
    for peer in store.open_incidents_for_host(host, 3600, incident["id"]):
        if not peer.get("ticket_id") or peer["ticket_id"] == incident.get("ticket_id"):
            continue
        try:
            ticket = zammad.get_ticket(peer["ticket_id"])
            if not zammad.is_open(ticket):
                continue
            zammad.link_tickets(incident["ticket_number"], peer["ticket_id"])
            linked.append(peer)
        except zammad.ZammadError as e:
            log(f"link failed for peer ticket {peer.get('ticket_id')}: {e}")
    return linked


def _verify(rule, incident):
    """Check whether an action actually fixed the problem."""
    verify = rule.get("verify") or {}
    kind = verify.get("type")
    # Services rarely come back instantly; without a settle the check races the
    # restart and reports a false failure, which would escalate a fix that
    # actually worked.
    time.sleep(int(verify.get("settle_seconds", 15)))

    if kind == "http":
        ok, detail = observability.http_probe(verify.get("url", ""))
        return ok, detail
    if kind == "probe_target":
        instance = incident.get("instance", "")
        if instance.startswith("http"):
            ok, detail = observability.http_probe(instance)
            return ok, detail
        return None, "(probe_target verification requested but instance is not a URL)"
    return None, "(no verification configured for this rule)"


def _escalate(incident, bundle_text, reason, extra_note=None):
    """Hand off to Sonnet and record whatever comes back."""
    ticket_id = incident.get("ticket_id")
    log(f"escalating incident {incident['id']}: {reason}")
    _tag(ticket_id, "auto-escalated")

    result = claude.escalate(incident, bundle_text, reason)

    body = claude.format_result(result)
    if extra_note:
        body = f"{extra_note}\n\n{body}"

    if result["status"] != "completed":
        _note(ticket_id, "Escalation skipped", body)
        _tag(ticket_id, "needs-human")
        store.finish(incident["id"], "escalation_unavailable", result.get("detail", ""), escalated=False)
        return

    if result.get("resolved"):
        # Post the RCA and close in one call. If the fix did not actually hold,
        # the alert keeps firing and Alertmanager's next notification opens a
        # fresh ticket -- which is the correct outcome, since a problem that
        # recurs after being "resolved" is genuinely a new incident and should
        # not be quietly appended to a closed one.
        try:
            zammad.close_ticket(ticket_id, "Resolved by AI investigation", body, internal=False)
        except zammad.ZammadError as e:
            log(f"could not close ticket {ticket_id}: {e}")
            _note(ticket_id, "AI investigation (Claude)", body, internal=False)
        _tag(ticket_id, "auto-resolved")
        store.finish(incident["id"], "escalated_resolved", result.get("rca", "")[:2000], escalated=True)
    else:
        _note(ticket_id, "AI investigation (Claude)", body, internal=False)
        _tag(ticket_id, "needs-human")
        store.finish(incident["id"], "escalated_unresolved", result.get("rca", "")[:2000], escalated=True)


def handle(incident):
    ticket_id = incident.get("ticket_id")
    alertname = incident.get("alertname")
    host = incident.get("host")
    service = incident.get("service")

    _tag(ticket_id, "auto-triage")

    # --- Self-exclusion ------------------------------------------------
    pol = config.host_policy(host) if host else {"self_exclude": False, "critical": True, "known": False}
    if pol.get("self_exclude"):
        _note(
            ticket_id,
            "Triage skipped -- alert concerns the incident agent itself",
            "This alert is about the host running the incident agent, which is excluded from its "
            "own triage: if it is genuinely down it cannot investigate, and if it is up the alert "
            "is stale. This needs a human.",
        )
        _tag(ticket_id, "needs-human")
        store.finish(incident["id"], "self_excluded")
        return

    # --- Grace period expiry: is this still a problem at all? ----------
    firing = observability.alert_is_firing(incident.get("fingerprint"), alertname, incident.get("instance"))
    if firing is False:
        _note(
            ticket_id,
            "Self-resolved during grace period",
            f"The alert cleared on its own within {config.grace_seconds()}s of the ticket being "
            f"raised, so no investigation was performed and nothing was restarted.\n\n"
            f"No diagnostics were collected deliberately -- there was nothing left to collect, and "
            f"skipping SSH and inference here is most of why running this automatically is cheap.",
        )
        _tag(ticket_id, "auto-transient")
        store.finish(incident["id"], "self_resolved")
        log(f"incident {incident['id']} self-resolved during grace period")
        return
    if firing is None:
        # Unreachable Alertmanager must not be read as "resolved" -- that would
        # make an outage affecting `service` silently discard every incident.
        log(f"incident {incident['id']}: Alertmanager unreachable, proceeding on the assumption the alert stands")

    # --- Storm detection ----------------------------------------------
    storm_cfg = config.storm_config()
    window = storm_cfg.get("window_seconds", 600)
    hosts_alerting = store.distinct_hosts_alerting(window)
    peers = store.storm_peers(window, incident["id"])
    is_storm = len(hosts_alerting) >= storm_cfg.get("min_hosts", 4)

    if is_storm:
        # Lowest id in the window is the parent. A stable, cheap rule that both
        # workers agree on without coordination.
        parent = min((p for p in peers if p.get("ticket_id")), key=lambda p: p["id"], default=None)
        if parent and parent["id"] < incident["id"]:
            if incident.get("ticket_number") and parent.get("ticket_id"):
                try:
                    zammad.link_tickets(incident["ticket_number"], parent["ticket_id"])
                except zammad.ZammadError as e:
                    log(f"storm link failed: {e}")
            _note(
                ticket_id,
                "Part of a wider event",
                f"{len(hosts_alerting)} hosts alerted within {window}s "
                f"({', '.join(sorted(h for h in hosts_alerting if h))}), so this is being handled as one "
                f"infrastructure-level event rather than as separate incidents.\n\n"
                f"Linked to ticket #{parent.get('ticket_number')}, which carries the investigation. "
                f"No action was taken on this host: when this many hosts fail together the cause is "
                f"usually shared (a hypervisor, the network, DNS), and restarting individual guests "
                f"treats the symptom while destroying evidence.",
            )
            _tag(ticket_id, "storm-child")
            store.finish(incident["id"], "storm_child", parent_ticket_id=parent.get("ticket_id"))
            log(f"incident {incident['id']} handled as storm child of {parent['id']}")
            return

    # --- Diagnostics ---------------------------------------------------
    log(f"collecting diagnostics for incident {incident['id']} ({alertname} on {host})")
    steps = collect.collect(alertname, host, service, incident.get("instance"))

    notes = []
    if pol.get("note"):
        notes.append(f"Host note: {pol['note']}")
    if pol.get("critical"):
        # State the boundary inside the bundle itself, not only in the context
        # doc, so the constraint travels with the incident.
        notes.append(
            f"POLICY: {host} is protected -- no automated action is permitted on it. "
            f"{pol.get('reason') or ''}"
        )
    linked = _link_related(incident)
    if linked:
        notes.append(
            "Linked related open tickets on this host: "
            + ", ".join(f"#{p.get('ticket_number')} ({p.get('alertname')})" for p in linked)
        )
    notes.extend(collect.history_notes(incident))

    bundle = collect.format_bundle(incident, steps, notes)
    _note(ticket_id, f"Automated diagnostics -- {alertname}", bundle)

    # --- Storm parent: investigate the whole event once -----------------
    if is_storm:
        summary = "\n".join(
            f"- {p.get('alertname')} on {p.get('host')} (ticket #{p.get('ticket_number')})" for p in peers
        )
        _escalate(
            incident,
            bundle + f"\n\n--- Other alerts in this event ---\n{summary}\n",
            reason=(
                f"{len(hosts_alerting)} hosts alerted within {window}s -- an infrastructure-level event. "
                f"Investigate the shared cause (hypervisor, network, DNS) rather than the individual "
                f"guests. Check both hypervisors first."
            ),
        )
        return

    # --- Can we act at all? --------------------------------------------
    if not host:
        _escalate(incident, bundle, reason=(
            f"Could not map the alert's instance label ('{incident.get('instance')}') onto a known "
            f"fleet host, so no automated action was possible."
        ))
        return

    if pol["critical"] or not pol["known"]:
        _escalate(incident, bundle, reason=(
            f"'{host}' is protected from automated action. {pol.get('reason') or ''} "
            f"Investigate and recommend; do not restart it."
        ))
        return

    rule = config.match_restart_rule(alertname, host, service)
    if not rule:
        # No allow-list entry. This is where the local model earns its keep: if
        # Alertmanager already says the alert cleared AND the model reads the
        # evidence as transient, skip a Sonnet call that would only confirm
        # "it's fine now". The model can only agree with the deterministic
        # signal here, never override it.
        analysis = llm.analyse(bundle)
        recheck = observability.alert_is_firing(incident.get("fingerprint"), alertname, incident.get("instance"))
        if recheck is False and analysis and analysis["classification"] == "transient" and analysis["confidence"] in ("medium", "high"):
            _note(ticket_id, "Assessed as transient", llm.format_analysis(analysis))
            _tag(ticket_id, "auto-transient")
            store.finish(incident["id"], "transient", analysis["summary"][:2000])
            log(f"incident {incident['id']} assessed transient, escalation skipped")
            return

        extra = llm.format_analysis(analysis) if analysis else None
        _escalate(incident, bundle, reason=(
            f"No restart_allowlist.yml rule covers {alertname} on {host}"
            + (f" (service {service})" if service else "")
            + ", so nothing could be done automatically."
        ), extra_note=("Local model assessment:\n\n" + extra) if extra else None)
        return

    # --- Flap guard -----------------------------------------------------
    guard = config.flap_guard()
    recent = store.recent_action_count(alertname, host, guard.get("window_seconds", 3600))
    if recent >= guard.get("max_actions", 2):
        _escalate(incident, bundle, reason=(
            f"Flap guard tripped: {alertname} on {host} has already been auto-actioned {recent} times "
            f"in the last {guard.get('window_seconds', 3600) // 60} minutes. Restarting is clearly not "
            f"fixing the underlying problem -- find the real cause rather than bouncing it again."
        ))
        return

    # --- Act -------------------------------------------------------------
    action = rule.get("action")
    target = rule.get("target") or ""
    log(f"incident {incident['id']}: applying {action} {target} on {host}")
    try:
        if action == "restart_container":
            ok, output = remote.restart_container(host, target)
        elif action == "restart_service":
            ok, output = remote.restart_service(host, target)
        elif action == "restart_host":
            ok, output = remote.restart_host(host)
        else:
            ok, output = False, f"unknown action '{action}' in restart_allowlist.yml"
    except remote.ActionRefused as e:
        store.record_action(incident["id"], alertname, host, action, target, "refused", str(e))
        _escalate(incident, bundle, reason=f"Action refused by policy: {e}")
        return

    store.record_action(incident["id"], alertname, host, action, target, "ok" if ok else "failed", output)

    if not ok:
        _escalate(
            incident, bundle,
            reason=f"Automated {action} of '{target or host}' on {host} FAILED.",
            extra_note=f"Attempted {action} `{target or host}` on `{host}` -- failed:\n\n```\n{output[:2000]}\n```",
        )
        return

    verified, verify_detail = _verify(rule, incident)

    action_note = (
        f"Applied `{action}` to `{target or host}` on `{host}`.\n"
        f"Result: {output[:1000]}\n"
        f"Verification: {verify_detail}"
    )

    if verified is False:
        _escalate(
            incident, bundle,
            reason=(
                f"Automated {action} of '{target or host}' on {host} completed, but the service is "
                f"still not healthy afterwards ({verify_detail}). The restart was not the fix."
            ),
            extra_note=action_note,
        )
        return

    # Restarted and either verified healthy, or no verification configured.
    analysis = llm.analyse(bundle, action_note=f"Action already taken automatically: {action_note}")
    narrative = llm.format_analysis(analysis) or llm.fallback_summary("no response from Ollama")

    # The ticket is left open on purpose rather than closed here. Alertmanager
    # closes it via zammad_relay.py when the alert actually clears, which is a
    # claim grounded in monitoring rather than in the agent's opinion of its own
    # work -- and if the restart did not really fix things, the ticket correctly
    # stays open instead of being closed on a false success.
    _note(
        ticket_id,
        f"Auto-resolved -- {action} on {host}",
        f"{action_note}\n\n{narrative}\n\n"
        f"This ticket is left open deliberately: Alertmanager closes it automatically once the "
        f"alert clears, so it staying open means monitoring has not yet confirmed the fix.",
        internal=False,
    )
    _tag(ticket_id, "auto-resolved")
    store.finish(incident["id"], "auto_resolved", action_note[:2000])
    log(f"incident {incident['id']} auto-resolved via {action} on {host}")


def main():
    store.init()
    log(f"worker starting (max concurrent={config.MAX_CONCURRENT_TRIAGE}, grace={config.grace_seconds()}s)")
    recovered = store.requeue_stale()
    if recovered:
        log(f"requeued {recovered} incident(s) abandoned by a previous worker")

    while True:
        try:
            # Re-read config each cycle so an edited allow-list takes effect
            # without a restart -- during an incident is exactly when someone
            # wants to add a rule, and that is the worst moment to require a
            # service restart to apply it.
            config.reset_cache()
            incident = store.claim_next(config.MAX_CONCURRENT_TRIAGE)
            if incident is None:
                time.sleep(config.WORKER_POLL_SECONDS)
                continue
            try:
                handle(incident)
            except Exception as e:  # noqa: BLE001
                log(f"ERROR handling incident {incident['id']}: {type(e).__name__}: {e}")
                _note(
                    incident.get("ticket_id"),
                    "Automated triage failed",
                    f"The incident agent hit an unexpected error and could not complete triage:\n\n"
                    f"```\n{type(e).__name__}: {e}\n```\n\nThis ticket needs a human.",
                )
                _tag(incident.get("ticket_id"), "needs-human")
                store.finish(incident["id"], "error", f"{type(e).__name__}: {e}")
        except KeyboardInterrupt:
            log("shutting down")
            return
        except Exception as e:  # noqa: BLE001
            # Never let the worker loop die -- a crashed worker means alerts
            # queue up silently and nobody finds out until it matters.
            log(f"ERROR in worker loop: {type(e).__name__}: {e}")
            time.sleep(config.WORKER_POLL_SECONDS)


if __name__ == "__main__":
    if len(sys.argv) > 1 and sys.argv[1] == "--once":
        # Single-shot mode for testing: process one ready incident and exit.
        store.init()
        job = store.claim_next(config.MAX_CONCURRENT_TRIAGE)
        if job is None:
            print("no incident ready to process")
        else:
            handle(job)
    else:
        main()
