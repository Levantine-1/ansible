#!/usr/bin/env python3
"""The triage worker: decides, acts, documents, and escalates when needed.

The restart_allowlist.yml fast path stays fully deterministic -- a matched
rule acts immediately, no model involved. As of 2026-08-24 the local model
also gets a real, bounded vote in two places: when no rule covers an alert at
all, and when a matched rule's own action fails (the case that made ticket
16093 cost $0.50 to power on a host -- the rule tried restart_service, which
failed because the whole VM was off, and the only option before this was to
escalate). In both cases the model's recommendation still goes through
_assert_actionable() in remote.py, the same flap guard as every other action,
and post-action verification -- a bad recommendation costs a failed attempt
that falls through to escalation, never an unsupervised action on something
protected.
"""
import json
import os
import sys
import time

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from incident_agent import claude, collect, config, llm, observability, remote, store, zammad  # noqa: E402

# Maps an (action, target_kind) pair from llm.analyse() onto the matching
# remote.py function. Every entry here is already gated through
# remote.py's _assert_actionable() -- this dict only chooses WHICH verb to
# call, it grants no additional authority.
_ACTION_FUNCS = {
    ("start", "host"): lambda host, target: remote.start_host(host),
    ("stop", "host"): lambda host, target: remote.stop_host(host),
    ("restart", "host"): lambda host, target: remote.restart_host(host),
    ("start", "container"): lambda host, target: remote.start_container(host, target),
    ("stop", "container"): lambda host, target: remote.stop_container(host, target),
    ("restart", "container"): lambda host, target: remote.restart_container(host, target),
    ("start", "service"): lambda host, target: remote.start_service(host, target),
    ("stop", "service"): lambda host, target: remote.stop_service(host, target),
    ("restart", "service"): lambda host, target: remote.restart_service(host, target),
}


def log(message):
    print(f"[triage] {time.strftime('%FT%TZ', time.gmtime())} {message}", flush=True)


def _tag(ticket_id, tag):
    if not ticket_id:
        return
    try:
        zammad.add_tag(ticket_id, tag)
    except zammad.ZammadError as e:
        log(f"could not tag ticket {ticket_id} with '{tag}': {e}")


def _note(ticket_id, subject, body, internal=True, author="script"):
    if not ticket_id:
        log(f"no ticket to write to; would have posted: {subject}")
        return
    try:
        zammad.add_article(ticket_id, subject, body, internal=internal, author=author)
    except zammad.ZammadError as e:
        log(f"could not post article to ticket {ticket_id}: {e}")


def _link_related(incident):
    """Link other recent tickets on the same host.

    Only same-host correlation is done here, deterministically. Subtler
    cross-host causation is left to the escalation tier, which can actually
    investigate -- guessing at it with string similarity would produce
    confident, wrong links, which are worse than none.

    Links regardless of the peer ticket's current state (open or already
    closed) -- deliberately changed 2026-08-24. A single host outage commonly
    trips several distinct Prometheus targets at once (confirmed live: theia
    powering off raised ProbeFailed, InstanceDown/node_exporter, and
    InstanceDown/cadvisor as three separate tickets), and this worker
    processes them sequentially -- by the time the second and third are
    handled, the first may already be closed. Only linking open peers meant
    those three never got cross-referenced at all, which is exactly the kind
    of noise a human reviewing Zammad complains about: three tickets that
    read as unrelated when they were one event.
    """
    host = incident.get("host")
    if not host or not incident.get("ticket_number"):
        return []
    linked = []
    for peer in store.recent_incidents_for_host(host, 3600, incident["id"]):
        if not peer.get("ticket_id") or peer["ticket_id"] == incident.get("ticket_id"):
            continue
        try:
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


def _host_down_evidence(bundle_text):
    """Whether the bundle actually shows signs the host itself is
    unreachable, as opposed to the model merely asserting so.

    Confirmed live (2026-08-24): a 3.8B model recommended action=start,
    target_kind=host for a DiskSpaceLow alert on a host that was
    demonstrably up and responding normally throughout its own diagnostic
    bundle -- it defaulted to the schema's simplest valid completion
    (target_kind=host needs no target name) rather than correctly saying
    none. `start` against an already-running VM is a safe no-op (Proxmox
    refuses it with an error), but `stop`/`restart` against a healthy host
    would not be -- this check gates all three host-level verbs regardless,
    since none of them make sense without real evidence anyway.
    """
    lowered = bundle_text.lower()
    signals = (
        "status: stopped", "no route to host", "connection refused",
        "ssh timed out", "could not connect", "connection timed out",
    )
    return any(s in lowered for s in signals)


def _hypervisor_unreachable(steps):
    """Whether every hypervisor-directed diagnostic step failed -- the
    affected host's physical server isn't answering SSH at all, not just the
    guest VM.

    Distinct from _host_down_evidence: that one looks for evidence the GUEST
    is down (used to gate host-level start/stop/restart recommendations, still
    something a local `qm start` can fix); this one is about the underlying
    HARDWARE being unreachable, used to gate whether escalating to Claude is
    even worth attempting at all -- Claude's SSH-based tools would hit the
    exact same wall reaching the same hypervisor over the same network.
    """
    hypervisor_steps = [s for s in steps if s.get("source") == "hypervisor"]
    return bool(hypervisor_steps) and all(not s["ok"] for s in hypervisor_steps)


def _try_llm_action(incident, bundle, extra_context=None, rule_for_verify=None):
    """Ask the local model for an action recommendation and, if it produces a
    valid one, attempt it -- subject to the same flap guard every other
    action goes through, and the same _assert_actionable() gate in remote.py.

    extra_context is free text prepended to the model's prompt -- used to
    tell it a previous action already failed and how, so it can react to
    that rather than repeating it (the theia case: a failed restart_service
    is strong evidence the host itself is down, not the service).

    rule_for_verify, if given, reuses that rule's own verify: block (the
    right check is "is theia's HTTP endpoint healthy", regardless of which
    action was used to get there); otherwise falls back to an Alertmanager
    re-check, same signal the grace period already uses.

    Returns (resolved, analysis, note):
      resolved=True  -> incident is fully handled (ticket noted/tagged/finished
                         already) -- caller should return immediately.
      resolved=False -> caller should escalate. `note`, if not None, is
                         ready-to-use context for the escalation (what was
                         tried and how it went); `analysis` is the raw
                         classification for callers that want it directly
                         (e.g. to check for a transient verdict).
    """
    host = incident.get("host")
    alertname = incident.get("alertname")
    ticket_id = incident.get("ticket_id")

    analysis = llm.analyse(bundle, action_note=extra_context or "")
    if not llm.has_action(analysis):
        return False, analysis, None

    if analysis["target_kind"] == "host" and not _host_down_evidence(bundle):
        log(
            f"incident {incident['id']}: local model recommended {analysis['action']} host "
            f"on {host}, but the bundle has no evidence the host is actually down -- refusing "
            f"(see _host_down_evidence's docstring)"
        )
        return False, analysis, (
            f"Local model recommended {analysis['action']} host `{host}`, but nothing in the "
            f"diagnostic bundle actually shows the host is unreachable -- refused as an "
            f"unsupported recommendation rather than attempted."
        )

    guard = config.flap_guard()
    recent = store.recent_action_count(alertname, host, guard.get("window_seconds", 3600))
    if recent >= guard.get("max_actions", 2):
        log(
            f"incident {incident['id']}: local model recommended "
            f"{analysis['action']} {analysis['target_kind']}, but the flap guard already "
            f"tripped ({recent} attempts on {alertname}/{host} this window) -- not attempting it"
        )
        return False, analysis, (
            f"Local model recommended {analysis['action']} {analysis['target_kind']} "
            f"`{analysis['target'] or host}`, but {alertname} on {host} has already been "
            f"auto-actioned {recent} times this window -- not attempting another."
        )

    action, kind, target = analysis["action"], analysis["target_kind"], analysis["target"]
    fn = _ACTION_FUNCS.get((action, kind))
    if fn is None:
        return False, analysis, None

    log(
        f"incident {incident['id']}: local model recommends {action} {kind} "
        f"{target or host} on {host} -- {analysis['notes']}"
    )
    action_label = f"{action}_{kind}"
    try:
        ok, output = fn(host, target)
    except remote.ActionRefused as e:
        store.record_action(incident["id"], alertname, host, action_label, target, "refused", str(e))
        return False, analysis, (
            f"Local model recommended {action} {kind} `{target or host}` -- refused by policy: {e}"
        )

    store.record_action(incident["id"], alertname, host, action_label, target, "ok" if ok else "failed", output)

    if not ok:
        return False, analysis, (
            f"Local model recommended {action} {kind} `{target or host}` "
            f"({analysis['notes']}) -- attempted, but it failed:\n```\n{output[:2000]}\n```"
        )

    if rule_for_verify:
        verified, verify_detail = _verify(rule_for_verify, incident)
    else:
        # No rule to borrow a verify: block from -- settle, then ask
        # Alertmanager directly, the same signal the grace period already
        # trusts for "is this actually still a problem."
        time.sleep(15)
        firing_after = observability.alert_is_firing(
            incident.get("fingerprint"), alertname, incident.get("instance")
        )
        verified = firing_after is False
        verify_detail = (
            "alert cleared" if verified
            else "still firing" if firing_after
            else "could not confirm (Alertmanager unreachable)"
        )

    action_note_text = (
        f"Local model recommended: {action} {kind} `{target or host}` -- {analysis['notes']}\n"
        f"Result: {output[:1000]}\n"
        f"Verification: {verify_detail}"
    )

    if verified is False:
        return False, analysis, action_note_text + "\n\n(action completed, but did not resolve the alert)"

    narrative = llm.format_analysis(analysis) or llm.fallback_summary("no response from Ollama")
    _note(
        ticket_id,
        f"Auto-resolved -- local model recommended {action} {kind} on {host}",
        f"{action_note_text}\n\n{narrative}\n\n"
        f"This ticket is left open deliberately: Alertmanager closes it automatically once the "
        f"alert clears, so it staying open means monitoring has not yet confirmed the fix.",
        internal=False,
        author=config.OLLAMA_MODEL,
    )
    _tag(ticket_id, "auto-resolved")
    _tag(ticket_id, "llm-decided")
    store.finish(incident["id"], "llm_auto_resolved", action_note_text[:2000])
    log(f"incident {incident['id']} auto-resolved via local model's {action} {kind} on {host}")
    return True, analysis, action_note_text


def _escalate(incident, bundle_text, reason, extra_note=None):
    """Hand off to Sonnet and record whatever comes back."""
    ticket_id = incident.get("ticket_id")
    log(f"escalating incident {incident['id']}: {reason}")
    _tag(ticket_id, "auto-escalated")

    result = claude.escalate(incident, bundle_text, reason)

    body = claude.format_result(result)
    if extra_note:
        body = f"{extra_note}\n\n{body}"

    # Claude only gets credit for content it actually wrote -- "completed"
    # means it ran and produced this body; anything else (no API key, budget
    # exhausted, an error) is a script message reporting that it didn't.
    author = "claude" if result["status"] == "completed" else "script"

    if result["status"] != "completed":
        _note(ticket_id, "Escalation skipped", body, author=author)
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
            zammad.close_ticket(ticket_id, "Resolved by AI investigation", body, internal=False, author=author)
        except zammad.ZammadError as e:
            log(f"could not close ticket {ticket_id}: {e}")
            _note(ticket_id, "AI investigation (Claude)", body, internal=False, author=author)
        _tag(ticket_id, "auto-resolved")
        store.finish(incident["id"], "escalated_resolved", result.get("rca", "")[:2000], escalated=True)
    else:
        _note(ticket_id, "AI investigation (Claude)", body, internal=False, author=author)
        _tag(ticket_id, "needs-human")
        store.finish(incident["id"], "escalated_unresolved", result.get("rca", "")[:2000], escalated=True)


def _escalate_or_retry(incident, bundle, steps, reason, extra_note=None):
    """The routine-vs-disaster gate (2026-08-24), used wherever an
    unconditional _escalate() call used to sit for the critical-host,
    no-rule, and rule-failed paths.

    Falls straight through to a normal _escalate(), unchanged, if the
    affected host's hypervisor answered fine -- this function only adds a
    gate for the unreachable case, never narrows the ordinary path.

    When the hypervisor IS unreachable, that is always treated as isolated
    and worth retrying via store.requeue_for_retry() -- deterministically,
    not put to the model. This is safe, not just convenient: every call site
    that reaches this function does so from a branch of handle() that runs
    AFTER the is_storm branch has already returned, so by construction fewer
    than storm_cfg['min_hosts'] hosts are alerting whenever this function is
    reached. A single unreachable hypervisor in that context cannot be a
    multi-host event; there is nothing for a "widespread" verdict to
    correctly mean here. Confirmed live (2026-08-24) this was not just a
    theoretical simplification: asked anyway, the model classified this
    exact single-host scenario as "widespread", reasoning "hypervisor
    unresponsive -> potential hardware issue -> widespread" -- conflating
    the CAUSE looking hardware-related with the SCOPE being broad, despite
    the prompt explicitly telling it to default to isolated and explicitly
    stating only 1 host was affected. Removing the question here removes the
    failure mode; the model still makes this call where it is genuinely
    ambiguous, in handle()'s storm-parent branch (multiple hosts really are
    alerting together there, so "shared cause or coincidence" is a real
    question worth asking).

    A hypervisor not answering SSH is physical, not something any amount of
    agentic reasoning fixes remotely -- per your steer (2026-08-24), this
    never reaches Claude, at any point, first attempt or after every retry is
    exhausted. Once retries run out it is flagged for a human exactly like
    the disaster case below, not escalated. The retry loop still runs first
    purely because it is free and self-resolves the common "briefly
    unreachable, came back" case without bothering anyone at all.

    The disaster case (incident-agent has no external connectivity at all)
    is checked once, earlier in handle(), before this function is ever
    reached -- by the time control gets here, connectivity is already known
    to be fine.
    """
    host = incident.get("host")
    ticket_id = incident.get("ticket_id")

    if not _hypervisor_unreachable(steps):
        _escalate(incident, bundle, reason, extra_note=extra_note)
        return

    retry_cfg = config.unreachable_retry_config()
    was_first_attempt = incident.get("retry_count", 0) == 0
    requeued = store.requeue_for_retry(incident["id"], retry_cfg["interval_seconds"], retry_cfg["max_retries"])

    if requeued:
        if was_first_attempt:
            # Only on the first detection -- retry_count was 0 before this
            # call incremented it, so a ticket note on every subsequent retry
            # (every ~15 min, potentially for hours) would just be spam.
            _note(ticket_id, "Hypervisor unreachable -- will keep checking", (
                f"The hypervisor for {host} is not responding to any diagnostic check. Treating "
                f"this as an isolated problem, not a wider outage (incident-agent's own "
                f"connectivity is fine, and nothing else currently points at a shared cause).\n\n"
                f"Will re-check every {retry_cfg['interval_seconds'] // 60} minutes, up to "
                f"{retry_cfg['max_retries']} times "
                f"(~{retry_cfg['interval_seconds'] * retry_cfg['max_retries'] // 60} minutes total), "
                f"and resolve normally if it answers again. A hypervisor being unreachable is "
                f"physical, not something remote tooling (including Claude) can fix -- if it is "
                f"still unreachable after that, this is flagged for a human rather than escalated."
            ))
        _tag(ticket_id, "auto-retry")
        log(
            f"incident {incident['id']}: hypervisor for {host} unreachable, requeued for retry "
            f"({'first attempt' if was_first_attempt else 'retry ' + str(incident.get('retry_count', 0) + 1)})"
        )
        return

    total_minutes = retry_cfg["max_retries"] * retry_cfg["interval_seconds"] // 60
    _note(ticket_id, "Hypervisor still unreachable -- needs a human", (
        f"The hypervisor for {host} has been unreachable across {retry_cfg['max_retries']} retries "
        f"over roughly {total_minutes} minutes. Not escalating to Claude -- an unreachable "
        f"hypervisor is a physical/infrastructure problem, and Claude's tools would hit the exact "
        f"same wall over the same network. This needs a human. The ticket will close automatically "
        f"once the underlying alert clears on its own."
    ))
    _tag(ticket_id, "needs-human")
    _tag(ticket_id, "physical-intervention")
    store.finish(incident["id"], "unfixable_remotely", f"hypervisor unreachable after {retry_cfg['max_retries']} retries")
    log(f"incident {incident['id']}: hypervisor for {host} still unreachable after {retry_cfg['max_retries']} retries, flagging for human, not escalating")


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

    # --- Disaster check: deterministic override -------------------------
    # Only checked when there's already a sign of real trouble -- the
    # affected host's hypervisor not answering, or a storm -- since this is a
    # real network call and the vast majority of incidents (a crashed
    # container, a stuck service) have nothing to do with connectivity.
    # Runs once, ahead of every remaining branch (critical-host, storm-parent,
    # no-rule, rule-failed): if incident-agent itself has no path to the
    # internet, nothing downstream should even be attempted, and this is the
    # one signal unambiguous enough not to need the model's judgment --
    # getting it wrong (escalating to Claude during a real site-wide outage)
    # is exactly the waste this exists to prevent.
    hypervisor_down = _hypervisor_unreachable(steps)
    if (hypervisor_down or is_storm) and not observability.external_connectivity_ok():
        _note(ticket_id, "Likely a network or power outage, not a single-host problem", (
            "incident-agent itself has no external connectivity right now. Claude's tools would "
            "reach the fleet over this same network and hit the same wall, so escalating would "
            "only spend money confirming that. Left for a human -- this needs physical "
            "intervention, not more automation. The ticket will close automatically once the "
            "underlying alert clears on its own."
        ))
        _tag(ticket_id, "needs-human")
        _tag(ticket_id, "physical-intervention")
        store.finish(incident["id"], "unfixable_remotely", "no external connectivity")
        log(f"incident {incident['id']}: no external connectivity -- treating as a disaster, not escalating")
        return

    # --- Storm parent: investigate the whole event once -----------------
    if is_storm:
        summary = "\n".join(
            f"- {p.get('alertname')} on {p.get('host')} (ticket #{p.get('ticket_number')})" for p in peers
        )
        storm_scope_context = (
            f"Evidence for how widespread this looks: {len(hosts_alerting)} distinct hosts alerted "
            f"within {window}s of each other (the storm-detection threshold). incident-agent's own "
            f"external connectivity is confirmed fine (checked separately, this call would not have "
            f"happened otherwise). This many hosts failing together usually IS a shared cause (a "
            f"hypervisor, the network, DNS) rather than coincidence -- classify scope as widespread "
            f"unless the evidence gives a specific reason to think these are actually unrelated."
        )
        storm_analysis = llm.analyse(bundle, action_note=storm_scope_context)
        if storm_analysis and storm_analysis.get("scope") == "widespread":
            _note(ticket_id, "Local model: this is a widespread event, not worth escalating per-incident", (
                f"{llm.format_analysis(storm_analysis) or '(no detail)'}\n\n"
                f"Not escalating to Claude -- {len(hosts_alerting)} hosts down together usually "
                f"means a shared cause Claude's SSH-based tools would hit the same way. Left for a "
                f"human; the ticket closes automatically once the underlying alert clears."
            ), author=config.OLLAMA_MODEL)
            _tag(ticket_id, "needs-human")
            _tag(ticket_id, "physical-intervention")
            store.finish(incident["id"], "unfixable_remotely", "storm classified as widespread")
            log(f"incident {incident['id']}: storm classified widespread, not escalating")
            return

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
        _escalate_or_retry(incident, bundle, steps, reason=(
            f"'{host}' is protected from automated action. {pol.get('reason') or ''} "
            f"Investigate and recommend; do not restart it."
        ))
        return

    rule = config.match_restart_rule(alertname, host, service)
    if not rule:
        if hypervisor_down:
            # No point asking the model for an action -- nothing can reach
            # this hypervisor to execute anything anyway. Straight to the
            # routine-vs-disaster gate instead of burning a CPU-bound
            # inference call on a recommendation that could only ever fail.
            _escalate_or_retry(incident, bundle, steps, reason=(
                f"No restart_allowlist.yml rule covers {alertname} on {host}"
                + (f" (service {service})" if service else "")
                + ", and the hypervisor is unreachable so no action could be attempted anyway."
            ))
            return

        # No allow-list entry. This is where the local model earns its keep --
        # as of 2026-08-24, it gets a real vote here, not just an opinion:
        # given the bundle's evidence, it can recommend starting/stopping/
        # restarting a host/container/service, and if the target is real and
        # non-critical, that recommendation gets attempted (still through the
        # same _assert_actionable() gate and flap guard as every other
        # action). One inference call does both the action decision and the
        # classification below, so this doesn't cost a second round-trip.
        resolved, analysis, note = _try_llm_action(incident, bundle)
        if resolved:
            return

        # No action taken (model recommended none, target didn't resolve, the
        # attempt failed, or the flap guard already tripped). Fall back to the
        # existing transient check, reusing the SAME analyse() call above --
        # if Alertmanager independently agrees the alert cleared AND the model
        # read the evidence as transient, skip a Sonnet call that would only
        # confirm "it's fine now." The model can only agree with the
        # deterministic signal here, never override it.
        recheck = observability.alert_is_firing(incident.get("fingerprint"), alertname, incident.get("instance"))
        if recheck is False and analysis and analysis["classification"] == "transient" and analysis["confidence"] in ("medium", "high"):
            _note(ticket_id, "Assessed as transient", llm.format_analysis(analysis), author=config.OLLAMA_MODEL)
            _tag(ticket_id, "auto-transient")
            store.finish(incident["id"], "transient", analysis["summary"][:2000])
            log(f"incident {incident['id']} assessed transient, escalation skipped")
            return

        extra_parts = [p for p in (note, llm.format_analysis(analysis) if analysis else None) if p]
        extra = "\n\n".join(extra_parts) or None
        _escalate_or_retry(incident, bundle, steps, reason=(
            f"No restart_allowlist.yml rule covers {alertname} on {host}"
            + (f" (service {service})" if service else "")
            + ", and the local model did not recommend an action it could safely take."
        ), extra_note=extra)
        return

    # --- Flap guard -----------------------------------------------------
    guard = config.flap_guard()
    recent = store.recent_action_count(alertname, host, guard.get("window_seconds", 3600))
    if recent >= guard.get("max_actions", 2):
        _escalate_or_retry(incident, bundle, steps, reason=(
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
        # The rule's own action failed -- this is the theia case (ticket
        # 16093, 2026-08-24): restart_service failed with "no route to host"
        # because the whole VM was off, and escalating straight to Claude cost
        # $0.50 for a power-on. Before escalating, tell the model exactly what
        # was tried and how it failed, and let it reconsider: a connection
        # failure is strong evidence the HOST is down, not the service, which
        # is a different fix than the rule assumed. Reuses this rule's own
        # verify: block, since "is the endpoint healthy" is the right check
        # regardless of which action got it there.
        action_failure_note = f"Attempted {action} `{target or host}` on `{host}` -- failed:\n\n```\n{output[:2000]}\n```"

        if hypervisor_down:
            # Already known unreachable from the pre-diagnostics check --
            # consistent with why the action just failed. No point asking the
            # model for an alternative either; nothing can execute against
            # this hypervisor right now regardless of what it recommends.
            _escalate_or_retry(incident, bundle, steps, reason=(
                f"Automated {action} of '{target or host}' on {host} FAILED, and the hypervisor "
                f"itself is unreachable -- consistent with the failure, and no action can succeed "
                f"until it answers again."
            ), extra_note=action_failure_note)
            return

        failure_context = (
            f"An automated action was already attempted and failed.\n"
            f"Attempted: {action} on target '{target or host}' (host {host}).\n"
            f"Failure detail: {output[:1000]}\n\n"
            f"If this failure looks like the HOST itself is down (connection refused, no route to "
            f"host, SSH/connect timeout) rather than the service or container being unhealthy, that "
            f"changes the right fix -- consider recommending the host be started instead of "
            f"repeating the same target."
        )
        resolved, analysis, note = _try_llm_action(
            incident, bundle, extra_context=failure_context, rule_for_verify=rule
        )
        if resolved:
            return

        extra = action_failure_note
        if note:
            extra += f"\n\n{note}"
        elif analysis:
            extra += f"\n\n{llm.format_analysis(analysis) or ''}"

        _escalate_or_retry(
            incident, bundle, steps,
            reason=(
                f"Automated {action} of '{target or host}' on {host} FAILED"
                + (", and the local model's alternative also failed." if note else
                   ", and the local model had no better recommendation.")
            ),
            extra_note=extra,
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
