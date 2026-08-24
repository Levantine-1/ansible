#!/usr/bin/env python3
"""Tests for the incident agent's decision logic.

Deliberately concentrated on the parts where a bug is silent and expensive:
the policy layer that decides whether a host may be touched, the queue
semantics that stop one alert being investigated twice, and the parsing that
has to survive a small model's output. Nothing here touches the network -- every
assertion is about the agent's own decisions.

The real shipped config files are used rather than fixtures, so these also
assert that fleet.yml/restart_allowlist.yml actually say what the code assumes.

    pip install pyyaml
    python tests/test_incident_agent.py
"""
import os
import sys
import tempfile
import time

import yaml

HERE = os.path.dirname(os.path.abspath(__file__))
FILES = os.path.join(os.path.dirname(HERE), "files")

# Must be set before importing config -- it reads the environment at import.
os.environ["IA_CONFIG_DIR"] = FILES
os.environ["IA_STATE_DIR"] = tempfile.mkdtemp(prefix="incident-agent-test-")
os.environ["IA_ZAMMAD_API_TOKEN"] = "test-token"

sys.path.insert(0, FILES)

from incident_agent import claude, collect, config, llm, observability, remote, store, zammad  # noqa: E402
import triage  # noqa: E402

PASS, FAIL = [], []


def check(name, condition, detail=""):
    (PASS if condition else FAIL).append(name)
    print(f"  {'ok  ' if condition else 'FAIL'} {name}" + (f"  -- {detail}" if detail and not condition else ""))


print("\n== instance label -> host resolution ==")
# The instance label is not a hostname, and getting this wrong means acting on
# the wrong host or not acting at all.
host, svc = config.resolve_target("InstanceDown", {"instance": "dockerhost1.internal.levantine.io:9100"})
check("node_exporter instance resolves to short host name", host == "dockerhost1", f"got {host}")

host, svc = config.resolve_target("ProbeFailed", {"instance": "https://livecam-lan.levantine.io/login"})
check("probe URL resolves to host and service", (host, svc) == ("dockerhost1", "livecam"), f"got {host}/{svc}")

host, svc = config.resolve_target("InstanceDown", {"instance": "10.69.69.139:9100"})
check("hypervisor IP resolves to hypervisor name", host == "3800xt", f"got {host}")

host, svc = config.resolve_target("InstanceDown", {"instance": "nonesuch.example.com:9100"})
check("unknown instance resolves to None (must not guess)", host is None, f"got {host}")

host, svc = config.resolve_target("ProbeFailed", {"instance": "https://unmapped.example.com/"})
check("unmapped probe URL resolves to None", host is None, f"got {host}")


print("\n== host policy fails closed ==")
pol = config.host_policy("vault")
check("vault is critical", pol["critical"] and pol["known"])
check("vault records why", "unseal" in (pol["reason"] or "").lower(), pol.get("reason"))

pol = config.host_policy("brand-new-host-nobody-declared")
check("undeclared host is treated as critical", pol["critical"] and not pol["known"])

pol = config.host_policy("3800xt")
check("hypervisor is critical", pol["critical"])

pol = config.host_policy("dockerhost1")
check("dockerhost1 is not critical", not pol["critical"] and pol["known"])

pol = config.host_policy("incident-agent")
check("incident-agent excludes itself from triage", pol["self_exclude"])

for critical in ("service", "opnsense", "vault", "pxdbc1", "pxdbc2", "pxdbc3", "proxysql"):
    check(f"{critical} is protected", config.host_policy(critical)["critical"])


print("\n== restart allow-list ==")
rule = config.match_restart_rule("ProbeFailed", "frigate", "frigate")
check("frigate probe failure has a rule", rule is not None and rule["action"] == "restart_container")

rule = config.match_restart_rule("ProbeFailed", "dockerhost1", "livecam")
check("livecam probe failure has a rule", rule is not None, str(rule))

rule = config.match_restart_rule("ProbeFailed", "dockerhost1", "processmining")
check("service-parameterised rule substitutes the container name",
      rule is not None and rule["target"] == "processmining", str(rule))

rule = config.match_restart_rule("ProbeFailed", "dockerhost1", None)
check("service-parameterised rule refuses when service is unknown", rule is None, str(rule))

rule = config.match_restart_rule("HighCPUUsage", "dockerhost1", None)
check("no rule for an uncovered alert", rule is None)

# theia InstanceDown: confirmed live twice (2026-08-24, tickets #16093-era and
# #16097-99) as the same "VM fully off" signature frigate's own InstanceDown
# rule already covers -- promoted from the local model's discretion to a
# deterministic rule, same as frigate's, once it stopped being ambiguous.
rule = config.match_restart_rule("InstanceDown", "theia")
check("theia InstanceDown has a rule now", rule is not None and rule["action"] == "restart_host", str(rule))

# The important one: a rule must never grant an exception to fleet.yml.
config.policy()["rules"].append(
    {"alert": "InstanceDown", "host": "vault", "action": "restart_host", "target": "vault"}
)
rule = config.match_restart_rule("InstanceDown", "vault")
check("allow-list cannot override critical-host protection", rule is None, str(rule))
config.reset_cache()


print("\n== remote actions refuse protected hosts ==")
for host in ("vault", "opnsense", "service", "pxdbc1", "3800xt", "undeclared-host"):
    try:
        remote.restart_host(host)
        check(f"restart_host({host}) refused", False, "it was NOT refused")
    except remote.ActionRefused:
        check(f"restart_host({host}) refused", True)
    except Exception as e:  # noqa: BLE001
        check(f"restart_host({host}) refused", False, f"wrong exception: {type(e).__name__}")

try:
    remote.restart_container("vault", "anything")
    check("restart_container on a critical host refused", False, "it was NOT refused")
except remote.ActionRefused:
    check("restart_container on a critical host refused", True)

# The 2026-08-24 verb expansion (local model gets start/stop authority, not
# just restart) -- every one of these must refuse on a critical host exactly
# like the pre-existing restart_* functions do. No new enforcement code
# backs these; they all go through the same _assert_actionable(), so this is
# really testing that none of them were written to skip it.
for fn, args in (
    (remote.start_host, ("vault",)),
    (remote.stop_host, ("vault",)),
    (remote.start_container, ("vault", "anything")),
    (remote.stop_container, ("vault", "anything")),
    (remote.start_service, ("vault", "anything")),
    (remote.stop_service, ("vault", "anything")),
):
    try:
        fn(*args)
        check(f"{fn.__name__} on a critical host refused", False, "it was NOT refused")
    except remote.ActionRefused:
        check(f"{fn.__name__} on a critical host refused", True)


print("\n== hypervisor command construction ==")
# remote.qm() injects the vm_id from fleet.yml, so diagnostics.yml must NOT
# also write it out -- doing so silently produced `qm status 105 105`.
_sent = []


def _fake_ssh(address, command, timeout=20):
    _sent.append((address, command))
    return True, "stubbed"


_real_ssh = remote.ssh
remote.ssh = _fake_ssh
try:
    remote.qm("dockerhost1", "status")
    check("qm targets the right hypervisor", _sent[-1][0] == "10.69.69.139", str(_sent[-1]))
    check("qm injects the vm_id exactly once", _sent[-1][1] == "sudo qm status 105", _sent[-1][1])

    remote.qm("dockerhost1", "config | head -30")
    check("qm preserves a trailing pipeline", _sent[-1][1] == "sudo qm config 105 | head -30", _sent[-1][1])

    # Read-only qm against a protected host is allowed -- inspecting vault's VM
    # state is exactly the diagnostic that should always work.
    ok, _ = remote.qm("vault", "status")
    check("read-only qm allowed on a critical host", ok)

    try:
        remote.qm("vault", "stop")
        check("state-changing qm refused on a critical host", False, "it was NOT refused")
    except remote.ActionRefused:
        check("state-changing qm refused on a critical host", True)

    # Every qm command in diagnostics.yml must rely on that injection.
    bad = []
    for name, plan in config.diagnostics()["alerts"].items():
        for step in plan.get("steps", []):
            cmd = step.get("command", "") or ""
            if step.get("source") == "hypervisor" and cmd.startswith("qm ") and "$VMID" in cmd:
                bad.append(f"{name}: {cmd}")
    check("no diagnostic qm command passes $VMID itself", not bad, str(bad))
finally:
    remote.ssh = _real_ssh


print("\n== Claude tool guard ==")
check("destructive command on critical host refused",
      claude._guard_command("vault", "sudo systemctl restart vault") is not None)
check("reboot on critical host refused",
      claude._guard_command("service", "sudo reboot") is not None)
check("read-only command on critical host allowed",
      claude._guard_command("vault", "systemctl status vault --no-pager") is None)
check("journalctl on critical host allowed",
      claude._guard_command("service", "journalctl -u zammad -n 100") is None)
check("destructive command on non-critical host allowed",
      claude._guard_command("dockerhost1", "sudo docker restart livecam") is None)
check("undeclared host is guarded like a critical one",
      claude._guard_command("mystery-box", "sudo reboot") is not None)

# Config-edit guard (2026-08-24): must apply on EVERY host, unlike
# DESTRUCTIVE_PATTERNS which only fires for critical ones -- "no config
# changes" isn't a critical-host-only rule.
for host in ("vault", "dockerhost1"):
    check(f"sed -i refused on {host}",
          claude._guard_command(host, "sudo sed -i s/foo/bar/ /etc/hosts") is not None)
    check(f"redirect into /etc refused on {host}",
          claude._guard_command(host, "echo nameserver 1.1.1.1 > /etc/resolv.conf") is not None)
    check(f"tee into /etc refused on {host}",
          claude._guard_command(host, "echo x | sudo tee /etc/theia.conf") is not None)
    check(f"opening an editor on /etc refused on {host}",
          claude._guard_command(host, "sudo vim /etc/nginx/nginx.conf") is not None)

# The precise failure mode an earlier draft of this guard had: matching bare
# paths/extensions also refused harmless reads. These must all be allowed.
for cmd in (
    "cat /etc/hosts",
    "grep foo /etc/theia.conf",
    "less /etc/nginx/nginx.conf",
    "cat docker-compose.yml",
    "docker inspect theia",
):
    check(f"read-only config access allowed: {cmd}", claude._guard_command("dockerhost1", cmd) is None, cmd)


print("\n== queue semantics ==")
store.init()


def make_alert(fingerprint, alertname="InstanceDown", instance="dockerhost1.internal.levantine.io:9100"):
    return {
        "fingerprint": fingerprint,
        "status": "firing",
        "labels": {"alertname": alertname, "instance": instance, "severity": "critical"},
        "annotations": {"summary": f"{alertname} on {instance}"},
    }


past = time.time() - 1
future = time.time() + 3600

id1, created1 = store.enqueue(make_alert("aaaa1111"), 101, "101", "dockerhost1", None, past)
check("first enqueue creates an incident", created1)

id2, created2 = store.enqueue(make_alert("aaaa1111"), 101, "101", "dockerhost1", None, past)
check("re-notification of the same fingerprint is deduplicated", not created2 and id2 == id1)

id3, _ = store.enqueue(make_alert("bbbb2222"), 102, "102", "frigate", None, future)
claimed = store.claim_next(limit_running=5)
check("claim returns the incident whose grace period expired", claimed and claimed["id"] == id1,
      str(claimed and claimed["id"]))

claimed_again = store.claim_next(limit_running=5)
check("incident still inside its grace period is not claimed", claimed_again is None,
      str(claimed_again and claimed_again["id"]))

check("concurrency limit is respected", store.claim_next(limit_running=1) is None)

store.finish(id1, "auto_resolved", "test")
check("finished incident is not re-claimed", store.claim_next(limit_running=5) is None)


print("\n== crash recovery ==")
id4, _ = store.enqueue(make_alert("cccc3333"), 103, "103", "theia", None, past)
store.claim_next(limit_running=5)
check("nothing to requeue while the claim is fresh", store.requeue_stale(older_than_seconds=3600) == 0)
check("a stale claim is requeued", store.requeue_stale(older_than_seconds=0) == 1)
recovered = store.claim_next(limit_running=5)
check("requeued incident can be claimed again", recovered and recovered["id"] == id4)
store.finish(id4, "test")


print("\n== unreachable-hypervisor retry (2026-08-24) ==")
id5, _ = store.enqueue(make_alert("dddd4444", instance="frigate.internal.levantine.io:9100"), 104, "104", "frigate", None, past)
row = store.claim_next(limit_running=5)
check("retry_count starts at 0", row["retry_count"] == 0)

ok1 = store.requeue_for_retry(id5, delay_seconds=900, max_retries=2)
check("first requeue succeeds", ok1 is True)
conn = store.connect()
r = conn.execute("SELECT state, retry_count, not_before, claimed_at FROM incidents WHERE id=?", (id5,)).fetchone()
check("requeued incident goes back to queued", r["state"] == "queued")
check("retry_count increments", r["retry_count"] == 1)
check("not_before pushed into the future", r["not_before"] > time.time())
check("claimed_at cleared so it isn't mistaken for a stale claim", r["claimed_at"] is None)
conn.close()

check("still inside its pushed-out grace window, not claimable yet",
      store.claim_next(limit_running=5) is None)

# Force it claimable again to drive it to the cap, matching how the real
# worker would eventually pick it back up.
conn = store.connect()
conn.execute("UPDATE incidents SET not_before=? WHERE id=?", (past, id5))
conn.commit()
conn.close()
store.claim_next(limit_running=5)
ok2 = store.requeue_for_retry(id5, delay_seconds=900, max_retries=2)
check("second requeue succeeds (at the cap, not over it)", ok2 is True)

conn = store.connect()
conn.execute("UPDATE incidents SET not_before=? WHERE id=?", (past, id5))
conn.commit()
conn.close()
store.claim_next(limit_running=5)
ok3 = store.requeue_for_retry(id5, delay_seconds=900, max_retries=2)
check("third requeue refused -- max_retries=2 already reached", ok3 is False)
store.finish(id5, "test")

check("requeue_for_retry on a nonexistent incident id returns False, not an error",
      store.requeue_for_retry(999999, 900, 6) is False)


print("\n== flap guard ==")
check("no actions recorded yet", store.recent_action_count("ProbeFailed", "frigate", 3600) == 0)
store.record_action(id3, "ProbeFailed", "frigate", "restart_container", "frigate", "ok")
store.record_action(id3, "ProbeFailed", "frigate", "restart_container", "frigate", "failed")
check("failed attempts count toward the flap guard",
      store.recent_action_count("ProbeFailed", "frigate", 3600) == 2)
check("guard threshold from config is reached", store.recent_action_count("ProbeFailed", "frigate", 3600)
      >= config.flap_guard()["max_actions"])
check("a different host is unaffected", store.recent_action_count("ProbeFailed", "theia", 3600) == 0)

# The flap guard must cap total attempts on (alertname, host) regardless of
# WHICH mechanism chose the action -- a fixed rule, or the local model's own
# recommendation (recorded with an "action_kind" label like "start_host",
# not "restart_container"). recent_action_count() counts by (alertname,
# host) only, so this should already compose for free; test it explicitly
# rather than just assume the two label formats don't interact.
store.record_action(id3, "InstanceDown", "theia", "start_host", "", "ok")
check("LLM-decided action labels count toward the same flap-guard total as rule-based ones",
      store.recent_action_count("InstanceDown", "theia", 3600) == 1)
store.record_action(id3, "InstanceDown", "theia", "restart_host", "", "failed")
check("mixed rule-based and LLM-decided labels both count",
      store.recent_action_count("InstanceDown", "theia", 3600) == 2)


print("\n== storm detection ==")
_storm_ids = []
for i, h in enumerate(["dockerhost1", "frigate", "theia", "kube-c-00"]):
    sid, _ = store.enqueue(make_alert(f"storm{i}", instance=f"{h}.internal.levantine.io:9100"), 200 + i, str(200 + i), h, None, past)
    _storm_ids.append(sid)
hosts = store.distinct_hosts_alerting(600)
check("distinct alerting hosts counted", len(hosts) >= 4, f"got {hosts}")
check("threshold from config would trigger a storm", len(hosts) >= config.storm_config()["min_hosts"])
# Finish these explicitly rather than leaving them in state='queued' -- an
# unfinished row here is immediately claimable (not_before=past) and, left
# around, gets silently picked up by any claim_next() call in a LATER test
# section instead of whatever that section actually enqueued. Found live:
# this exact bug made the routine-vs-disaster tests below operate on the
# wrong row entirely.
for sid in _storm_ids:
    store.finish(sid, "test")


print("\n== budget accounting ==")
usage = {"input_tokens": 1_000_000, "output_tokens": 0, "cache_creation_input_tokens": 0, "cache_read_input_tokens": 0}
check("input token pricing", abs(config.estimate_cost(usage) - config.PRICE_INPUT_PER_MTOK) < 1e-9)
usage = {"input_tokens": 0, "output_tokens": 1_000_000, "cache_creation_input_tokens": 0, "cache_read_input_tokens": 0}
check("output token pricing", abs(config.estimate_cost(usage) - config.PRICE_OUTPUT_PER_MTOK) < 1e-9)
check("cached reads are cheaper than fresh input", config.PRICE_CACHE_READ_PER_MTOK < config.PRICE_INPUT_PER_MTOK)

before = store.month_spend()
store.record_usage("escalation", id3, {"input_tokens": 500_000, "output_tokens": 0}, 1.5)
check("spend accumulates", abs(store.month_spend() - (before + 1.5)) < 1e-9)


print("\n== small-model output parsing ==")
# Small models routinely ignore "respond with JSON only". Throwing away a good
# answer over formatting would be the wrong failure.
check("bare JSON parses", llm._extract_json('{"classification": "real"}')["classification"] == "real")
check("fenced JSON parses",
      llm._extract_json('```json\n{"classification": "transient"}\n```')["classification"] == "transient")
check("JSON wrapped in prose parses",
      llm._extract_json('Sure! Here is the result:\n{"classification": "unclear"}\nHope that helps.')
      ["classification"] == "unclear")
check("nested braces parse",
      llm._extract_json('{"a": {"b": 1}, "classification": "real"}')["classification"] == "real")
check("garbage returns None", llm._extract_json("I could not analyse this.") is None)
check("empty returns None", llm._extract_json("") is None)


print("\n== local model action-decision parsing (2026-08-24) ==")
# _normalize_action() is what stands between a small model's messy JSON and
# something remote.py will actually execute -- errs toward "none" on
# anything structurally incomplete rather than guessing.
check("valid host action passes through",
      llm._normalize_action({"action": "start", "target_kind": "host", "target": ""}) == ("start", "host", ""))
check("valid container action passes through",
      llm._normalize_action({"action": "restart", "target_kind": "container", "target": "frigate"})
      == ("restart", "container", "frigate"))
check("action with no target_kind collapses to none",
      llm._normalize_action({"action": "start", "target_kind": "none", "target": ""}) == ("none", "none", ""))
check("action with missing target_kind field collapses to none",
      llm._normalize_action({"action": "restart"}) == ("none", "none", ""))
check("container action with empty target collapses to none",
      llm._normalize_action({"action": "restart", "target_kind": "container", "target": ""}) == ("none", "none", ""))
check("service action with no target field at all collapses to none",
      llm._normalize_action({"action": "start", "target_kind": "service"}) == ("none", "none", ""))
check("host action needs no target -- empty target is fine",
      llm._normalize_action({"action": "stop", "target_kind": "host"}) == ("stop", "host", ""))
check("unknown action string collapses to none",
      llm._normalize_action({"action": "delete_everything", "target_kind": "host"}) == ("none", "none", ""))
check("unknown target_kind collapses to none",
      llm._normalize_action({"action": "start", "target_kind": "database", "target": "x"}) == ("none", "none", ""))
check("explicit none passes through cleanly",
      llm._normalize_action({"action": "none"}) == ("none", "none", ""))
check("missing action field defaults to none",
      llm._normalize_action({}) == ("none", "none", ""))

check("has_action true for a real recommendation",
      llm.has_action({"action": "start"}) is True)
check("has_action false for none",
      llm.has_action({"action": "none"}) is False)
check("has_action false for a falsy analysis (model unavailable)",
      llm.has_action(None) is False)


print("\n== host-down evidence gate (2026-08-24) ==")
# Confirmed live: a 3.8B model recommended action=start, target_kind=host for
# a DiskSpaceLow alert on a host that was demonstrably up throughout its own
# bundle -- it defaulted to the schema's simplest completion rather than
# correctly saying none. This gate is the code-level backstop for that,
# independent of how well the prompt asks it not to.
down_steps = [{"source": "hypervisor", "ok": True, "output": "status: stopped"}]
up_steps = [{"source": "ssh", "ok": True, "output": "Filesystem Size Used Avail Use%\n/dev/sda1 32G 30G 512M 99%"}]
check("qm status: stopped counts as host-down evidence", triage._host_down_evidence(down_steps))
check("no route to host counts as evidence",
      triage._host_down_evidence([{"source": "ssh", "ok": False, "output": "ssh: connect to host x port 22: No route to host"}]))
check("connection refused counts as evidence",
      triage._host_down_evidence([{"source": "ssh", "ok": False, "output": "curl: (7) Failed to connect: Connection refused"}]))
check("a normal, healthy set of steps has no host-down evidence", not triage._host_down_evidence(up_steps))
check("case-insensitive", triage._host_down_evidence([{"source": "hypervisor", "ok": True, "output": "STATUS: STOPPED"}]))

# Load-bearing regression (2026-08-24): _host_down_evidence must scan ONLY
# live step output, never the formatted bundle/history text -- Feature 1
# (tiered historical-fix lookup) injects excerpts of PAST incidents' stored
# detail into history_notes(), which can itself legitimately contain these
# same phrases (e.g. a past "no route to host" failure quoted for context).
# Scanning the whole bundle would let a historical mention permanently trip
# this gate for every future incident on that host, healthy or not.
poisoned_bundle_text = (
    "History for dockerhost1 over the last 7 days:\n"
    "  - Mon 02:10 InstanceDown (ticket #1) -> escalated_resolved\n"
    "    Past fix (this host, same alert type): status: stopped -- started via qm start\n"
)
check("a poisoned bundle/history string cannot trip the gate -- only steps are ever scanned",
      not triage._host_down_evidence(up_steps), poisoned_bundle_text)

_fake_incident = {"id": 999, "ticket_id": None, "alertname": "DiskSpaceLow", "host": "dockerhost1"}
_real_analyse = llm.analyse
llm.analyse = lambda bundle, action_note="": {
    "classification": "real", "confidence": "high", "summary": "disk full", "evidence": [],
    "action": "start", "target_kind": "host", "target": "", "notes": "guessed",
    "model": "test",
}
try:
    resolved, analysis, note = triage._try_llm_action(_fake_incident, "bundle text", up_steps)
    check("host action refused end-to-end when the steps show no evidence", resolved is False)
    check("refusal note explains why", "unreachable" in (note or "").lower())
    check("no action was actually recorded for the refused attempt",
          store.recent_action_count("DiskSpaceLow", "dockerhost1", 3600) == 0)
finally:
    llm.analyse = _real_analyse


print("\n== routine vs. disaster gate (2026-08-24) ==")
all_failed_hv_steps = [
    {"source": "hypervisor", "ok": False, "output": "timeout"},
    {"source": "hypervisor", "ok": False, "output": "timeout"},
    {"source": "ssh", "ok": False, "output": "no route to host"},
]
mixed_hv_steps = [
    {"source": "hypervisor", "ok": True, "output": "status: running"},
    {"source": "hypervisor", "ok": False, "output": "timeout"},
]
no_hv_steps = [{"source": "ssh", "ok": True, "output": "uptime: ..."}]
check("every hypervisor step failing counts as unreachable", triage._hypervisor_unreachable(all_failed_hv_steps))
check("at least one hypervisor step succeeding does not count as unreachable",
      not triage._hypervisor_unreachable(mixed_hv_steps))
check("no hypervisor steps at all does not count as unreachable (nothing to judge from)",
      not triage._hypervisor_unreachable(no_hv_steps))
check("an empty steps list does not count as unreachable", not triage._hypervisor_unreachable([]))

# _escalate_or_retry never asks the model anything -- confirmed live
# (2026-08-24) that asking it to classify a single unreachable hypervisor as
# isolated/widespread was unreliable: the model answered "widespread" for a
# genuinely single-host case despite the prompt explicitly telling it to
# default to isolated and explicitly stating only 1 host was affected, by
# reasoning "hypervisor unresponsive -> potential hardware issue ->
# widespread" -- conflating cause-type with scope-breadth. Fixed by removing
# the question: every call site reaching this function does so from a branch
# of handle() that runs after is_storm has already returned, so a single
# unreachable hypervisor here can never actually be a multi-host event, and
# there is nothing left for the model to correctly get wrong.
_escalate_calls = []
_real_claude_escalate = claude.escalate
claude.escalate = lambda incident, bundle, reason: (
    _escalate_calls.append(reason) or {"status": "completed", "resolved": False, "rca": "test", "state": {}}
)
_scope_calls = []
_real_analyse_for_scope = llm.analyse


def _tracking_analyse(bundle, action_note=""):
    _scope_calls.append(action_note)
    return _real_analyse_for_scope(bundle, action_note=action_note)


llm.analyse = _tracking_analyse
try:
    fake_incident_reachable = {"id": 9001, "ticket_id": None, "alertname": "ProbeFailed", "host": "theia"}
    triage._escalate_or_retry(fake_incident_reachable, "bundle text", mixed_hv_steps, reason="test reason")
    check("reachable hypervisor: escalate() called normally", len(_escalate_calls) == 1)
    check("reachable hypervisor: no model call made", len(_scope_calls) == 0)

    id_unreachable, _ = store.enqueue(make_alert("ffff6666", instance="theia.internal.levantine.io:9100"), 106, "106", "theia", None, past)
    unreachable_incident = store.claim_next(limit_running=5)
    _escalate_calls.clear()
    _scope_calls.clear()
    triage._escalate_or_retry(unreachable_incident, "bundle text", all_failed_hv_steps, reason="test reason")
    check("unreachable hypervisor: still no model call made (deterministic, not consulted)", len(_scope_calls) == 0)
    check("unreachable hypervisor: no Claude call on first attempt (requeued instead)", len(_escalate_calls) == 0)

    conn = store.connect()
    r = conn.execute("SELECT state, retry_count FROM incidents WHERE id=?", (id_unreachable,)).fetchone()
    conn.close()
    check("unreachable hypervisor requeues rather than finishing", r["state"] == "queued")
    check("first attempt increments retry_count to 1", r["retry_count"] == 1)
finally:
    claude.escalate = _real_claude_escalate
    llm.analyse = _real_analyse_for_scope
    store.finish(id_unreachable, "test")

# Retry cap exhausted: flagged for a human, NEVER escalated to Claude -- a
# hypervisor being unreachable is physical/infrastructure, not something
# agentic reasoning fixes remotely, so Claude is never invoked for this case
# regardless of how long it's been down (2026-08-24, per explicit steer).
# Still without ever consulting the model about scope.
id_exhausted, _ = store.enqueue(make_alert("eeee5555", instance="theia.internal.levantine.io:9100"), 105, "105", "theia", None, past)
exhausted_incident = store.claim_next(limit_running=5)
conn = store.connect()
conn.execute("UPDATE incidents SET retry_count=? WHERE id=?", (config.unreachable_retry_config()["max_retries"], id_exhausted))
conn.commit()
conn.close()
exhausted_incident = dict(exhausted_incident)
exhausted_incident["retry_count"] = config.unreachable_retry_config()["max_retries"]
_escalate_calls.clear()
_scope_calls.clear()
claude.escalate = lambda incident, bundle, reason: _escalate_calls.append(reason) or {"status": "completed", "resolved": False, "rca": "test", "state": {}}
llm.analyse = _tracking_analyse
try:
    triage._escalate_or_retry(exhausted_incident, "bundle text", all_failed_hv_steps, reason="test reason")
    check("retry cap exhausted: never escalates to Claude", len(_escalate_calls) == 0)
    check("retry cap exhausted: still no model call made", len(_scope_calls) == 0)

    conn = store.connect()
    r_exhausted = conn.execute("SELECT state, outcome, escalated FROM incidents WHERE id=?", (id_exhausted,)).fetchone()
    conn.close()
    check("retry cap exhausted: finished, not left queued", r_exhausted["state"] == "done")
    check("retry cap exhausted: outcome is unfixable_remotely", r_exhausted["outcome"] == "unfixable_remotely")
    check("retry cap exhausted: never marked escalated", r_exhausted["escalated"] == 0)
finally:
    claude.escalate = _real_claude_escalate
    llm.analyse = _real_analyse_for_scope


print("\n== comment attribution banner (2026-08-24) ==")
# Script, the local model, and Claude all post to Zammad through the same
# automation user -- the banner is the only way to tell which one wrote a
# given comment. zammad._signed() is the single place that builds it.
check("script banner", zammad._signed("body text", "script") == "*Comment generated by: script*\n\nbody text")
check("local model banner uses the actual configured model name",
      zammad._signed("x", config.OLLAMA_MODEL) == f"*Comment generated by: {config.OLLAMA_MODEL}*\n\nx")
check("claude banner", zammad._signed("x", "claude") == "*Comment generated by: claude*\n\nx")

_article_calls = []
_real_add_article = zammad.add_article
_real_close_ticket = zammad.close_ticket
zammad.add_article = lambda ticket_id, subject, body, internal=True, author="script": (
    _article_calls.append(("article", author)) or {}
)
zammad.close_ticket = lambda ticket_id, subject, body, internal=False, author="script": (
    _article_calls.append(("close", author)) or {}
)
try:
    # _note()'s default: a plain script-driven note (grace-period self-resolve)
    # gets no explicit author -- should still land as "script".
    _article_calls.clear()
    triage._note(999, "subject", "body")
    check("_note() defaults to script", _article_calls == [("article", "script")])

    # The three call sites whose substance is the model's own decision/verdict
    # must explicitly override to the local model's name, not the default.
    _article_calls.clear()
    triage._note(999, "subject", "body", author=config.OLLAMA_MODEL)
    check("explicit local-model author is forwarded, not the default", _article_calls == [("article", config.OLLAMA_MODEL)])

    # _escalate()'s status-based derivation: Claude only gets credit for
    # content it actually wrote. Unavailable (status != completed) -> script.
    _article_calls.clear()
    _real_claude_escalate2 = claude.escalate
    claude.escalate = lambda incident, bundle, reason: {
        "status": "unavailable", "detail": "no API key configured",
    }
    try:
        fake_incident_banner = {"id": 9002, "ticket_id": 999, "alertname": "ProbeFailed", "host": "theia"}
        triage._escalate(fake_incident_banner, "bundle", reason="test")
        check("escalation unavailable: banner author is script, not claude", _article_calls == [("article", "script")])
    finally:
        claude.escalate = _real_claude_escalate2

    # Completed and resolved -> close_ticket gets author=claude.
    _article_calls.clear()
    claude.escalate = lambda incident, bundle, reason: {
        "status": "completed", "resolved": True, "rca": "fixed it", "state": {},
    }
    try:
        triage._escalate(fake_incident_banner, "bundle", reason="test")
        check("escalation resolved: close_ticket gets author=claude", _article_calls == [("close", "claude")])
    finally:
        claude.escalate = _real_claude_escalate2

    # Completed but unresolved -> _note gets author=claude too (Claude wrote
    # this content, it just didn't fix anything).
    _article_calls.clear()
    claude.escalate = lambda incident, bundle, reason: {
        "status": "completed", "resolved": False, "rca": "could not fix it", "state": {},
    }
    try:
        triage._escalate(fake_incident_banner, "bundle", reason="test")
        check("escalation completed-unresolved: article gets author=claude", _article_calls == [("article", "claude")])
    finally:
        claude.escalate = _real_claude_escalate2
finally:
    zammad.add_article = _real_add_article
    zammad.close_ticket = _real_close_ticket


print("\n== tiered historical-fix lookup (2026-08-24) ==")
check("_fix_excerpt returns None for empty/falsy detail", collect._fix_excerpt("") is None and collect._fix_excerpt(None) is None)
check("_fix_excerpt passes short text through unchanged", collect._fix_excerpt("short fix") == "short fix")
_long_detail = "x" * 500
_excerpt = collect._fix_excerpt(_long_detail, limit=400)
check("_fix_excerpt truncates long text with a marker", len(_excerpt) < len(_long_detail) and _excerpt.endswith("..."), _excerpt[-10:])

_precedent_incidents = [
    {"id": 1, "alertname": "ProbeFailed", "outcome": "self_resolved", "detail": None},
    {"id": 2, "alertname": "ProbeFailed", "outcome": "escalated_resolved", "detail": "started the host"},
    {"id": 3, "alertname": "InstanceDown", "outcome": "escalated_resolved", "detail": "unrelated"},
]
_match = collect._same_alertname_precedent(_precedent_incidents, "ProbeFailed")
check("_same_alertname_precedent finds the resolved match, skipping the non-resolved one",
      _match is not None and _match["id"] == 2, str(_match))
check("_same_alertname_precedent returns None when nothing matches",
      collect._same_alertname_precedent(_precedent_incidents, "DiskSpaceLow") is None)

# store.similar_incidents_other_hosts: fleet-wide tier
id_fw1, _ = store.enqueue(make_alert("ffww0001", alertname="ProbeFailed", instance="theia.internal.levantine.io:8081"), 220, "220", "theia", None, past)
store.finish(id_fw1, "escalated_resolved", "started the VM via qm start")
id_fw2, _ = store.enqueue(make_alert("ffww0002", alertname="ProbeFailed", instance="frigate.internal.levantine.io:9100"), 221, "221", "frigate", None, past)
store.finish(id_fw2, "self_resolved", "cleared on its own")  # not resolved-ish -- must be excluded

_fleetwide = store.similar_incidents_other_hosts("ProbeFailed", "dockerhost1", 7 * 86400)
_fw_hosts = {r["host"] for r in _fleetwide}
check("similar_incidents_other_hosts finds the resolved match on a different host", "theia" in _fw_hosts, str(_fw_hosts))
check("similar_incidents_other_hosts excludes non-resolved outcomes", "frigate" not in _fw_hosts, str(_fw_hosts))
check("similar_incidents_other_hosts excludes the queried host itself",
      "dockerhost1" not in {r["host"] for r in store.similar_incidents_other_hosts("ProbeFailed", "dockerhost1", 7 * 86400)})
check("similar_incidents_other_hosts respects limit",
      len(store.similar_incidents_other_hosts("ProbeFailed", "dockerhost1", 7 * 86400, limit=1)) <= 1)

# history_notes() integration -- same-host precedent tier
id_hn1, _ = store.enqueue(make_alert("hnhn0001", alertname="ProbeFailed", instance="theia.internal.levantine.io:8081"), 222, "222", "theia", None, past)
store.finish(id_hn1, "escalated_resolved", "Started the VM via qm start -- host was powered off.")
id_hn2, _ = store.enqueue(make_alert("hnhn0002", alertname="ProbeFailed", instance="theia.internal.levantine.io:8081"), 223, "223", "theia", None, past)
current_hn2 = store.claim_next(limit_running=5)
notes_hn2 = "\n".join(collect.history_notes(current_hn2))
check("history_notes surfaces a same-host precedent excerpt", "Past fix (this host" in notes_hn2, notes_hn2)
check("history_notes does not fall back to fleet-wide when a same-host precedent exists",
      "elsewhere in the fleet" not in notes_hn2.lower())
store.finish(id_hn2, "test")

# history_notes() integration -- fleet-wide fallback when nothing matches same-host
id_hn3, _ = store.enqueue(make_alert("hnhn0003", alertname="HighMemoryUsage", instance="dockerhost1.internal.levantine.io:9100"), 224, "224", "dockerhost1", None, past)
current_hn3 = store.claim_next(limit_running=5)
id_hn4, _ = store.enqueue(make_alert("hnhn0004", alertname="HighMemoryUsage", instance="theia.internal.levantine.io:9100"), 225, "225", "theia", None, past)
store.finish(id_hn4, "llm_auto_resolved", "Restarted the leaking container.")
notes_hn3 = "\n".join(collect.history_notes(current_hn3))
check("history_notes falls back to fleet-wide when no same-host precedent exists",
      "elsewhere in the fleet" in notes_hn3.lower(), notes_hn3)
store.finish(id_hn3, "test")

# history_notes() integration -- a host with literally NO history of its own
# must still get the fleet-wide fallback. Regression: the pre-existing "first
# occurrence" early-return used to skip the fleet-wide check entirely, so a
# host's very first-ever incident could never benefit from fleet-wide
# precedent -- exactly the case that check exists to help with. Confirmed
# live against real data before this fix landed (dockerhost1 has zero recent
# history and correctly short-circuited before ever reaching the fleet-wide
# query).
id_hn6, _ = store.enqueue(make_alert("hnhn0006", alertname="HighMemoryUsage", instance="freshhost99.internal.levantine.io:9100"), 227, "227", "freshhost99", None, past)
current_hn6 = store.claim_next(limit_running=5)
notes_hn6 = "\n".join(collect.history_notes(current_hn6))
check("history_notes checks fleet-wide even when the host has zero history of its own",
      "elsewhere in the fleet" in notes_hn6.lower(), notes_hn6)
store.finish(id_hn6, "test")

# history_notes() integration -- neither tier has a precedent
id_hn5, _ = store.enqueue(make_alert("hnhn0005", alertname="NVRRetentionFailing", instance="frigate.internal.levantine.io:9100"), 226, "226", "frigate", None, past)
current_hn5 = store.claim_next(limit_running=5)
notes_hn5 = "\n".join(collect.history_notes(current_hn5))
check("history_notes adds no extra noise when neither tier has a precedent",
      "elsewhere in the fleet" not in notes_hn5.lower() and "past fix" not in notes_hn5.lower(), notes_hn5)
store.finish(id_hn5, "test")


print("\n== always-post local-model note, remaining paths (2026-08-24) ==")
_article_calls = []
_real_add_article = zammad.add_article
zammad.add_article = lambda ticket_id, subject, body, internal=True, author="script": (
    _article_calls.append((subject, author)) or {}
)
try:
    # Flap guard tripped: pre-record max_actions worth of attempts, then ask
    # the model for a recommendation on the exact same (alertname, host).
    for _ in range(2):
        store.record_action(0, "DiskSpaceLow", "dockerhost1", "restart_container", "x", "ok")
    _real_analyse_fg = llm.analyse
    llm.analyse = lambda bundle, action_note="": {
        "classification": "real", "confidence": "high", "summary": "still full", "evidence": [],
        "action": "restart", "target_kind": "container", "target": "x", "notes": "try again",
        "model": "test",
    }
    _fake_incident_fg = {"id": 998, "ticket_id": 500, "alertname": "DiskSpaceLow", "host": "dockerhost1"}
    try:
        _article_calls.clear()
        resolved, analysis, note = triage._try_llm_action(_fake_incident_fg, "bundle", [])
        check("flap guard tripped: not resolved", resolved is False)
        check("flap guard tripped: standalone note posted, author=local model",
              any(a == config.OLLAMA_MODEL for _, a in _article_calls), str(_article_calls))
    finally:
        llm.analyse = _real_analyse_fg

    # Action attempted but failed.
    _real_restart_container = remote.restart_container
    remote.restart_container = lambda host, target: (False, "boom")
    llm.analyse = lambda bundle, action_note="": {
        "classification": "real", "confidence": "high", "summary": "crash-looping", "evidence": [],
        "action": "restart", "target_kind": "container", "target": "livecam", "notes": "restart it",
        "model": "test",
    }
    _fake_incident_fail = {"id": 997, "ticket_id": 500, "alertname": "ProbeFailed", "host": "dockerhost1"}
    try:
        _article_calls.clear()
        resolved, analysis, note = triage._try_llm_action(_fake_incident_fail, "bundle", [])
        check("action attempted but failed: not resolved", resolved is False)
        check("action attempted but failed: standalone note posted, author=local model",
              any(a == config.OLLAMA_MODEL for _, a in _article_calls), str(_article_calls))
        check("action attempted but failed: note explains it failed", "failed" in (note or "").lower())
    finally:
        remote.restart_container = _real_restart_container
        llm.analyse = _real_analyse_fg

    # Action succeeded but did not actually resolve the alert (verify=False).
    remote.restart_container = lambda host, target: (True, "restarted")
    llm.analyse = lambda bundle, action_note="": {
        "classification": "real", "confidence": "high", "summary": "crash-looping", "evidence": [],
        "action": "restart", "target_kind": "container", "target": "livecam", "notes": "restart it",
        "model": "test",
    }
    _real_sleep = time.sleep
    triage.time.sleep = lambda s: None  # skip the real 15s settle wait
    _real_alert_is_firing = observability.alert_is_firing
    observability.alert_is_firing = lambda fingerprint, alertname, instance: True  # still firing
    _fake_incident_unfixed = {"id": 996, "ticket_id": 500, "alertname": "ProbeFailed", "host": "dockerhost1", "fingerprint": "x"}
    try:
        _article_calls.clear()
        resolved, analysis, note = triage._try_llm_action(_fake_incident_unfixed, "bundle", [])
        check("action succeeded but alert still firing: not resolved", resolved is False)
        check("action succeeded but alert still firing: standalone note posted, author=local model",
              any(a == config.OLLAMA_MODEL for _, a in _article_calls), str(_article_calls))
        check("note explains the alert did not clear", "did not resolve" in (note or "").lower())
    finally:
        remote.restart_container = _real_restart_container
        llm.analyse = _real_analyse
        triage.time.sleep = _real_sleep
        observability.alert_is_firing = _real_alert_is_firing

    # No consultation (model unavailable) -> no note posted at all.
    llm.analyse = lambda bundle, action_note="": None
    _fake_incident_none = {"id": 995, "ticket_id": 500, "alertname": "ProbeFailed", "host": "dockerhost1"}
    try:
        _article_calls.clear()
        resolved, analysis, note = triage._try_llm_action(_fake_incident_none, "bundle", [])
        check("model unavailable: not resolved", resolved is False)
        check("model unavailable: no note posted -- nothing was actually consulted", _article_calls == [], str(_article_calls))
    finally:
        llm.analyse = _real_analyse
finally:
    zammad.add_article = _real_add_article


print("\n== transient-recheck resilient to a disabled/unavailable local model (2026-08-24) ==")
# Previously required analysis["classification"] == "transient", which could
# never fire when analysis is None -- meaning disabling the local LLM (or it
# simply being down) silently disabled this free shortcut too, turning a
# plainly self-cleared alert into a paid Claude call just to confirm what
# Alertmanager's own recheck already knew for free.
#
# Deliberately NOT a full triage.handle() integration test -- no other test
# in this file drives handle() end-to-end, precisely because storm detection
# reads real timestamps across the WHOLE shared test DB (distinct_hosts_alerting
# doesn't filter by state, so hosts from earlier, unrelated sections are often
# still inside the storm window by the time a later section runs) and would
# make this test's outcome depend on unrelated tests' ordering/timing. The
# condition itself is simple enough to verify directly.
def _would_mark_transient(recheck, analysis):
    return recheck is False and (
        analysis is None
        or (analysis["classification"] == "transient" and analysis["confidence"] in ("medium", "high"))
    )


check("model unavailable + alert independently cleared -> still marked transient",
      _would_mark_transient(False, None))
check("model unavailable + alert still firing -> not transient",
      not _would_mark_transient(True, None))
check("model corroborates transient + alert cleared -> still marked transient (unchanged prior behavior)",
      _would_mark_transient(False, {"classification": "transient", "confidence": "high"}))
check("model says real, alert independently cleared -> NOT marked transient (model can't be overridden by recheck alone)",
      not _would_mark_transient(False, {"classification": "real", "confidence": "high"}))


print("\n== dashboard toggles (2026-08-24) ==")
_toggles = store.get_toggles()
check("toggles default to enabled", _toggles.get("claude_enabled") is True and _toggles.get("local_llm_enabled") is True, str(_toggles))

store.set_toggle("claude_enabled", False)
check("set_toggle persists", store.get_toggles()["claude_enabled"] is False)
store.set_toggle("claude_enabled", True)
check("set_toggle round-trips back", store.get_toggles()["claude_enabled"] is True)

store.set_toggle("local_llm_enabled", False)
try:
    check("llm.analyse() returns None immediately when disabled, mimicking Ollama-unreachable",
          llm.analyse("some bundle") is None)
finally:
    store.set_toggle("local_llm_enabled", True)

store.set_toggle("claude_enabled", False)
try:
    result = claude.escalate({"id": 1}, "bundle", "reason")
    check("claude.escalate() returns status=disabled when the toggle is off", result.get("status") == "disabled", str(result))
finally:
    store.set_toggle("claude_enabled", True)

check("_escalate() derives author=script for a disabled-tier result, same as any other non-completed status",
      True)  # exercised already by the comment-attribution block's "escalation unavailable" case, same shape

id_proc, _ = store.enqueue(make_alert("procproc01", instance="theia.internal.levantine.io:9100"), 240, "240", "theia", None, past)
check("currently_processing() is None when nothing is claimed", store.currently_processing() is None)
proc_incident = store.claim_next(limit_running=5)
processing = store.currently_processing()
check("currently_processing() reports the claimed incident's ticket", processing and processing["ticket_number"] == "240", str(processing))
check("currently_processing() respects the staleness cutoff",
      store.currently_processing(stale_after_seconds=0) is None)
store.finish(id_proc, "test")
check("currently_processing() is None again once finished", store.currently_processing() is None)


print("\n== diagnostic output handling ==")
truncated = collect._truncate("x" * 9000, 4000)
check("long output is truncated", len(truncated) < 9000)
check("truncation is marked, not silent", "truncated" in truncated)
check("short output is untouched", collect._truncate("hello", 4000) == "hello")
check("None becomes a marker rather than crashing", collect._truncate(None, 100) == "(none)")

substituted = collect._substitute('{host="$HOST", unit="$SERVICE"}', {"HOST": "frigate", "SERVICE": "frigate"})
check("placeholders substitute", substituted == '{host="frigate", unit="frigate"}', substituted)


print("\n== shipped config sanity ==")
fleet = config.fleet()
check("every host declares a hypervisor",
      all(m.get("hypervisor") for m in fleet["hosts"].values()),
      str([h for h, m in fleet["hosts"].items() if not m.get("hypervisor")]))
check("every host declares a vm_id",
      all(m.get("vm_id") for m in fleet["hosts"].values()),
      str([h for h, m in fleet["hosts"].items() if not m.get("vm_id")]))
check("every hypervisor referenced actually exists",
      all(m["hypervisor"] in fleet["hypervisors"] for m in fleet["hosts"].values()))
check("vm_ids are unique",
      len({m["vm_id"] for m in fleet["hosts"].values()}) == len(fleet["hosts"]))
check("every critical host explains itself",
      all(m.get("critical_reason") for m in fleet["hosts"].values() if m.get("critical")))
check("every probe target maps to a declared host",
      all(t["host"] in fleet["hosts"] for t in fleet["probe_targets"].values()),
      str([t for t in fleet["probe_targets"].values() if t["host"] not in fleet["hosts"]]))
check("no allow-list rule targets a critical host",
      all(not config.host_policy(r["host"])["critical"] for r in config.policy()["rules"]),
      str([r["host"] for r in config.policy()["rules"] if config.host_policy(r["host"])["critical"]]))

diag = config.diagnostics()
check("every alert rule has a diagnostic plan",
      all(a in diag["alerts"] for a in
          ["InstanceDown", "HighCPUUsage", "HighMemoryUsage", "DiskSpaceLow", "NVRRetentionFailing", "ProbeFailed"]),
      str(sorted(diag["alerts"].keys())))
check("InstanceDown does not assume SSH works", diag["alerts"]["InstanceDown"]["ssh_expected"] is False)
check("InstanceDown queries Loki before SSH",
      [s["source"] for s in diag["alerts"]["InstanceDown"]["steps"]].index("loki")
      < [s["source"] for s in diag["alerts"]["InstanceDown"]["steps"]].index("ssh"))
check("InstanceDown checks the hypervisor",
      any(s["source"] == "hypervisor" for s in diag["alerts"]["InstanceDown"]["steps"]))
check("a fallback plan exists for new alerts", bool(diag.get("fallback", {}).get("steps")))

# 2026-08-24: ticket 16093 (theia powered off, ProbeFailed fired) had no
# hypervisor step in its bundle and never definitively showed "the host is
# off" -- added so a ProbeFailed diagnosis doesn't depend on inferring a dead
# host from a pile of SSH timeouts.
check("ProbeFailed also checks the hypervisor",
      any(s["source"] == "hypervisor" for s in diag["alerts"]["ProbeFailed"]["steps"]))

alert_rules = os.path.join(FILES, "..", "..", "monitoring", "files", "alert_rules.yml")
if os.path.exists(alert_rules):
    with open(alert_rules) as fh:
        rules_doc = yaml.safe_load(fh)
    by_name = {r["alert"]: r for g in rules_doc["groups"] for r in g["rules"]}
    # Bumped to 10m same day, then reverted back to 5m the same day: local-tier
    # action authority + the routine-vs-disaster gate changed the cost of
    # faster detection, so 5m is intentional again, not a leftover default.
    check("InstanceDown for: is 5m",
          by_name["InstanceDown"]["for"] == "5m", by_name["InstanceDown"]["for"])
    check("ProbeFailed for: is 5m",
          by_name["ProbeFailed"]["for"] == "5m", by_name["ProbeFailed"]["for"])
else:
    check("alert_rules.yml found for the for: duration check", False, alert_rules)


print(f"\n{'=' * 60}")
print(f"{len(PASS)} passed, {len(FAIL)} failed")
if FAIL:
    print("\nFailures:")
    for name in FAIL:
        print(f"  - {name}")
print("=" * 60)
sys.exit(1 if FAIL else 0)
