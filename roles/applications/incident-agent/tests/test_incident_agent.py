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

HERE = os.path.dirname(os.path.abspath(__file__))
FILES = os.path.join(os.path.dirname(HERE), "files")

# Must be set before importing config -- it reads the environment at import.
os.environ["IA_CONFIG_DIR"] = FILES
os.environ["IA_STATE_DIR"] = tempfile.mkdtemp(prefix="incident-agent-test-")
os.environ["IA_ZAMMAD_API_TOKEN"] = "test-token"

sys.path.insert(0, FILES)

from incident_agent import claude, collect, config, llm, remote, store  # noqa: E402

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


print("\n== flap guard ==")
check("no actions recorded yet", store.recent_action_count("ProbeFailed", "frigate", 3600) == 0)
store.record_action(id3, "ProbeFailed", "frigate", "restart_container", "frigate", "ok")
store.record_action(id3, "ProbeFailed", "frigate", "restart_container", "frigate", "failed")
check("failed attempts count toward the flap guard",
      store.recent_action_count("ProbeFailed", "frigate", 3600) == 2)
check("guard threshold from config is reached", store.recent_action_count("ProbeFailed", "frigate", 3600)
      >= config.flap_guard()["max_actions"])
check("a different host is unaffected", store.recent_action_count("ProbeFailed", "theia", 3600) == 0)


print("\n== storm detection ==")
for i, h in enumerate(["dockerhost1", "frigate", "theia", "kube-c-00"]):
    store.enqueue(make_alert(f"storm{i}", instance=f"{h}.internal.levantine.io:9100"), 200 + i, str(200 + i), h, None, past)
hosts = store.distinct_hosts_alerting(600)
check("distinct alerting hosts counted", len(hosts) >= 4, f"got {hosts}")
check("threshold from config would trigger a storm", len(hosts) >= config.storm_config()["min_hosts"])


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


print(f"\n{'=' * 60}")
print(f"{len(PASS)} passed, {len(FAIL)} failed")
if FAIL:
    print("\nFailures:")
    for name in FAIL:
        print(f"  - {name}")
print("=" * 60)
sys.exit(1 if FAIL else 0)
