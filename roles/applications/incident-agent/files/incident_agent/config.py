"""Configuration loading and the policy decisions that depend on it.

Everything that answers "may the agent do X to host Y" lives here, so that
question has exactly one implementation. The LLM tiers never make these
decisions -- they are handed the answer.
"""
import os
import yaml

CONFIG_DIR = os.environ.get("IA_CONFIG_DIR", "/etc/incident-agent")
STATE_DIR = os.environ.get("IA_STATE_DIR", "/var/lib/incident-agent")

# All read-only HTTP diagnostic sources live on `service`. Route prefixes on
# Prometheus/Alertmanager are load-bearing -- both run with --web.route-prefix,
# which covers their API surface too, so the unprefixed paths 404.
ZAMMAD_URL = os.environ.get("IA_ZAMMAD_URL", "http://service.internal.levantine.io:8080").rstrip("/")
ZAMMAD_API_TOKEN = os.environ.get("IA_ZAMMAD_API_TOKEN", "")
ZAMMAD_GROUP = os.environ.get("IA_ZAMMAD_GROUP", "Users")
ZAMMAD_CUSTOMER_EMAIL = os.environ.get("IA_ZAMMAD_CUSTOMER_EMAIL", "zammad-admin@levantine.io")

LOKI_URL = os.environ.get("IA_LOKI_URL", "http://service.internal.levantine.io:3100").rstrip("/")
PROMETHEUS_URL = os.environ.get("IA_PROMETHEUS_URL", "http://service.internal.levantine.io:9090/prometheus").rstrip("/")
ALERTMANAGER_URL = os.environ.get("IA_ALERTMANAGER_URL", "http://service.internal.levantine.io:9093/alertmanager").rstrip("/")

OLLAMA_URL = os.environ.get("IA_OLLAMA_URL", "http://127.0.0.1:11434").rstrip("/")
# Never hardcode the model anywhere else. Swapping to a better local model as
# they improve should be `ollama pull` + this one value + a service restart.
OLLAMA_MODEL = os.environ.get("IA_OLLAMA_MODEL", "phi4-mini")
OLLAMA_TIMEOUT = int(os.environ.get("IA_OLLAMA_TIMEOUT", "180"))

ANTHROPIC_API_KEY = os.environ.get("IA_ANTHROPIC_API_KEY", "")
ANTHROPIC_MODEL = os.environ.get("IA_ANTHROPIC_MODEL", "claude-sonnet-5")
# Bounds the cost of a single escalation. An agent that cannot solve it in this
# many tool calls is not going to solve it in eighty -- at that point the
# correct output is a clear writeup of what it found for a human.
ANTHROPIC_MAX_TURNS = int(os.environ.get("IA_ANTHROPIC_MAX_TURNS", "24"))
# Hard stop for one incident regardless of turns, so a single pathological
# investigation cannot consume the month.
ANTHROPIC_MAX_INCIDENT_USD = float(os.environ.get("IA_ANTHROPIC_MAX_INCIDENT_USD", "1.50"))

# Local cost estimate only -- used to decide when to stop spending, and to show
# a number when reviewing spend. The authoritative cap is the spend limit
# configured on the Anthropic Console workspace, which enforces itself
# server-side regardless of whether this estimate is accurate. Overridable
# because published per-token prices change and a stale constant compiled into
# the agent would silently skew the soft ceiling.
PRICE_INPUT_PER_MTOK = float(os.environ.get("IA_PRICE_INPUT_PER_MTOK", "3.00"))
PRICE_OUTPUT_PER_MTOK = float(os.environ.get("IA_PRICE_OUTPUT_PER_MTOK", "15.00"))
PRICE_CACHE_WRITE_PER_MTOK = float(os.environ.get("IA_PRICE_CACHE_WRITE_PER_MTOK", "3.75"))
PRICE_CACHE_READ_PER_MTOK = float(os.environ.get("IA_PRICE_CACHE_READ_PER_MTOK", "0.30"))

BUDGET_MONTHLY_USD = float(os.environ.get("IA_BUDGET_MONTHLY_USD", "20"))
# Stop escalating below the hard cap so hitting the ceiling is a decision the
# agent makes and reports, rather than an API error it discovers mid-incident.
BUDGET_SOFT_FRACTION = float(os.environ.get("IA_BUDGET_SOFT_FRACTION", "0.85"))

SSH_KEY = os.environ.get("IA_SSH_KEY", "/etc/incident-agent/automation.pem")
SSH_USER = os.environ.get("IA_SSH_USER", "automation")

LISTEN_HOST = os.environ.get("IA_LISTEN_HOST", "0.0.0.0")
LISTEN_PORT = int(os.environ.get("IA_LISTEN_PORT", "9098"))

MAX_CONCURRENT_TRIAGE = int(os.environ.get("IA_MAX_CONCURRENT_TRIAGE", "2"))
WORKER_POLL_SECONDS = int(os.environ.get("IA_WORKER_POLL_SECONDS", "15"))

_cache = {}


def _load(name):
    if name not in _cache:
        with open(os.path.join(CONFIG_DIR, name)) as fh:
            _cache[name] = yaml.safe_load(fh)
    return _cache[name]


def fleet():
    return _load("fleet.yml")


def policy():
    return _load("restart_allowlist.yml")


def diagnostics():
    return _load("diagnostics.yml")


def reset_cache():
    """Drop cached config -- used by tests, and by the worker between jobs so
    an edited allow-list takes effect without a service restart."""
    _cache.clear()


def resolve_target(alertname, labels):
    """Map an alert's labels onto a concrete fleet host.

    The `instance` label is not a hostname, which is the whole reason this
    exists. For node_exporter/cAdvisor alerts it is `<fqdn>:9100`; for
    ProbeFailed Prometheus rewrites it to the probed URL
    (see prometheus.yml.j2's blackbox_http relabel_configs); for the two
    hypervisors it is a raw IP because Prometheus runs containerised on
    `service` and cannot rely on guest DNS.

    Returns (host_name, service_name) where either may be None if unresolvable.
    Callers must treat host=None as "escalate, do not act" -- acting on a host
    we could not identify is exactly the wrong response.
    """
    f = fleet()
    instance = (labels or {}).get("instance", "")

    if instance.startswith("http://") or instance.startswith("https://"):
        target = (f.get("probe_targets") or {}).get(instance)
        if target:
            return target.get("host"), target.get("service")
        return None, None

    address = instance.rsplit(":", 1)[0] if ":" in instance else instance
    if not address:
        return None, None

    for name, meta in (f.get("hosts") or {}).items():
        if address in (name, meta.get("fqdn")):
            return name, None

    # Hypervisors are monitored by raw IP, and an alert on one of them is
    # always significant -- fleet-wide outages start here.
    for name, meta in (f.get("hypervisors") or {}).items():
        if address == meta.get("address") or address == name:
            return name, None

    return None, None


def host_policy(host):
    """Everything the agent needs to know about acting on a host.

    Fails closed: an unknown host (a new VM someone added to monitoring but not
    here) is treated as critical, so it gets diagnostics and a human rather
    than unsupervised restarts nobody signed off on.
    """
    f = fleet()
    meta = (f.get("hosts") or {}).get(host)
    if meta is None:
        if host in (f.get("hypervisors") or {}):
            return {
                "known": True,
                "critical": True,
                "self_exclude": False,
                "reason": "Bare-metal hypervisor -- rebooting it takes down every VM on it.",
                "hypervisor": None,
                "vm_id": None,
                "fqdn": (f["hypervisors"][host] or {}).get("address"),
            }
        return {
            "known": False,
            "critical": True,
            "self_exclude": False,
            "reason": f"Host '{host}' is not declared in fleet.yml -- treated as critical by default.",
            "hypervisor": None,
            "vm_id": None,
            "fqdn": None,
        }
    return {
        "known": True,
        "critical": bool(meta.get("critical")),
        "self_exclude": bool(meta.get("self_exclude")),
        "reason": meta.get("critical_reason") or "",
        "note": meta.get("note") or "",
        "hypervisor": meta.get("hypervisor"),
        "vm_id": meta.get("vm_id"),
        "fqdn": meta.get("fqdn"),
    }


def match_restart_rule(alertname, host, service=None):
    """Find the allow-list rule permitting an action, if any.

    Criticality is checked FIRST and wins unconditionally: fleet.yml cannot be
    overridden by restart_allowlist.yml. Two files must agree before anything
    is touched, and the restrictive one always wins.
    """
    pol = host_policy(host)
    if pol["critical"] or not pol["known"]:
        return None

    for rule in (policy().get("rules") or []):
        if rule.get("alert") != alertname:
            continue
        if rule.get("host") != host:
            continue
        if rule.get("service") and rule.get("service") != service:
            continue
        resolved = dict(rule)
        target = rule.get("target") or ""
        if "{service}" in target:
            if not service:
                # The rule is service-parameterised but we could not identify
                # which service -- restarting an unknown container name would
                # either no-op or hit the wrong thing.
                continue
            resolved["target"] = target.replace("{service}", service)
        return resolved
    return None


def flap_guard():
    return (policy().get("flap_guard") or {"max_actions": 2, "window_seconds": 3600})


def storm_config():
    return (policy().get("storm") or {"min_hosts": 4, "window_seconds": 600})


def grace_seconds():
    return int((policy().get("grace") or {}).get("seconds", 300))


def unreachable_retry_config():
    return (policy().get("unreachable_retry") or {"interval_seconds": 900, "max_retries": 6})


def claude_enabled():
    """Whether the dashboard's toggle allows the Claude escalation tier to
    run (2026-08-24). Lazy import -- store.py already imports config at
    module level, so a top-level import here would be circular. Read live
    from the DB every call rather than the _cache dict above: the toggle is
    written by an unprivileged process on a different host, so genuine
    liveness matters more than the cheap SQLite read costs."""
    from . import store
    return store.get_toggles().get("claude_enabled", True)


def local_llm_enabled():
    """Whether the dashboard's toggle allows the local model tier to run.
    See claude_enabled()'s docstring -- same reasoning, same mechanism."""
    from . import store
    return store.get_toggles().get("local_llm_enabled", True)


def estimate_cost(usage):
    """USD estimate for one API response's token usage."""
    if not usage:
        return 0.0
    return (
        usage.get("input_tokens", 0) / 1e6 * PRICE_INPUT_PER_MTOK
        + usage.get("output_tokens", 0) / 1e6 * PRICE_OUTPUT_PER_MTOK
        + usage.get("cache_creation_input_tokens", 0) / 1e6 * PRICE_CACHE_WRITE_PER_MTOK
        + usage.get("cache_read_input_tokens", 0) / 1e6 * PRICE_CACHE_READ_PER_MTOK
    )
