"""Read-only queries against Loki, Prometheus and Alertmanager.

These are preferred over SSH for one structural reason: they all answer from
`service`, so they work when the host under investigation does not. For
InstanceDown -- the alert where the target is by definition unreachable --
this is the only log source that works at all.
"""
import json
import time
import urllib.error
import urllib.parse
import urllib.request

from . import config


def _get(url, timeout=20):
    req = urllib.request.Request(url, method="GET")
    req.add_header("Accept", "application/json")
    with urllib.request.urlopen(req, timeout=timeout) as resp:
        return json.loads(resp.read() or b"{}")


def alert_is_firing(fingerprint, alertname, instance):
    """Is this alert still active right now?

    Used by the grace period. Fingerprint is preferred because it is exact;
    the (alertname, instance) fallback exists because Alertmanager's v2 API
    computes its own fingerprints, which are not guaranteed to equal the ones
    Prometheus put in the webhook payload.

    Returns True/False, or None when Alertmanager cannot be reached -- and the
    distinction matters: an unreachable Alertmanager must NOT be read as "the
    alert cleared", or an outage that takes out `service` would cause the agent
    to silently drop every incident as self-resolved.
    """
    try:
        alerts = _get(f"{config.ALERTMANAGER_URL}/api/v2/alerts?active=true&silenced=false&inhibited=false")
    except (urllib.error.URLError, urllib.error.HTTPError, ValueError, TimeoutError):
        return None

    for alert in alerts or []:
        if fingerprint and alert.get("fingerprint") == fingerprint:
            return True
        labels = alert.get("labels", {})
        if labels.get("alertname") == alertname and labels.get("instance") == instance:
            return True
    return False


def loki_query(query, lookback_minutes=30, limit=200):
    """Query Loki over a time range, newest first."""
    end = time.time()
    start = end - lookback_minutes * 60
    params = urllib.parse.urlencode(
        {
            "query": query,
            "start": int(start * 1e9),
            "end": int(end * 1e9),
            "limit": limit,
            "direction": "backward",
        }
    )
    data = _get(f"{config.LOKI_URL}/loki/api/v1/query_range?{params}", timeout=30)
    lines = []
    for stream in data.get("data", {}).get("result", []):
        unit = stream.get("stream", {}).get("unit", "?")
        for ts_ns, line in stream.get("values", []):
            lines.append((int(ts_ns), unit, line))
    lines.sort(key=lambda x: x[0])
    out = []
    for ts_ns, unit, line in lines:
        stamp = time.strftime("%H:%M:%S", time.localtime(ts_ns / 1e9))
        out.append(f"{stamp} [{unit}] {line}")
    return "\n".join(out) if out else "(no log lines returned)"


def prometheus_query(expr):
    """Instant query. Range selectors (`foo[30m]`) are routed to query_range
    automatically, since Prometheus's instant endpoint rejects them."""
    if expr.rstrip().endswith("]"):
        base, _, window = expr.rstrip().rpartition("[")
        window = window.rstrip("]")
        seconds = _parse_duration(window)
        end = time.time()
        params = urllib.parse.urlencode(
            {"query": base, "start": end - seconds, "end": end, "step": max(15, seconds // 60)}
        )
        data = _get(f"{config.PROMETHEUS_URL}/api/v1/query_range?{params}", timeout=30)
        return _format_range(data)

    params = urllib.parse.urlencode({"query": expr})
    data = _get(f"{config.PROMETHEUS_URL}/api/v1/query?{params}", timeout=30)
    results = data.get("data", {}).get("result", [])
    if not results:
        return "(no data)"
    out = []
    for r in results:
        metric = r.get("metric", {})
        label = metric.get("instance") or metric.get("__name__") or json.dumps(metric)
        value = r.get("value", [None, "?"])[1]
        out.append(f"{label} = {value}")
    return "\n".join(out)


def _format_range(data):
    results = data.get("data", {}).get("result", [])
    if not results:
        return "(no data)"
    out = []
    for r in results:
        metric = r.get("metric", {})
        label = metric.get("instance") or json.dumps(metric)
        values = r.get("values", [])
        # Compress to transitions rather than dumping every sample: for `up`
        # in particular, "1 until 14:02 then 0" is the whole diagnosis and
        # hundreds of identical samples are noise that costs tokens.
        transitions = []
        last = None
        for ts, v in values:
            if v != last:
                transitions.append(f"{time.strftime('%H:%M:%S', time.localtime(float(ts)))}={v}")
                last = v
        out.append(f"{label}: " + (", ".join(transitions) if transitions else "(flat, no samples)"))
    return "\n".join(out)


def _parse_duration(text):
    units = {"s": 1, "m": 60, "h": 3600, "d": 86400}
    try:
        return int(text[:-1]) * units.get(text[-1], 60)
    except (ValueError, IndexError):
        return 1800


def http_probe(url, timeout=10):
    """Re-probe an endpoint the same way Blackbox does, to see whether it has
    recovered since the alert fired."""
    started = time.time()
    try:
        req = urllib.request.Request(url, method="GET")
        req.add_header("User-Agent", "incident-agent/1.0")
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            elapsed = time.time() - started
            return True, f"HTTP {resp.status} in {elapsed:.2f}s"
    except urllib.error.HTTPError as e:
        elapsed = time.time() - started
        # A 2xx is what Blackbox's http_2xx module wants, but any HTTP status
        # at all proves something is listening and answering -- a materially
        # different diagnosis from a connection failure.
        return False, f"HTTP {e.code} in {elapsed:.2f}s (endpoint is up but not 2xx)"
    except Exception as e:  # noqa: BLE001 -- probe failure detail is the payload
        elapsed = time.time() - started
        return False, f"{type(e).__name__}: {e} after {elapsed:.2f}s"
