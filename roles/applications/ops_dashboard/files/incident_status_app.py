#!/usr/bin/env python3
"""Incident-agent status + controls, backed by listener.py's /status and
/toggles routes on `incident-agent` (2026-08-24).

Same reasoning as chat_app.py for why this exists as its own small native
Flask process rather than folding into that one: one app, one job, same
pattern repeated. No auth, same convention as the rest of this dashboard and
everything reaching it -- this dashboard is LAN-only by design (see
ops-dashboard.conf.j2's own comment), and a toggle flip here is a real,
no-expiry behavior change (the disabled tier stays off until someone flips it
back), same tradeoff already accepted for every other unauthenticated control
in this repo.

Considered and rejected: putting this on `thisper` instead of a new process
here. thisper is genuinely public-internet-facing (a real AWS Route53 record,
serving `portfolio`'s public visitor browsers) -- an unauthenticated
Claude/local-LLM kill switch and live incident data have no business being
reachable from the whole internet just because thisper's skeleton is small.
"""
import json
import os
import urllib.error
import urllib.request

from flask import Flask, Response, request

INCIDENT_AGENT_URL = os.environ.get("INCIDENT_AGENT_URL", "http://incident-agent.internal.levantine.io:9098")

app = Flask(__name__)

PAGE = """<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<title>Incident Agent</title>
<meta name="viewport" content="width=device-width, initial-scale=1">
<style>
  :root {
    color-scheme: light dark;
    --bg: #f5f6f8;
    --card-bg: #ffffff;
    --text: #1a1a1a;
    --muted: #666;
    --border: #e0e0e0;
    --accent: #3b6ef5;
    --ok: #1a9e5c;
    --off: #999;
  }
  @media (prefers-color-scheme: dark) {
    :root {
      --bg: #14161a;
      --card-bg: #1e2127;
      --text: #e8e8e8;
      --muted: #9aa0aa;
      --border: #2c3038;
      --accent: #6d93ff;
      --ok: #3ecf8e;
      --off: #6b7280;
    }
  }
  * { box-sizing: border-box; }
  body {
    margin: 0;
    font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif;
    background: var(--bg);
    color: var(--text);
    padding: 2.5rem 1.5rem;
  }
  .wrap { max-width: 640px; margin: 0 auto; }
  header a { color: var(--muted); font-size: 0.85rem; text-decoration: none; }
  h1 { font-size: 1.3rem; margin: 0.4rem 0 1.5rem; }
  .card {
    background: var(--card-bg);
    border: 1px solid var(--border);
    border-radius: 10px;
    padding: 1.2rem 1.4rem;
    margin-bottom: 1rem;
  }
  .status-row { display: flex; align-items: center; gap: 0.6rem; }
  .dot {
    width: 0.65rem;
    height: 0.65rem;
    border-radius: 50%;
    background: var(--off);
    flex-shrink: 0;
  }
  .dot.online { background: var(--ok); }
  .status-label { font-weight: 600; }
  .processing {
    margin-top: 0.7rem;
    padding-top: 0.7rem;
    border-top: 1px solid var(--border);
    font-size: 0.9rem;
    color: var(--muted);
  }
  .processing strong { color: var(--text); }
  .toggle-row {
    display: flex;
    align-items: center;
    justify-content: space-between;
    padding: 0.6rem 0;
  }
  .toggle-row + .toggle-row { border-top: 1px solid var(--border); }
  .toggle-label { font-weight: 600; }
  .toggle-desc { color: var(--muted); font-size: 0.8rem; margin-top: 0.1rem; }
  .switch {
    position: relative;
    width: 2.6rem;
    height: 1.5rem;
    flex-shrink: 0;
  }
  .switch input { opacity: 0; width: 0; height: 0; }
  .slider {
    position: absolute;
    cursor: pointer;
    inset: 0;
    background: var(--off);
    border-radius: 999px;
    transition: background 0.15s ease;
  }
  .slider::before {
    content: "";
    position: absolute;
    width: 1.15rem;
    height: 1.15rem;
    left: 0.18rem;
    top: 0.18rem;
    background: #fff;
    border-radius: 50%;
    transition: transform 0.15s ease;
  }
  input:checked + .slider { background: var(--accent); }
  input:checked + .slider::before { transform: translateX(1.1rem); }
  input:disabled + .slider { opacity: 0.5; cursor: default; }
  .error { color: #d33; font-size: 0.85rem; margin-top: 0.6rem; }
</style>
</head>
<body>
<div class="wrap">
  <header><a href="/">&larr; Dashboard</a></header>
  <h1>Incident Agent</h1>

  <div class="card">
    <div class="status-row">
      <div class="dot" id="dot"></div>
      <div class="status-label" id="status-label">Checking...</div>
    </div>
    <div class="processing" id="processing" style="display:none;"></div>
  </div>

  <div class="card">
    <div class="toggle-row">
      <div>
        <div class="toggle-label">Claude escalation</div>
        <div class="toggle-desc">Paid tier -- investigates and fixes what the local model can't.</div>
      </div>
      <label class="switch">
        <input type="checkbox" id="claude_enabled" disabled>
        <span class="slider"></span>
      </label>
    </div>
    <div class="toggle-row">
      <div>
        <div class="toggle-label">Local LLM</div>
        <div class="toggle-desc">Free tier -- classifies incidents and recommends bounded actions.</div>
      </div>
      <label class="switch">
        <input type="checkbox" id="local_llm_enabled" disabled>
        <span class="slider"></span>
      </label>
    </div>
    <div class="error" id="error" style="display:none;"></div>
  </div>
</div>

<script>
  const dot = document.getElementById("dot");
  const statusLabel = document.getElementById("status-label");
  const processingEl = document.getElementById("processing");
  const errorEl = document.getElementById("error");
  const toggleEls = {
    claude_enabled: document.getElementById("claude_enabled"),
    local_llm_enabled: document.getElementById("local_llm_enabled"),
  };

  function showError(msg) {
    errorEl.textContent = msg;
    errorEl.style.display = "block";
  }

  async function refreshStatus() {
    try {
      const resp = await fetch("api/status");
      if (!resp.ok) throw new Error("HTTP " + resp.status);
      const data = await resp.json();
      dot.className = "dot" + (data.worker_online ? " online" : "");
      statusLabel.textContent = data.worker_online ? "Online" : "Offline";
      if (data.processing) {
        const p = data.processing;
        processingEl.innerHTML = "Processing ticket <strong>#" + (p.ticket_number || p.id) +
          "</strong> -- " + (p.alertname || "?") + " on " + (p.host || "?");
        processingEl.style.display = "block";
      } else {
        processingEl.style.display = "none";
      }
      errorEl.style.display = "none";
    } catch (err) {
      dot.className = "dot";
      statusLabel.textContent = "Unreachable";
      processingEl.style.display = "none";
      showError("Could not reach incident-agent: " + err.message);
    }
  }

  async function refreshToggles() {
    try {
      const resp = await fetch("api/toggles");
      if (!resp.ok) throw new Error("HTTP " + resp.status);
      const data = await resp.json();
      for (const [name, el] of Object.entries(toggleEls)) {
        if (name in data) el.checked = !!data[name];
        el.disabled = false;
      }
    } catch (err) {
      showError("Could not reach incident-agent: " + err.message);
    }
  }

  async function flipToggle(name, checked) {
    const el = toggleEls[name];
    el.disabled = true;
    try {
      const resp = await fetch("api/toggles", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ [name]: checked }),
      });
      if (!resp.ok) throw new Error("HTTP " + resp.status);
      const data = await resp.json();
      if (name in data) el.checked = !!data[name];
      errorEl.style.display = "none";
    } catch (err) {
      el.checked = !checked; // revert on failure
      showError("Could not update toggle: " + err.message);
    } finally {
      el.disabled = false;
    }
  }

  for (const [name, el] of Object.entries(toggleEls)) {
    el.addEventListener("change", () => flipToggle(name, el.checked));
  }

  refreshStatus();
  refreshToggles();
  setInterval(refreshStatus, 5000);
</script>
</body>
</html>
"""


def _proxy_get(path):
    req = urllib.request.Request(f"{INCIDENT_AGENT_URL}{path}", method="GET")
    with urllib.request.urlopen(req, timeout=10) as resp:
        return resp.read()


@app.route("/incidents/")
def index():
    return PAGE


@app.route("/incidents/api/status")
def status():
    try:
        return Response(_proxy_get("/status"), mimetype="application/json")
    except (urllib.error.URLError, urllib.error.HTTPError, TimeoutError, OSError) as e:
        return Response(json.dumps({"error": str(e)}), status=502, mimetype="application/json")


@app.route("/incidents/api/toggles", methods=["GET", "POST"])
def toggles():
    try:
        if request.method == "GET":
            return Response(_proxy_get("/toggles"), mimetype="application/json")
        req = urllib.request.Request(
            f"{INCIDENT_AGENT_URL}/toggles",
            data=request.get_data(),
            method="POST",
        )
        req.add_header("Content-Type", "application/json")
        with urllib.request.urlopen(req, timeout=10) as resp:
            return Response(resp.read(), mimetype="application/json")
    except (urllib.error.URLError, urllib.error.HTTPError, TimeoutError, OSError) as e:
        return Response(json.dumps({"error": str(e)}), status=502, mimetype="application/json")


if __name__ == "__main__":
    app.run(host="127.0.0.1", port=5056)
