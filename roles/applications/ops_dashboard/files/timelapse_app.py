#!/usr/bin/env python3
"""Timelapse settings, review and metrics, served at /timelapse/ (2026-10-22).

The capture itself is a short-lived container started by systemd timers
(roles/applications/timelapse) -- nothing resident there. This app is the
only always-on piece, and it lives here beside chat_app.py and
incident_status_app.py rather than in that container so the container can
stay a run-and-exit job. Same conventions as those two: one small Flask
process, 127.0.0.1 only, no auth because this whole dashboard is LAN-only.

It only ever reads the archive. The one thing it writes is the camera
selection (/srv/timelapse/.config/config.json), which the capture job reads
at the start of every run -- so a change applies from the next 15-minute
slot with nothing to restart.

/timelapse/metrics is what Prometheus scrapes; the alert rules that use it
are in roles/applications/monitoring/files/alert_rules.yml.
"""
import json
import os
import re
import shutil
import tempfile
import time
from datetime import datetime, timedelta, timezone

from flask import Flask, Response, abort, jsonify, redirect, render_template_string, request, send_file

DATA = os.environ.get("TIMELAPSE_DATA", "/srv/timelapse")
CAMERAS_FILE = os.environ.get("CAMERAS_FILE", "/etc/timelapse/cameras.json")
PORT = int(os.environ.get("PORT", "5057"))
CONFIG_FILE = os.path.join(DATA, ".config", "config.json")
CHANGES_LOG = os.path.join(DATA, ".config", "changes.log")
STATE_DIR = os.path.join(DATA, ".state")
SLOT_SECONDS = 15 * 60
SLOTS_PER_DAY = 96
# Four byte-identical frames in a row == a streak of 3 repeats.
FROZEN_STREAK = 3

NAME_RE = re.compile(r"^[A-Za-z0-9_-]{1,64}$")
FRAME_RE = re.compile(r"^(?P<cam>[A-Za-z0-9_-]+)_(?P<ts>\d{8}T\d{4}Z)\.jpg$")

app = Flask(__name__)


# --------------------------------------------------------------------------
# Reading the archive
# --------------------------------------------------------------------------

def read_json(path, default):
    try:
        with open(path) as f:
            return json.load(f)
    except (OSError, ValueError):
        return default


def cameras():
    return [c for c in read_json(CAMERAS_FILE, []) if NAME_RE.match(str(c.get("name", "")))]


def load_config():
    cfg = read_json(CONFIG_FILE, {})
    cfg.setdefault("enabled", [])
    cfg.setdefault("enabled_since", {})
    return cfg


def enabled_since(cfg, camera):
    """When capture was switched on for this camera. A camera enabled by the
    initial seed has no entry, so it counts from when the config was created."""
    since = cfg["enabled_since"].get(camera)
    if since:
        return since
    try:
        return os.path.getmtime(CONFIG_FILE)
    except OSError:
        return time.time()


def utc_day(ts):
    return datetime.fromtimestamp(ts, timezone.utc).replace(hour=0, minute=0, second=0, microsecond=0)


def day_dir(camera, day):
    return os.path.join(DATA, camera, f"{day:%Y}", f"{day:%m}", f"{day:%d}")


def frame_time(name):
    m = FRAME_RE.match(name)
    if not m:
        return None
    return datetime.strptime(m.group("ts"), "%Y%m%dT%H%MZ").replace(tzinfo=timezone.utc)


def frames_on_day(camera, day):
    """[(datetime, filename)] for one camera's UTC day, oldest first."""
    try:
        names = os.listdir(day_dir(camera, day))
    except OSError:
        return []
    out = [(frame_time(n), n) for n in names if frame_time(n)]
    return sorted(out)


def camera_days(camera):
    root = os.path.join(DATA, camera)
    days = []
    try:
        for y in os.listdir(root):
            for m in os.listdir(os.path.join(root, y)):
                for d in os.listdir(os.path.join(root, y, m)):
                    try:
                        days.append(datetime(int(y), int(m), int(d), tzinfo=timezone.utc))
                    except ValueError:
                        pass
    except OSError:
        pass
    return sorted(days)


def latest_frame(camera):
    for day in reversed(camera_days(camera)):
        frames = frames_on_day(camera, day)
        if frames:
            return day, frames[-1]
    return None


def archive_cameras():
    """Cameras with frames on disk, including ones since removed or disabled."""
    try:
        return sorted(n for n in os.listdir(DATA)
                      if NAME_RE.match(n) and os.path.isdir(os.path.join(DATA, n)))
    except OSError:
        return []


def pending_days(now=None):
    """Completed UTC camera-days not yet uploaded -- same rule as the backup job."""
    today = utc_day(now or time.time())
    uploaded = read_json(os.path.join(STATE_DIR, "uploaded.json"), {})
    return sorted((day, cam) for cam in archive_cameras() for day in camera_days(cam)
                  if day < today and f"{cam}/{day:%Y%m%d}" not in uploaded)


def expected_slots(since, start, end):
    """How many 15-minute slots in [start, end) came at or after `since`."""
    first = max(start.timestamp(), since)
    first = -(-first // SLOT_SECONDS) * SLOT_SECONDS  # round up to a slot
    span = end.timestamp() - first
    if span <= 0:
        return 0
    return min(SLOTS_PER_DAY, int(-(-span // SLOT_SECONDS)))  # slots first, first+15m, ... < end


def disk_usage():
    try:
        usage = shutil.disk_usage(DATA)
        return usage.free, usage.total
    except OSError:
        return None, None


# --------------------------------------------------------------------------
# Writing the camera selection
# --------------------------------------------------------------------------

def save_enabled(names, who):
    known = {c["name"] for c in cameras()}
    names = [n for n in names if n in known]
    cfg = load_config()
    before = set(cfg["enabled"])
    now = time.time()
    since = {n: cfg["enabled_since"].get(n) or (enabled_since(cfg, n) if n in before else now)
             for n in names}
    new = {"enabled": names, "enabled_since": since, "updated_at": now}

    os.makedirs(os.path.dirname(CONFIG_FILE), exist_ok=True)
    fd, tmp = tempfile.mkstemp(dir=os.path.dirname(CONFIG_FILE), prefix=".tmp-")
    with os.fdopen(fd, "w") as f:
        json.dump(new, f, indent=2, sort_keys=True)
        f.write("\n")
    os.chmod(tmp, 0o644)
    os.replace(tmp, CONFIG_FILE)

    added, removed = sorted(set(names) - before), sorted(before - set(names))
    if added or removed:
        with open(CHANGES_LOG, "a") as f:
            f.write(f"{datetime.now(timezone.utc):%Y-%m-%dT%H:%M:%SZ} {who} "
                    f"enabled={','.join(added) or '-'} disabled={','.join(removed) or '-'}\n")
    return added, removed


def recent_changes(n=10):
    try:
        with open(CHANGES_LOG) as f:
            return f.readlines()[-n:][::-1]
    except OSError:
        return []


# --------------------------------------------------------------------------
# Metrics
# --------------------------------------------------------------------------

def metrics_text(now=None):
    now = now or time.time()
    cfg = load_config()
    capture = read_json(os.path.join(STATE_DIR, "capture.json"), {})
    backup = read_json(os.path.join(STATE_DIR, "backup.json"), {})
    yesterday = utc_day(now) - timedelta(days=1)
    today = utc_day(now)
    out = []

    def metric(name, help_text, samples):
        out.append(f"# HELP {name} {help_text}")
        out.append(f"# TYPE {name} gauge")
        for labels, value in samples:
            label_str = ",".join(f'{k}="{v}"' for k, v in labels.items())
            out.append(f"{name}{{{label_str}}} {value}" if label_str else f"{name} {value}")

    cams = [c["name"] for c in cameras()]
    enabled = [c for c in cams if c in cfg["enabled"]]

    metric("timelapse_camera_enabled", "1 if capture is enabled for this camera.",
           [({"camera": c}, 1 if c in enabled else 0) for c in cams])
    # For an enabled camera that has not produced a frame yet, the moment it
    # was enabled stands in -- so "enabled but never captured" goes stale
    # and alerts, instead of the metric simply being absent.
    metric("timelapse_last_capture_timestamp",
           "Last successful capture (or when capture was enabled, if none since).",
           [({"camera": c}, max(capture.get(c, {}).get("last_success_ts", 0), enabled_since(cfg, c)))
            for c in enabled])
    metric("timelapse_last_error_timestamp", "Last failed fetch attempt, from any source.",
           [({"camera": c}, capture[c]["last_error_ts"]) for c in cams
            if capture.get(c, {}).get("last_error_ts")])
    metric("timelapse_frozen", "1 if the last 4+ frames were byte-identical.",
           [({"camera": c}, 1 if capture.get(c, {}).get("identical_streak", 0) >= FROZEN_STREAK else 0)
            for c in enabled])
    metric("timelapse_frames_yesterday", "Frames captured during the previous UTC day.",
           [({"camera": c}, len(frames_on_day(c, yesterday))) for c in enabled])
    metric("timelapse_frames_yesterday_expected",
           "Slots in the previous UTC day after capture was enabled.",
           [({"camera": c}, expected_slots(enabled_since(cfg, c), yesterday, today)) for c in enabled])

    pending = pending_days(now)
    last_ok = backup.get("last_success_ts")
    if not last_ok:
        # Never succeeded yet: count from when the oldest pending day became
        # uploadable, so a backup that has never worked still goes stale.
        last_ok = (pending[0][0] + timedelta(days=1)).timestamp() if pending else now
    metric("timelapse_last_backup_success_timestamp", "Last backup run with no failures.",
           [({}, last_ok)])
    metric("timelapse_backup_pending_days", "Completed camera-days not yet in S3.",
           [({}, len(pending))])
    free, size = disk_usage()
    if free is not None:
        metric("timelapse_disk_free_bytes", "Free space on the timelapse disk.", [({}, free)])
        metric("timelapse_disk_size_bytes", "Size of the timelapse disk.", [({}, size)])
    return "\n".join(out) + "\n"


# --------------------------------------------------------------------------
# Pages
# --------------------------------------------------------------------------

STYLE = """
  :root { color-scheme: light dark; --bg:#f5f6f8; --card-bg:#fff; --text:#1a1a1a; --muted:#666;
          --border:#e0e0e0; --accent:#3b6ef5; --ok:#1a9e5c; --warn:#c77700; --off:#999; }
  @media (prefers-color-scheme: dark) {
    :root { --bg:#14161a; --card-bg:#1e2127; --text:#e8e8e8; --muted:#9aa0aa; --border:#2c3038;
            --accent:#6d93ff; --ok:#3ecf8e; --warn:#f0a43a; --off:#6b7280; } }
  * { box-sizing:border-box; }
  body { margin:0; font-family:-apple-system,BlinkMacSystemFont,"Segoe UI",Roboto,sans-serif;
         background:var(--bg); color:var(--text); padding:2rem 1.25rem; }
  .wrap { max-width:1100px; margin:0 auto; }
  header { display:flex; align-items:baseline; gap:1rem; flex-wrap:wrap; }
  header a { color:var(--muted); font-size:.85rem; text-decoration:none; }
  header a:hover { color:var(--accent); }
  h1 { font-size:1.3rem; margin:.4rem 0 1.25rem; }
  h2 { font-size:1rem; margin:0 0 .75rem; }
  .card { background:var(--card-bg); border:1px solid var(--border); border-radius:10px;
          padding:1.1rem 1.25rem; margin-bottom:1rem; }
  .muted { color:var(--muted); font-size:.85rem; }
  .ok { color:var(--ok); } .warn { color:var(--warn); }
  button, select, input { font:inherit; }
  button { background:var(--accent); color:#fff; border:0; border-radius:6px; padding:.45rem 1rem; cursor:pointer; }
"""

REVIEW = """<!doctype html>
<html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Timelapse</title>
<style>{{ style|safe }}
  .cams { display:grid; gap:1rem; grid-template-columns:repeat(auto-fill,minmax(min(100%,320px),1fr)); }
  .cams img { width:100%; border-radius:6px; display:block; background:#000; aspect-ratio:16/9; object-fit:contain; }
  .stat { display:flex; justify-content:space-between; font-size:.85rem; padding:.2rem 0; }
  .controls { display:flex; gap:.6rem; flex-wrap:wrap; align-items:center; margin-bottom:.8rem; }
  .grid { display:grid; gap:.4rem; grid-template-columns:repeat(auto-fill,minmax(150px,1fr)); }
  .grid figure { margin:0; cursor:pointer; }
  .grid img { width:100%; display:block; border-radius:4px; background:#000; aspect-ratio:16/9; object-fit:cover; }
  .grid figcaption { font-size:.75rem; color:var(--muted); text-align:center; }
  #viewer[hidden] { display:none; }
  #viewer { position:fixed; inset:0; background:#000e; z-index:10; display:flex; flex-direction:column; }
  #viewer .bar { display:flex; gap:.6rem; align-items:center; padding:.6rem 1rem; color:#eee; }
  #viewer .bar span { margin-right:auto; }
  #viewer img { flex:1; min-height:0; width:100%; object-fit:contain; }
</style></head><body><div class="wrap">
<header><a href="/">&larr; Homelab Ops</a><a href="settings">Camera settings &rarr;</a></header>
<h1>Timelapse</h1>

<div class="card">
  <h2>Status</h2>
  {% if not enabled %}<p class="warn">No cameras are enabled &mdash; nothing is being captured.
    <a href="settings">Choose cameras</a>.</p>{% endif %}
  <div class="stat"><span>Last backup to S3</span><span data-ts="{{ backup_ok or '' }}">never</span></div>
  <div class="stat"><span>Days waiting for backup</span>
    <span class="{{ 'warn' if pending > 2 else '' }}">{{ pending }}</span></div>
  {% if backup_error %}<div class="stat"><span>Last backup error</span><span class="warn">{{ backup_error }}</span></div>{% endif %}
  <div class="stat"><span>Disk</span><span>{{ disk }}</span></div>
</div>

<div class="cams">
{% for c in cams %}
  <div class="card">
    <h2>{{ c.label }} {% if c.enabled %}<span class="ok muted">&bull; capturing</span>{% else %}<span class="muted">&bull; off</span>{% endif %}</h2>
    {% if c.latest %}<img src="{{ c.latest }}" alt="Latest frame from {{ c.label }}" loading="lazy">{% else %}<p class="muted">No frames yet.</p>{% endif %}
    <div class="stat"><span>Last frame</span><span data-ts="{{ c.last_ts or '' }}">&mdash;</span></div>
    {% if c.enabled %}<div class="stat"><span>Yesterday (UTC)</span><span>{{ c.yesterday }} / {{ c.expected }}</span></div>{% endif %}
    {% if c.error %}<div class="stat"><span>Last error</span><span class="warn" data-ts="{{ c.error_ts }}"></span></div>
    <div class="muted">{{ c.error }}</div>{% endif %}
  </div>
{% endfor %}
</div>

<div class="card">
  <h2>Browse a day</h2>
  <div class="controls">
    <select id="cam">{% for c in cams if c.has_frames %}<option value="{{ c.name }}">{{ c.label }}</option>{% endfor %}</select>
    <button type="button" id="prev">&larr;</button>
    <input type="date" id="day">
    <button type="button" id="next">&rarr;</button>
    <span class="muted" id="count"></span>
  </div>
  <div class="grid" id="grid"></div>
</div>
</div>

<div id="viewer" hidden>
  <div class="bar"><span id="vtitle"></span>
    <button type="button" id="vprev">&larr;</button><button type="button" id="vnext">&rarr;</button>
    <a id="vopen" target="_blank" rel="noopener" style="color:#9cf">full size</a>
    <button type="button" id="vclose">Close (Esc)</button></div>
  <img id="vimg" alt="">
</div>

<script>
// Frames are named and stored in UTC; everything shown here is local time.
const fmt = new Intl.DateTimeFormat(undefined, {weekday:'short', day:'numeric', month:'short', hour:'numeric', minute:'2-digit'});
const tfmt = new Intl.DateTimeFormat(undefined, {hour:'numeric', minute:'2-digit'});
document.querySelectorAll('[data-ts]').forEach(el => {
  if (el.dataset.ts) el.textContent = fmt.format(new Date(Number(el.dataset.ts) * 1000));
});

const cam = document.getElementById('cam'), day = document.getElementById('day');
const grid = document.getElementById('grid'), count = document.getElementById('count');
const pad = n => String(n).padStart(2, '0');
const isoLocal = d => `${d.getFullYear()}-${pad(d.getMonth() + 1)}-${pad(d.getDate())}`;
day.value = isoLocal(new Date());
let frames = [], current = -1;

async function load() {
  grid.innerHTML = ''; count.textContent = '';
  if (!cam.value) { count.textContent = 'No frames captured yet.'; return; }
  const [y, m, d] = day.value.split('-').map(Number);
  const start = new Date(y, m - 1, d), end = new Date(y, m - 1, d + 1);   // the viewer's own local day
  const r = await fetch(`api/frames?camera=${encodeURIComponent(cam.value)}&start=${start / 1000}&end=${end / 1000}`);
  frames = r.ok ? await r.json() : [];
  count.textContent = `${frames.length} frame${frames.length === 1 ? '' : 's'}`;
  frames.forEach((f, i) => {
    const fig = document.createElement('figure');
    fig.innerHTML = `<img loading="lazy" src="${f.thumb}" alt=""><figcaption>${tfmt.format(new Date(f.t * 1000))}</figcaption>`;
    fig.addEventListener('click', () => show(i));
    grid.appendChild(fig);
  });
}
function shift(days) {
  const [y, m, d] = day.value.split('-').map(Number);
  day.value = isoLocal(new Date(y, m - 1, d + days)); load();
}
const viewer = document.getElementById('viewer'), vimg = document.getElementById('vimg');
function show(i) {
  if (i < 0 || i >= frames.length) return;
  current = i; const f = frames[i];
  vimg.src = f.img; document.getElementById('vopen').href = f.img;
  document.getElementById('vtitle').textContent = `${cam.options[cam.selectedIndex].text} \\u2014 ${fmt.format(new Date(f.t * 1000))} (${i + 1}/${frames.length})`;
  viewer.hidden = false;
}
document.getElementById('vclose').onclick = () => { viewer.hidden = true; };
document.getElementById('vprev').onclick = () => show(current - 1);
document.getElementById('vnext').onclick = () => show(current + 1);
addEventListener('keydown', e => {
  if (viewer.hidden) return;
  if (e.key === 'Escape') viewer.hidden = true;
  if (e.key === 'ArrowLeft') show(current - 1);
  if (e.key === 'ArrowRight') show(current + 1);
});
document.getElementById('prev').onclick = () => shift(-1);
document.getElementById('next').onclick = () => shift(1);
cam.onchange = load; day.onchange = load;
load();
</script>
</body></html>
"""

SETTINGS = """<!doctype html>
<html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Timelapse settings</title>
<style>{{ style|safe }}
  .wrap { max-width:640px; }
  label.row { display:flex; gap:.8rem; align-items:center; padding:.6rem 0; cursor:pointer; }
  label.row + label.row { border-top:1px solid var(--border); }
  label.row input { width:1.15rem; height:1.15rem; }
  .saved { background:var(--card-bg); border-left:3px solid var(--ok); padding:.6rem .9rem; margin-bottom:1rem; }
  pre { white-space:pre-wrap; font-size:.8rem; margin:0; }
</style></head><body><div class="wrap">
<header><a href="./">&larr; Timelapse</a></header>
<h1>Which cameras to capture</h1>
{% if saved %}<div class="saved">Saved. Changes apply from the next quarter hour.</div>{% endif %}
<form method="post" class="card">
  {% for c in cams %}
  <label class="row">
    <input type="checkbox" name="enabled" value="{{ c.name }}" {{ 'checked' if c.enabled }}>
    <span><strong>{{ c.label }}</strong><br><span class="muted">{{ c.name }} &middot; {{ c.ip }}</span></span>
  </label>
  {% else %}
  <p class="muted">No cameras defined (group_vars/Frigate <code>cameras</code>).</p>
  {% endfor %}
  <p class="muted">One full-resolution frame every 15 minutes per ticked camera &mdash; roughly 7&ndash;30&nbsp;GB a
    year each, depending on the camera (baby-ptz's frames are about 200&nbsp;KB, so about 7&nbsp;GB a year).
    Unticking stops new frames only &mdash; frames already captured stay and are still backed up.
    New cameras appear here unticked.</p>
  <button type="submit">Save</button>
</form>
{% if changes %}<div class="card"><h2>Recent changes</h2><pre>{% for line in changes %}{{ line }}{% endfor %}</pre></div>{% endif %}
</div></body></html>
"""


def human_bytes(n):
    for unit in ("B", "KB", "MB", "GB", "TB"):
        if n < 1024 or unit == "TB":
            return f"{n:.1f} {unit}" if unit != "B" else f"{n} B"
        n /= 1024


@app.route("/timelapse/")
def review():
    now = time.time()
    cfg = load_config()
    capture = read_json(os.path.join(STATE_DIR, "capture.json"), {})
    backup = read_json(os.path.join(STATE_DIR, "backup.json"), {})
    yesterday, today = utc_day(now) - timedelta(days=1), utc_day(now)
    defined = {c["name"]: c for c in cameras()}
    names = list(defined) + [n for n in archive_cameras() if n not in defined]

    cams = []
    for name in names:
        latest = latest_frame(name)
        state = capture.get(name, {})
        cams.append({
            "name": name,
            "label": defined.get(name, {}).get("friendly_name") or name,
            "enabled": name in cfg["enabled"],
            "has_frames": latest is not None,
            "latest": f"img/{name}/{latest[0]:%Y/%m/%d}/{latest[1][1]}" if latest else None,
            "last_ts": latest[1][0].timestamp() if latest else None,
            "yesterday": len(frames_on_day(name, yesterday)),
            "expected": expected_slots(enabled_since(cfg, name), yesterday, today),
            "error": state.get("last_error") if state.get("last_error_ts", 0) > now - 86400 else None,
            "error_ts": state.get("last_error_ts"),
        })
    free, size = disk_usage()
    return render_template_string(
        REVIEW, style=STYLE, cams=cams, enabled=cfg["enabled"],
        backup_ok=backup.get("last_success_ts"), backup_error=backup.get("last_error")
        if backup.get("last_error_ts", 0) > backup.get("last_success_ts", 0) else None,
        pending=len(pending_days(now)),
        disk=f"{human_bytes(free)} free of {human_bytes(size)}" if free is not None else "unavailable")


@app.route("/timelapse/settings", methods=["GET", "POST"])
def settings():
    if request.method == "POST":
        who = request.headers.get("X-Forwarded-For", request.remote_addr or "?").split(",")[0].strip()
        save_enabled(request.form.getlist("enabled"), who)
        return redirect("settings?saved=1", code=303)
    cfg = load_config()
    cams = [{"name": c["name"], "label": c.get("friendly_name") or c["name"], "ip": c.get("ip", ""),
             "enabled": c["name"] in cfg["enabled"]} for c in cameras()]
    return render_template_string(SETTINGS, style=STYLE, cams=cams, saved=request.args.get("saved"),
                                  changes=recent_changes())


@app.route("/timelapse/api/frames")
def api_frames():
    """Frames for one camera between two epoch times -- the viewer's local
    day, which can straddle two UTC day directories."""
    camera = request.args.get("camera", "")
    if not NAME_RE.match(camera):
        abort(400)
    try:
        start = float(request.args["start"])
        end = float(request.args["end"])
    except (KeyError, ValueError):
        abort(400)
    if end <= start or end - start > 3 * 86400:
        abort(400)
    out = []
    day = utc_day(start)
    while day.timestamp() < end:
        for t, name in frames_on_day(camera, day):
            if start <= t.timestamp() < end:
                rel = f"{camera}/{day:%Y/%m/%d}/{name}"
                out.append({"t": t.timestamp(), "img": f"img/{rel}", "thumb": f"img/{rel}?thumb=1"})
        day += timedelta(days=1)
    return jsonify(out)


@app.route("/timelapse/img/<camera>/<year>/<month>/<dayn>/<name>")
def image(camera, year, month, dayn, name):
    # Every component is validated, never joined raw: this route serves
    # files off disk and must not be steerable outside the archive.
    if not (NAME_RE.match(camera) and FRAME_RE.match(name) and year.isdigit() and len(year) == 4
            and month.isdigit() and len(month) == 2 and dayn.isdigit() and len(dayn) == 2):
        abort(404)
    directory = os.path.join(DATA, camera, year, month, dayn)
    path = os.path.join(directory, "_thumbs", name) if request.args.get("thumb") else os.path.join(directory, name)
    if not os.path.isfile(path):
        if request.args.get("thumb") and os.path.isfile(os.path.join(directory, name)):
            path = os.path.join(directory, name)   # no preview made: fall back to the frame
        else:
            abort(404)
    resp = send_file(path, mimetype="image/jpeg", max_age=86400 * 30)
    return resp


@app.route("/timelapse/metrics")
def metrics():
    return Response(metrics_text(), mimetype="text/plain; version=0.0.4")


if __name__ == "__main__":
    app.run(host="127.0.0.1", port=PORT)
