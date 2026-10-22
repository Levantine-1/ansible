"""Checks for timelapse_app.py against a throwaway archive.

    pip install flask
    python roles/applications/ops_dashboard/tests/test_timelapse_app.py
"""

import json
import os
import re
import sys
import tempfile
import time
from datetime import datetime, timedelta, timezone

WORK = tempfile.mkdtemp(prefix="timelapse-app-test-")
os.environ.update(TIMELAPSE_DATA=WORK, CAMERAS_FILE=os.path.join(WORK, "cameras.json"))
sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "files"))

import timelapse_app as a  # noqa: E402

failures = []


def check(name, condition, detail=""):
    print(("PASS  " if condition else "FAIL  ") + name + ("" if condition else f"  -> {detail}"))
    if not condition:
        failures.append(name)


def utc(*args):
    return datetime(*args, tzinfo=timezone.utc)


def put_frame(camera, when, thumb=True):
    d = a.day_dir(camera, when)
    os.makedirs(os.path.join(d, "_thumbs"), exist_ok=True)
    name = f"{camera}_{when:%Y%m%dT%H%MZ}.jpg"
    with open(os.path.join(d, name), "wb") as f:
        f.write(b"\xff\xd8\xff full " + name.encode())
    if thumb:
        with open(os.path.join(d, "_thumbs", name), "wb") as f:
            f.write(b"\xff\xd8\xff thumb " + name.encode())
    return name


def parse_metrics(text):
    out = {}
    for line in text.splitlines():
        if line.startswith("#") or not line.strip():
            continue
        key, value = line.rsplit(" ", 1)
        out[key] = float(value)
    return out


with open(a.CAMERAS_FILE, "w") as f:
    json.dump([{"name": "baby-ptz", "friendly_name": "Baby PTZ", "ip": "10.0.0.1", "channel": 1},
               {"name": "the-boiz", "friendly_name": "The Boiz", "ip": "10.0.0.2", "channel": 1},
               {"name": "the-gurlz", "friendly_name": "The Gurlz", "ip": "10.0.0.3", "channel": 1}], f)
os.makedirs(os.path.dirname(a.CONFIG_FILE))
os.makedirs(a.STATE_DIR)
with open(a.CONFIG_FILE, "w") as f:
    json.dump({"enabled": ["baby-ptz"], "enabled_since": {}}, f)


def main():
    c = a.app.test_client()

    # --- expected slots -----------------------------------------------------
    day0, day1 = utc(2026, 10, 22), utc(2026, 10, 23)
    check("a camera enabled before the day expects all 96 slots",
          a.expected_slots(day0.timestamp() - 10, day0, day1) == 96)
    check("enabled at noon expects 48",
          a.expected_slots(utc(2026, 10, 22, 12).timestamp(), day0, day1) == 48)
    check("enabled at 12:05 expects the 47 slots from 12:15",
          a.expected_slots(utc(2026, 10, 22, 12, 5).timestamp(), day0, day1) == 47)
    check("enabled in the last slot expects 1",
          a.expected_slots(utc(2026, 10, 22, 23, 45).timestamp(), day0, day1) == 1)
    check("enabled after the day expects 0",
          a.expected_slots(day1.timestamp() + 5, day0, day1) == 0)

    # --- settings -----------------------------------------------------------
    r = c.get("/timelapse/settings")
    page = r.get_data(as_text=True)
    check("settings lists every camera",
          r.status_code == 200 and all(n in page for n in ("Baby PTZ", "The Boiz", "The Gurlz")))
    check("only baby-ptz starts ticked",
          re.search(r'value="baby-ptz"\s+checked', page) and not re.search(r'value="the-boiz"\s+checked', page))

    r = c.post("/timelapse/settings", data={"enabled": ["baby-ptz", "the-boiz", "not-a-camera"]})
    cfg = json.load(open(a.CONFIG_FILE))
    check("saving redirects back with a confirmation", r.status_code == 303 and "saved=1" in r.headers["Location"])
    check("saved selection drops unknown names", cfg["enabled"] == ["baby-ptz", "the-boiz"], cfg)
    check("a newly enabled camera records when it was enabled",
          abs(cfg["enabled_since"]["the-boiz"] - time.time()) < 5, cfg)
    check("the change is logged", "enabled=the-boiz" in open(a.CHANGES_LOG).read())
    check("the settings page shows the confirmation and history",
          "Saved." in c.get("/timelapse/settings?saved=1").get_data(as_text=True)
          and "enabled=the-boiz" in c.get("/timelapse/settings").get_data(as_text=True))

    c.post("/timelapse/settings", data={"enabled": ["baby-ptz"]})
    cfg = json.load(open(a.CONFIG_FILE))
    check("unticking removes it and its enabled time", cfg["enabled"] == ["baby-ptz"]
          and "the-boiz" not in cfg["enabled_since"], cfg)
    check("unticking is logged too", "disabled=the-boiz" in open(a.CHANGES_LOG).read())

    # --- review + images -----------------------------------------------------
    now = time.time()
    today = a.utc_day(now)
    yesterday = today - timedelta(days=1)
    for i in range(10):
        put_frame("baby-ptz", yesterday + timedelta(minutes=15 * i))
    latest = put_frame("baby-ptz", today)
    r = c.get("/timelapse/")
    page = r.get_data(as_text=True)
    check("review page renders", r.status_code == 200 and "Baby PTZ" in page, r.status_code)
    check("review shows the latest frame", latest in page)

    rel = f"baby-ptz/{today:%Y/%m/%d}/{latest}"
    r = c.get(f"/timelapse/img/{rel}")
    check("full frame served", r.status_code == 200 and b"full" in r.data)
    r = c.get(f"/timelapse/img/{rel}?thumb=1")
    check("thumbnail served", r.status_code == 200 and b"thumb" in r.data)
    check("path traversal refused",
          c.get("/timelapse/img/..%2F..%2Fetc/2026/10/23/passwd").status_code == 404
          and c.get(f"/timelapse/img/baby-ptz/{today:%Y/%m/%d}/..%2Fx.jpg").status_code == 404)

    # A local day that straddles two UTC days returns frames from both.
    r = c.get(f"/timelapse/api/frames?camera=baby-ptz&start={yesterday.timestamp() + 3600}"
              f"&end={today.timestamp() + 3600}")
    times = [f["t"] for f in r.get_json()]
    check("a local day spanning two UTC directories returns frames from both, in range",
          r.status_code == 200 and len(times) == 7 and times == sorted(times), times)
    check("frame listing rejects bad input",
          c.get("/timelapse/api/frames?camera=../x&start=0&end=1").status_code == 400
          and c.get("/timelapse/api/frames?camera=baby-ptz&start=0&end=999999999").status_code == 400)

    # --- metrics ---------------------------------------------------------------
    # baby-ptz has been on for a long time; its enable time must not mask a
    # real last-capture time.
    cfg = json.load(open(a.CONFIG_FILE))
    cfg["enabled_since"]["baby-ptz"] = now - 10 * 86400
    json.dump(cfg, open(a.CONFIG_FILE, "w"))
    with open(os.path.join(a.STATE_DIR, "capture.json"), "w") as f:
        json.dump({"baby-ptz": {"last_success_ts": now - 60, "identical_streak": 3,
                                "last_error_ts": now - 120}}, f)
    r = c.get("/timelapse/metrics")
    m = parse_metrics(r.get_data(as_text=True))
    check("metrics served", r.status_code == 200, r.status_code)
    check("enabled flag per camera",
          m.get('timelapse_camera_enabled{camera="baby-ptz"}') == 1
          and m.get('timelapse_camera_enabled{camera="the-gurlz"}') == 0, m)
    check("last capture reported for enabled cameras only",
          abs(m.get('timelapse_last_capture_timestamp{camera="baby-ptz"}', 0) - (now - 60)) < 2
          and 'timelapse_last_capture_timestamp{camera="the-gurlz"}' not in m, m)
    check("frozen flagged after four identical frames",
          m.get('timelapse_frozen{camera="baby-ptz"}') == 1, m)
    check("yesterday's frame count", m.get('timelapse_frames_yesterday{camera="baby-ptz"}') == 10, m)
    check("a camera on all yesterday expects 96 frames",
          m.get('timelapse_frames_yesterday_expected{camera="baby-ptz"}') == 96, m)
    check("a camera never backed up shows pending days and a stale-able backup time",
          m.get("timelapse_backup_pending_days") == 1
          and m.get("timelapse_last_backup_success_timestamp") == today.timestamp(), m)
    check("disk metrics present", m.get("timelapse_disk_size_bytes", 0) > 0)

    with open(os.path.join(a.STATE_DIR, "uploaded.json"), "w") as f:
        json.dump({f"baby-ptz/{yesterday:%Y%m%d}": {}}, f)
    m = parse_metrics(c.get("/timelapse/metrics").get_data(as_text=True))
    check("uploaded days are no longer pending", m.get("timelapse_backup_pending_days") == 0, m)

    # An enabled camera that has never produced a frame goes stale from
    # when it was enabled, rather than being silently absent.
    c.post("/timelapse/settings", data={"enabled": ["baby-ptz", "the-gurlz"]})
    m = parse_metrics(c.get("/timelapse/metrics").get_data(as_text=True))
    check("a never-captured enabled camera reports its enable time",
          abs(m.get('timelapse_last_capture_timestamp{camera="the-gurlz"}', 0) - time.time()) < 5, m)

    print()
    print("ALL PASS" if not failures else "FAILURES: " + ", ".join(failures))
    return 1 if failures else 0


if __name__ == "__main__":
    sys.exit(main())
