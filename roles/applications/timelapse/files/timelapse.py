#!/usr/bin/env python3
"""Timelapse capture and archive, run as a short-lived container on `service`.

    timelapse.py capture   -- one frame per enabled camera for this 15-minute slot
    timelapse.py backup    -- upload every completed, not-yet-uploaded UTC day to S3

Nothing here runs between invocations: systemd timers start the container,
it does one job and exits. Everything it knows lives on the data disk
(/data, i.e. /srv/timelapse on the host):

    <camera>/YYYY/MM/DD/<camera>_YYYYMMDDTHHMMZ.jpg      the frames
    <camera>/YYYY/MM/DD/_thumbs/<same name>              320px previews
    .config/config.json    which cameras to capture -- written by the ops
                           dashboard's settings page, only read here
    .state/capture.json    per-camera last success/error, for the dashboard
                           and its /metrics
    .state/backup.json     last backup run
    .state/uploaded.json   which camera-days are already in S3

Names are UTC so a DST change can never produce two 01:30s or skip one;
the dashboard shows local time.
"""

import hashlib
import io
import json
import os
import sys
import tarfile
import tempfile
import time
from datetime import datetime, timedelta, timezone

import requests
from PIL import Image
from requests.auth import HTTPDigestAuth

DATA = os.environ.get("TIMELAPSE_DATA", "/data")
CAMERAS_FILE = os.environ.get("CAMERAS_FILE", "/etc/timelapse/cameras.json")
CONFIG_FILE = os.path.join(DATA, ".config", "config.json")
STATE_DIR = os.path.join(DATA, ".state")
CAPTURE_STATE = os.path.join(STATE_DIR, "capture.json")
BACKUP_STATE = os.path.join(STATE_DIR, "backup.json")
UPLOADED_FILE = os.path.join(STATE_DIR, "uploaded.json")

CAMERA_USERNAME = os.environ.get("CAMERA_USERNAME", "")
CAMERA_PASSWORD = os.environ.get("CAMERA_PASSWORD", "")
GO2RTC_URL = os.environ.get("GO2RTC_URL", "").rstrip("/")
S3_BUCKET = os.environ.get("S3_BUCKET", "")

SLOT_MINUTES = 15
# A full-resolution frame from these cameras is ~0.5-1.5 MB. Anything this
# small is an error page, a grey "no signal" frame or a truncated transfer.
MIN_FRAME_BYTES = int(os.environ.get("MIN_FRAME_BYTES", "50000"))
ATTEMPTS_PER_SOURCE = 3
RETRY_DELAY_SECONDS = float(os.environ.get("RETRY_DELAY_SECONDS", "3"))
THUMB_WIDTH = 320


def log(msg):
    print(f"{datetime.now(timezone.utc):%Y-%m-%dT%H:%M:%SZ} {msg}", flush=True)


# --------------------------------------------------------------------------
# Small file helpers
# --------------------------------------------------------------------------

def read_json(path, default):
    try:
        with open(path) as f:
            return json.load(f)
    except (OSError, ValueError):
        return default


def write_atomic(path, data):
    """Write bytes so a reader only ever sees the old file or the whole new one.

    A frame half-written when the host loses power would otherwise sit in
    the archive for years looking like a real one.
    """
    os.makedirs(os.path.dirname(path), exist_ok=True)
    fd, tmp = tempfile.mkstemp(dir=os.path.dirname(path), prefix=".tmp-")
    try:
        with os.fdopen(fd, "wb") as f:
            f.write(data)
            f.flush()
            os.fsync(f.fileno())
        os.chmod(tmp, 0o644)
        os.replace(tmp, path)
    except BaseException:
        try:
            os.unlink(tmp)
        except OSError:
            pass
        raise


def write_json(path, obj):
    write_atomic(path, (json.dumps(obj, indent=2, sort_keys=True) + "\n").encode())


# --------------------------------------------------------------------------
# Naming
# --------------------------------------------------------------------------

def slot_for(now):
    """The 15-minute UTC slot this run belongs to.

    Rounded to the nearest slot rather than floored: the timer fires on the
    slot boundary, but container start-up takes a second or two, and a run
    that somehow started a moment early must still land on its own slot.
    """
    now = now.astimezone(timezone.utc)
    base = now.replace(minute=0, second=0, microsecond=0)
    minutes = round((now - base).total_seconds() / 60 / SLOT_MINUTES) * SLOT_MINUTES
    return base + timedelta(minutes=minutes)


def frame_name(camera, slot):
    return f"{camera}_{slot:%Y%m%dT%H%MZ}.jpg"


def day_dir(camera, day):
    return os.path.join(DATA, camera, f"{day:%Y}", f"{day:%m}", f"{day:%d}")


def frame_path(camera, slot):
    return os.path.join(day_dir(camera, slot), frame_name(camera, slot))


def thumb_path(camera, slot):
    return os.path.join(day_dir(camera, slot), "_thumbs", frame_name(camera, slot))


# --------------------------------------------------------------------------
# Config
# --------------------------------------------------------------------------

def load_cameras():
    """Every camera that exists ([{name, friendly_name, ip, channel}, ...])."""
    return read_json(CAMERAS_FILE, [])


def enabled_cameras():
    """Cameras ticked on the dashboard's settings page, in cameras.json order.

    A name in the config that no longer exists in cameras.json is ignored
    rather than captured from nowhere.
    """
    enabled = set(read_json(CONFIG_FILE, {}).get("enabled", []))
    return [c for c in load_cameras() if c.get("name") in enabled]


# --------------------------------------------------------------------------
# Capture
# --------------------------------------------------------------------------

def valid_jpeg(data):
    """True only for a complete, decodable JPEG of plausible size."""
    if not data or len(data) < MIN_FRAME_BYTES or not data.startswith(b"\xff\xd8\xff"):
        return False
    # A transfer cut off mid-body is the realistic failure, and Pillow's
    # verify() does NOT catch it for JPEG (it only checks headers) -- found
    # by this role's own tests. So: require the end-of-image marker (some
    # cameras pad after it), then fully decode, which raises on truncation.
    if not data.rstrip(b"\x00\r\n ").endswith(b"\xff\xd9"):
        return False
    try:
        Image.open(io.BytesIO(data)).load()
    except Exception:
        return False
    return True


def fetch_from_camera(cam):
    """The camera's own full-resolution JPEG.

    Preferred over go2rtc: it is encoded once by the camera itself at full
    resolution, and it works even while Frigate/go2rtc are down.
    """
    r = requests.get(
        f"http://{cam['ip']}/cgi-bin/snapshot.cgi",
        params={"channel": cam.get("channel", 1)},
        auth=HTTPDigestAuth(CAMERA_USERNAME, CAMERA_PASSWORD),
        timeout=15,
    )
    r.raise_for_status()
    return r.content


def fetch_from_go2rtc(cam):
    """A frame decoded from the live stream go2rtc already holds open."""
    if not GO2RTC_URL:
        raise RuntimeError("GO2RTC_URL not set")
    r = requests.get(f"{GO2RTC_URL}/api/frame.jpeg", params={"src": cam["name"]}, timeout=20)
    r.raise_for_status()
    return r.content


SOURCES = (("camera", fetch_from_camera), ("go2rtc", fetch_from_go2rtc))


def grab(cam):
    """(jpeg bytes, source name, [errors]) -- or (None, None, errors)."""
    errors = []
    for source, fetch in SOURCES:
        for attempt in range(1, ATTEMPTS_PER_SOURCE + 1):
            try:
                data = fetch(cam)
                if valid_jpeg(data):
                    return data, source, errors
                errors.append(f"{source} attempt {attempt}: invalid jpeg ({len(data or b'')} bytes)")
            except Exception as e:
                errors.append(f"{source} attempt {attempt}: {type(e).__name__}: {e}")
            if attempt < ATTEMPTS_PER_SOURCE:
                time.sleep(RETRY_DELAY_SECONDS)
    return None, None, errors


def make_thumbnail(data):
    img = Image.open(io.BytesIO(data))
    img.thumbnail((THUMB_WIDTH, THUMB_WIDTH * 4))
    out = io.BytesIO()
    img.convert("RGB").save(out, "JPEG", quality=80)
    return out.getvalue()


def capture(now=None):
    """Capture this slot for every enabled camera. Returns a process exit code."""
    slot = slot_for(now or datetime.now(timezone.utc))
    cams = enabled_cameras()
    state = read_json(CAPTURE_STATE, {})
    failed = 0

    if not cams:
        log("no cameras enabled; nothing to capture")
    for cam in cams:
        name = cam["name"]
        entry = state.setdefault(name, {})
        path = frame_path(name, slot)
        if os.path.exists(path):
            # A re-run of the same slot (manual or after a crash) must not
            # count as a second identical frame or overwrite the first.
            log(f"{name}: {os.path.basename(path)} already captured")
            continue

        data, source, errors = grab(cam)
        if errors:
            entry["last_error_ts"] = time.time()
            entry["last_error"] = errors[-1]
        if data is None:
            failed += 1
            log(f"{name}: FAILED for slot {slot:%H%MZ}: {'; '.join(errors)}")
            continue

        write_atomic(path, data)
        try:
            write_atomic(thumb_path(name, slot), make_thumbnail(data))
        except Exception as e:
            # A missing preview is cosmetic; the frame itself is what matters.
            log(f"{name}: thumbnail failed: {e}")

        digest = hashlib.sha256(data).hexdigest()
        # Byte-identical consecutive frames mean the camera (or go2rtc) is
        # serving a frozen picture -- a live scene with the camera's clock
        # overlay never produces the same bytes twice.
        entry["identical_streak"] = entry.get("identical_streak", 0) + 1 \
            if entry.get("last_sha256") == digest else 0
        entry.update({
            "last_success_ts": time.time(),
            "last_slot": f"{slot:%Y-%m-%dT%H:%MZ}",
            "last_sha256": digest,
            "last_bytes": len(data),
            "last_source": source,
        })
        log(f"{name}: saved {os.path.relpath(path, DATA)} ({len(data)} bytes via {source})")

    write_json(CAPTURE_STATE, state)
    return 1 if failed else 0


# --------------------------------------------------------------------------
# Backup
# --------------------------------------------------------------------------

def frame_days(camera):
    """Every UTC date that has a directory of frames for this camera."""
    root = os.path.join(DATA, camera)
    days = []
    for y in sorted(os.listdir(root)) if os.path.isdir(root) else []:
        for m in sorted(os.listdir(os.path.join(root, y))):
            for d in sorted(os.listdir(os.path.join(root, y, m))):
                try:
                    days.append(datetime(int(y), int(m), int(d), tzinfo=timezone.utc))
                except ValueError:
                    continue
    return days


def camera_dirs():
    """Every camera with frames on disk -- enabled or not, current or retired."""
    if not os.path.isdir(DATA):
        return []
    return sorted(n for n in os.listdir(DATA)
                  if not n.startswith(".") and os.path.isdir(os.path.join(DATA, n)))


def day_key(camera, day):
    return f"{camera}/{day:%Y%m%d}"


def s3_key(camera, day):
    return f"{camera}/{day:%Y}/{camera}_{day:%Y%m%d}.tar"


def pending_days(today=None):
    """[(camera, day)] for completed UTC days not yet in S3, oldest first."""
    today = (today or datetime.now(timezone.utc)).replace(hour=0, minute=0, second=0, microsecond=0)
    uploaded = read_json(UPLOADED_FILE, {})
    out = [(cam, day) for cam in camera_dirs() for day in frame_days(cam)
           if day < today and day_key(cam, day) not in uploaded]
    return sorted(out, key=lambda x: (x[1], x[0]))


def build_tar(camera, day, fileobj):
    """A plain (uncompressed -- JPEGs don't compress) tar of one camera-day,
    with a SHA256SUMS so a restore years from now can be verified."""
    directory = day_dir(camera, day)
    names = sorted(n for n in os.listdir(directory) if n.endswith(".jpg"))
    sums = []
    with tarfile.open(fileobj=fileobj, mode="w") as tar:
        for n in names:
            p = os.path.join(directory, n)
            with open(p, "rb") as f:
                sums.append(f"{hashlib.sha256(f.read()).hexdigest()}  {n}")
            tar.add(p, arcname=f"{camera}_{day:%Y%m%d}/{n}")
        body = ("\n".join(sums) + "\n").encode()
        info = tarfile.TarInfo(f"{camera}_{day:%Y%m%d}/SHA256SUMS")
        info.size = len(body)
        info.mtime = int(time.time())
        tar.addfile(info, io.BytesIO(body))
    return len(names)


def s3_client():
    import boto3  # only the backup needs it; keeps capture start-up lean
    return boto3.client("s3")


def backup(today=None, client=None):
    """Upload each pending camera-day. Returns a process exit code."""
    state = read_json(BACKUP_STATE, {})
    uploaded = read_json(UPLOADED_FILE, {})
    todo = pending_days(today)
    if not todo:
        log("backup: nothing pending")
    client = client or (s3_client() if todo else None)
    failed = 0

    for camera, day in todo:
        key = s3_key(camera, day)
        try:
            with tempfile.TemporaryFile(dir=STATE_DIR if os.path.isdir(STATE_DIR) else None) as f:
                count = build_tar(camera, day, f)
                size = f.tell()
                f.seek(0)
                # A single PutObject, not boto3's managed multipart upload:
                # the IAM policy only allows DEEP_ARCHIVE writes, and
                # UploadPart requests carry no storage-class header, so
                # multipart would be refused. A camera-day is ~100 MB, far
                # under the 5 GB single-PUT limit.
                client.put_object(Bucket=S3_BUCKET, Key=key, Body=f,
                                  StorageClass="DEEP_ARCHIVE", ContentType="application/x-tar")
            uploaded[day_key(camera, day)] = {"key": key, "frames": count,
                                              "bytes": size, "ts": time.time()}
            write_json(UPLOADED_FILE, uploaded)
            log(f"backup: uploaded s3://{S3_BUCKET}/{key} ({count} frames, {size} bytes)")
        except Exception as e:
            failed += 1
            state["last_error_ts"] = time.time()
            state["last_error"] = f"{key}: {type(e).__name__}: {e}"
            log(f"backup: FAILED {key}: {e}")

    if not failed:
        state["last_success_ts"] = time.time()
    state["last_run_ts"] = time.time()
    os.makedirs(STATE_DIR, exist_ok=True)
    write_json(BACKUP_STATE, state)
    return 1 if failed else 0


def main(argv):
    if len(argv) != 2 or argv[1] not in ("capture", "backup"):
        print(__doc__)
        return 2
    os.makedirs(STATE_DIR, exist_ok=True)
    return capture() if argv[1] == "capture" else backup()


if __name__ == "__main__":
    sys.exit(main(sys.argv))
