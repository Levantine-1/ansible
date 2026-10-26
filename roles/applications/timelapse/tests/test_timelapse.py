"""Checks for timelapse.py, run inside the built image so Pillow/requests are
the exact versions that will capture for years:

    docker run --rm --entrypoint python3 -v $PWD/tests:/tests timelapse:local /tests/test_timelapse.py

Network and S3 are stubbed; everything else (naming, atomic writes, JPEG
validation, the enabled-camera filter, backup idempotency) is real.
"""

import io
import json
import os
import sys
import tarfile
import tempfile
from datetime import datetime, timezone

WORK = tempfile.mkdtemp(prefix="timelapse-test-")
os.environ.update(TIMELAPSE_DATA=WORK, CAMERAS_FILE=os.path.join(WORK, "cameras.json"),
                  RETRY_DELAY_SECONDS="0", S3_BUCKET="test-bucket",
                  GO2RTC_URL="http://go2rtc.invalid:1984")
sys.path.insert(0, "/app")
sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "files"))

import timelapse as t  # noqa: E402
from PIL import Image  # noqa: E402

failures = []


def check(name, condition, detail=""):
    print(("PASS  " if condition else "FAIL  ") + name + ("" if condition else f"  -> {detail}"))
    if not condition:
        failures.append(name)


def jpeg(seed=0, size=(1280, 720)):
    """A real, decodable JPEG over MIN_FRAME_BYTES -- noise, so it doesn't
    compress below the size floor, and seeded so frames differ or match on
    purpose."""
    import random
    rnd = random.Random(seed)
    img = Image.frombytes("RGB", size, bytes(rnd.getrandbits(8) for _ in range(size[0] * size[1] * 3)))
    out = io.BytesIO()
    img.save(out, "JPEG", quality=90)
    return out.getvalue()


CAMS = [{"name": "baby-ptz", "friendly_name": "Baby PTZ", "ip": "10.0.0.1", "channel": 1},
        {"name": "the-boiz", "friendly_name": "The Boiz", "ip": "10.0.0.2", "channel": 1}]
with open(t.CAMERAS_FILE, "w") as f:
    json.dump(CAMS, f)
os.makedirs(os.path.dirname(t.CONFIG_FILE), exist_ok=True)


def set_enabled(names):
    with open(t.CONFIG_FILE, "w") as f:
        json.dump({"enabled": names}, f)


def main():
    # --- naming ---------------------------------------------------------
    slot = t.slot_for(datetime(2026, 10, 23, 14, 15, 1, tzinfo=timezone.utc))
    check("a run just after the boundary lands on that slot", slot.minute == 15, slot)
    slot = t.slot_for(datetime(2026, 10, 23, 14, 14, 59, tzinfo=timezone.utc))
    check("a run just before the boundary still lands on it", slot.minute == 15, slot)
    slot = t.slot_for(datetime(2026, 10, 23, 14, 59, 30, tzinfo=timezone.utc))
    check("a run just before the hour lands on the next hour",
          (slot.hour, slot.minute) == (15, 0), slot)
    slot = t.slot_for(datetime(2026, 10, 26, 6, 8, 53, tzinfo=timezone.utc))
    check("a manual run mid-slot belongs to the slot already started, not the next one",
          (slot.hour, slot.minute) == (6, 0), slot)
    slot = t.slot_for(datetime(2026, 10, 23, 14, 52, 40, tzinfo=timezone.utc))
    check("a run 7 minutes before a boundary stays in its own slot",
          (slot.hour, slot.minute) == (14, 45), slot)
    check("frame names are camera then UTC timestamp",
          t.frame_name("baby-ptz", datetime(2026, 10, 23, 14, 15, tzinfo=timezone.utc))
          == "baby-ptz_20261023T1415Z.jpg")
    check("frames live under camera/YYYY/MM/DD",
          t.frame_path("baby-ptz", datetime(2026, 1, 2, 3, 45, tzinfo=timezone.utc))
          .endswith(os.path.join("baby-ptz", "2026", "01", "02", "baby-ptz_20260102T0345Z.jpg")))

    # --- validation -----------------------------------------------------
    good = jpeg(1)
    check("a real full-size jpeg is valid", t.valid_jpeg(good))
    check("an error page is not a frame", not t.valid_jpeg(b"<html>401 Unauthorized</html>" * 3000))
    check("a truncated jpeg is not a frame", not t.valid_jpeg(good[: len(good) // 2]))
    check("a tiny jpeg (no-signal frame) is not a frame", not t.valid_jpeg(jpeg(1, (64, 36))))

    # --- capture: enabled filter, fallback, idempotency, frozen ------------
    calls = []

    def camera_ok(cam):
        calls.append(("camera", cam["name"]))
        return good

    def camera_down(cam):
        calls.append(("camera", cam["name"]))
        raise ConnectionError("no route to host")

    def go2rtc_ok(cam):
        calls.append(("go2rtc", cam["name"]))
        return jpeg(2)

    def go2rtc_down(cam):
        calls.append(("go2rtc", cam["name"]))
        raise ConnectionError("go2rtc down")

    set_enabled(["baby-ptz"])
    t.SOURCES = (("camera", camera_ok), ("go2rtc", go2rtc_ok))
    at = datetime(2026, 10, 23, 14, 15, tzinfo=timezone.utc)
    rc = t.capture(at)
    p = t.frame_path("baby-ptz", at)
    check("capture succeeds", rc == 0, rc)
    check("only enabled cameras are captured",
          os.path.exists(p) and not os.path.exists(t.frame_path("the-boiz", at))
          and all(name == "baby-ptz" for _, name in calls), calls)
    check("a thumbnail is written beside the frame",
          os.path.exists(t.thumb_path("baby-ptz", at))
          and Image.open(t.thumb_path("baby-ptz", at)).width == t.THUMB_WIDTH)
    check("no temp files are left behind",
          not [n for n in os.listdir(os.path.dirname(p)) if n.startswith(".tmp-")])
    state = json.load(open(t.CAPTURE_STATE))
    check("state records the success and its source",
          state["baby-ptz"].get("last_source") == "camera" and "last_success_ts" in state["baby-ptz"])

    calls.clear()
    rc = t.capture(at)
    check("re-running the same slot fetches nothing and keeps the frame",
          rc == 0 and calls == [] and open(p, "rb").read() == good, calls)

    t.SOURCES = (("camera", camera_down), ("go2rtc", go2rtc_ok))
    at2 = datetime(2026, 10, 23, 14, 30, tzinfo=timezone.utc)
    calls.clear()
    rc = t.capture(at2)
    state = json.load(open(t.CAPTURE_STATE))
    check("camera failure falls back to go2rtc after its retries",
          rc == 0 and os.path.exists(t.frame_path("baby-ptz", at2))
          and calls.count(("camera", "baby-ptz")) == t.ATTEMPTS_PER_SOURCE
          and state["baby-ptz"]["last_source"] == "go2rtc", calls)
    check("the fallback still records the camera error", "last_error_ts" in state["baby-ptz"])

    t.SOURCES = (("camera", camera_down), ("go2rtc", go2rtc_down))
    at3 = datetime(2026, 10, 23, 14, 45, tzinfo=timezone.utc)
    rc = t.capture(at3)
    check("both sources down: non-zero exit and no file",
          rc == 1 and not os.path.exists(t.frame_path("baby-ptz", at3)), rc)

    # Frozen detection: the same bytes three slots running.
    t.SOURCES = (("camera", camera_ok),)
    for minute in (0, 15, 30):
        t.capture(datetime(2026, 10, 23, 16, minute, tzinfo=timezone.utc))
    state = json.load(open(t.CAPTURE_STATE))
    check("identical consecutive frames are counted as a frozen streak",
          state["baby-ptz"]["identical_streak"] >= 2, state["baby-ptz"])

    set_enabled(["baby-ptz", "no-such-camera"])
    calls.clear()
    t.capture(datetime(2026, 10, 23, 17, 0, tzinfo=timezone.utc))
    check("a configured name missing from cameras.json is ignored",
          all(name == "baby-ptz" for _, name in calls), calls)

    # --- backup -------------------------------------------------------------
    class FakeS3:
        def __init__(self):
            self.puts = []

        def put_object(self, **kw):
            self.puts.append({**kw, "Body": kw["Body"].read()})

    s3 = FakeS3()
    today = datetime(2026, 10, 24, 3, 0, tzinfo=timezone.utc)
    pending = t.pending_days(today)
    check("completed days are pending, today is not",
          [(c, d.day) for c, d in pending] == [("baby-ptz", 23)], pending)
    rc = t.backup(today, client=s3)
    put = s3.puts[0] if s3.puts else {}
    check("backup uploads one DEEP_ARCHIVE tar per camera-day",
          rc == 0 and len(s3.puts) == 1 and put["StorageClass"] == "DEEP_ARCHIVE"
          and put["Key"] == "baby-ptz/2026/baby-ptz_20261023.tar", [p.get("Key") for p in s3.puts])
    with tarfile.open(fileobj=io.BytesIO(put.get("Body", b""))) as tar:
        names = tar.getnames()
        sums = tar.extractfile("baby-ptz_20261023/SHA256SUMS").read().decode()
    check("the tar holds the day's frames plus SHA256SUMS, not thumbnails",
          "baby-ptz_20261023/baby-ptz_20261023T1415Z.jpg" in names
          and not any("_thumbs" in n for n in names) and "baby-ptz_20261023T1415Z.jpg" in sums, names)

    rc = t.backup(today, client=s3)
    check("a second backup run uploads nothing", rc == 0 and len(s3.puts) == 1, len(s3.puts))
    check("backup state records success", "last_success_ts" in json.load(open(t.BACKUP_STATE)))

    class BrokenS3:
        def put_object(self, **kw):
            raise RuntimeError("AccessDenied")

    t.SOURCES = (("camera", camera_ok),)
    t.capture(datetime(2026, 10, 24, 1, 0, tzinfo=timezone.utc))
    rc = t.backup(datetime(2026, 10, 25, 3, 0, tzinfo=timezone.utc), client=BrokenS3())
    check("a failed upload exits non-zero and stays pending",
          rc == 1 and ("baby-ptz", 24) in [(c, d.day) for c, d in
                                           t.pending_days(datetime(2026, 10, 25, tzinfo=timezone.utc))])

    print()
    print("ALL PASS" if not failures else "FAILURES: " + ", ".join(failures))
    return 1 if failures else 0


if __name__ == "__main__":
    sys.exit(main())
