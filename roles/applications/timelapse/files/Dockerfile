# Built on `service` by roles/applications/timelapse/install.yml as
# timelapse:local and run by systemd timers -- one short-lived container per
# capture/backup, nothing resident between runs.
FROM python:3.12-slim

# Versions pinned so a rebuild years from now produces the same program.
RUN pip install --no-cache-dir requests==2.32.3 Pillow==11.0.0 boto3==1.35.54

COPY timelapse.py /app/timelapse.py

ENTRYPOINT ["python3", "/app/timelapse.py"]
