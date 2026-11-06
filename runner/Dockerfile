# Sandbox image: Playwright + Chromium, nothing else. No secrets are ever baked
# in or passed at run time. Runs as the unprivileged `pwuser` (uid 1001).
FROM mcr.microsoft.com/playwright/python:v1.49.1-noble
COPY capture.py /app/capture.py
ENV HOME=/tmp \
    PYTHONDONTWRITEBYTECODE=1 \
    OUT_DIR=/out
USER pwuser
WORKDIR /tmp
ENTRYPOINT ["python3", "-u", "/app/capture.py"]
