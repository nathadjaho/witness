# Sandbox image: Playwright + Chromium, nothing else. No secrets are ever baked
# in or passed at run time. Runs as the unprivileged `pwuser` (uid 1001).
FROM mcr.microsoft.com/playwright/python:v1.49.1-noble
# Make sure the Python package matches the bundled browsers and is importable
# by the system interpreter, whatever the base image does.
RUN python3 -m pip install --no-cache-dir --break-system-packages playwright==1.49.1 \
 && python3 -c "import playwright; print('playwright ok')"
COPY capture.py /app/capture.py
ENV HOME=/tmp \
    PYTHONDONTWRITEBYTECODE=1 \
    OUT_DIR=/out \
    PLAYWRIGHT_BROWSERS_PATH=/ms-playwright
USER pwuser
WORKDIR /tmp
ENTRYPOINT ["python3", "-u", "/app/capture.py"]
