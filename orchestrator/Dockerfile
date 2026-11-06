# Control plane. Holds the inference key and the docker socket; never runs page code.
# The docker CLI is a static Go binary: copy it from the official image rather than
# relying on distro packages (Debian's docker.io no longer ships the CLI).
FROM docker:27-cli AS dockercli

FROM python:3.12-slim
COPY --from=dockercli /usr/local/bin/docker /usr/local/bin/docker
WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
COPY . .
EXPOSE 8000
CMD ["uvicorn", "app:app", "--host", "0.0.0.0", "--port", "8000", "--proxy-headers"]
