"""
Receipts egress proxy — the ONLY path from a sandbox to the network.

Sandboxes live on an `internal` Docker network with no route out. Chromium
inside them is pointed at this proxy. Each sandbox job gets a one-off token
(sent as the proxy username) bound to an allowlist of hostnames that the
orchestrator registers before the job starts. Anything else is refused and
logged, so the UI can show every blocked attempt.

Extra rules, regardless of allowlist:
  * private / link-local / loopback destinations are refused (blocks SSRF to
    the Vultr metadata service at 169.254.169.254, the Docker host, etc.),
    except hosts named in ALLOW_PRIVATE_HOSTS (the local trap site);
  * unknown or expired tokens are refused.

Admin API (control network only, and every call needs X-Admin-Token, which
only the orchestrator holds — so even if a sandbox could reach the port it
could not widen its own allowlist):
  POST /jobs            {"token": str, "allow": [host, ...], "ttl": seconds}
  GET  /jobs/<token>    -> {"events": [...]}
  DELETE /jobs/<token>
"""
from __future__ import annotations

import asyncio
import base64
import ipaddress
import json
import os
import socket
import time
from urllib.parse import urlsplit

PROXY_PORT = int(os.environ.get("PROXY_PORT", "3128"))
ADMIN_PORT = int(os.environ.get("ADMIN_PORT", "9090"))
ADMIN_TOKEN = os.environ.get("ADMIN_TOKEN", "")
ALLOW_PRIVATE_HOSTS = {
    h.strip().lower() for h in os.environ.get("ALLOW_PRIVATE_HOSTS", "").split(",") if h.strip()
}
MAX_EVENTS = 500

# token -> {"allow": set[str], "expires": float, "events": list}
JOBS: dict[str, dict] = {}


def _now() -> float:
    return time.time()


def host_allowed(host: str, allow: set[str]) -> bool:
    host = host.lower().rstrip(".")
    for a in allow:
        a = a.lower().rstrip(".")
        if host == a or host.endswith("." + a):
            return True
    return False


def resolve_is_private(host: str) -> bool:
    try:
        infos = socket.getaddrinfo(host, None)
    except socket.gaierror:
        return False  # unresolvable: connection will fail anyway
    for info in infos:
        ip = ipaddress.ip_address(info[4][0])
        if ip.is_private or ip.is_loopback or ip.is_link_local or ip.is_reserved or ip.is_multicast:
            return True
    return False


def record(job: dict | None, kind: str, host: str, port: int, reason: str = "") -> None:
    if job is None:
        return
    ev = {"t": round(_now(), 3), "kind": kind, "host": host, "port": port}
    if reason:
        ev["reason"] = reason
    if len(job["events"]) < MAX_EVENTS:
        job["events"].append(ev)


def decide(token: str | None, host: str, port: int) -> tuple[bool, dict | None, str]:
    job = JOBS.get(token or "")
    if job is None or job["expires"] < _now():
        return False, None, "unknown_or_expired_token"
    if not host_allowed(host, job["allow"]):
        return False, job, "not_on_allowlist"
    if host.lower() not in ALLOW_PRIVATE_HOSTS and resolve_is_private(host):
        return False, job, "private_address"
    if port not in (80, 443) and host.lower() not in ALLOW_PRIVATE_HOSTS:
        return False, job, "port_not_allowed"
    return True, job, ""


async def _pipe(reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
    try:
        while True:
            data = await reader.read(65536)
            if not data:
                break
            writer.write(data)
            await writer.drain()
    except (ConnectionError, asyncio.CancelledError):
        pass
    finally:
        try:
            writer.close()
        except Exception:
            pass


def _token_from_headers(headers: dict[str, str]) -> str | None:
    auth = headers.get("proxy-authorization", "")
    if not auth.lower().startswith("basic "):
        return None
    try:
        user = base64.b64decode(auth[6:]).decode().split(":", 1)[0]
    except Exception:
        return None
    return user


async def handle_client(reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
    try:
        head = await asyncio.wait_for(reader.readuntil(b"\r\n\r\n"), timeout=15)
    except Exception:
        writer.close()
        return
    lines = head.decode("latin-1").split("\r\n")
    try:
        method, target, version = lines[0].split(" ", 2)
    except ValueError:
        writer.close()
        return
    headers: dict[str, str] = {}
    for line in lines[1:]:
        if ":" in line:
            k, v = line.split(":", 1)
            headers[k.strip().lower()] = v.strip()

    token = _token_from_headers(headers)
    if token is None:
        # Ask the client to authenticate (Chromium sends credentials after a 407).
        writer.write(
            b"HTTP/1.1 407 Proxy Authentication Required\r\n"
            b'Proxy-Authenticate: Basic realm="receipts"\r\nContent-Length: 0\r\n\r\n'
        )
        await writer.drain()
        writer.close()
        return

    if method.upper() == "CONNECT":
        host, _, port_s = target.rpartition(":")
        port = int(port_s or 443)
    else:
        parts = urlsplit(target)
        host = parts.hostname or ""
        port = parts.port or (443 if parts.scheme == "https" else 80)

    ok, job, reason = decide(token, host, port)
    if not ok:
        record(job, "blocked", host, port, reason)
        body = json.dumps({"blocked": host, "reason": reason}).encode()
        writer.write(
            b"HTTP/1.1 403 Forbidden\r\nContent-Type: application/json\r\n"
            + f"Content-Length: {len(body)}\r\nConnection: close\r\n\r\n".encode()
            + body
        )
        await writer.drain()
        writer.close()
        return

    try:
        up_reader, up_writer = await asyncio.wait_for(asyncio.open_connection(host, port), timeout=10)
    except Exception as exc:  # noqa: BLE001
        record(job, "error", host, port, type(exc).__name__)
        writer.write(b"HTTP/1.1 502 Bad Gateway\r\nContent-Length: 0\r\nConnection: close\r\n\r\n")
        await writer.drain()
        writer.close()
        return

    record(job, "allowed", host, port)
    if method.upper() == "CONNECT":
        writer.write(b"HTTP/1.1 200 Connection Established\r\n\r\n")
        await writer.drain()
    else:
        # Plain HTTP: forward request line in origin-form, drop proxy headers.
        parts = urlsplit(target)
        path = parts.path or "/"
        if parts.query:
            path += "?" + parts.query
        out = [f"{method} {path} {version}"]
        for line in lines[1:]:
            if not line or line.lower().startswith(("proxy-authorization", "proxy-connection")):
                continue
            out.append(line)
        up_writer.write(("\r\n".join(out) + "\r\n\r\n").encode("latin-1"))
        await up_writer.drain()

    await asyncio.gather(_pipe(reader, up_writer), _pipe(up_reader, writer))


# ---------------------------------------------------------------- admin API
async def handle_admin(reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
    try:
        head = await asyncio.wait_for(reader.readuntil(b"\r\n\r\n"), timeout=10)
        lines = head.decode().split("\r\n")
        method, path, _ = lines[0].split(" ", 2)
        length, auth = 0, ""
        for line in lines[1:]:
            if line.lower().startswith("content-length:"):
                length = int(line.split(":", 1)[1])
            if line.lower().startswith("x-admin-token:"):
                auth = line.split(":", 1)[1].strip()
        body = await reader.readexactly(min(length, 65536)) if length else b""
        status, payload = 404, {"error": "not found"}

        if path != "/health" and (not ADMIN_TOKEN or auth != ADMIN_TOKEN):
            status, payload = 401, {"error": "admin token required"}
        elif method == "POST" and path == "/jobs":
            data = json.loads(body or b"{}")
            JOBS[data["token"]] = {
                "allow": {h.lower() for h in data.get("allow", [])},
                "expires": _now() + float(data.get("ttl", 120)),
                "events": [],
            }
            status, payload = 201, {"ok": True}
        elif path.startswith("/jobs/"):
            token = path.split("/", 2)[2]
            job = JOBS.get(token)
            if method == "GET" and job:
                status, payload = 200, {"events": job["events"], "allow": sorted(job["allow"])}
            elif method == "DELETE":
                JOBS.pop(token, None)
                status, payload = 200, {"ok": True}
        elif path == "/health":
            status, payload = 200, {"ok": True, "jobs": len(JOBS)}

        raw = json.dumps(payload).encode()
        writer.write(
            f"HTTP/1.1 {status} X\r\nContent-Type: application/json\r\nContent-Length: {len(raw)}\r\n"
            f"Connection: close\r\n\r\n".encode() + raw
        )
        await writer.drain()
    except Exception:
        pass
    finally:
        writer.close()


async def gc_loop() -> None:
    while True:
        await asyncio.sleep(30)
        cutoff = _now() - 600
        for t in [t for t, j in JOBS.items() if j["expires"] < cutoff]:
            JOBS.pop(t, None)


async def main() -> None:
    proxy = await asyncio.start_server(handle_client, "0.0.0.0", PROXY_PORT)
    admin = await asyncio.start_server(handle_admin, os.environ.get("ADMIN_BIND", "0.0.0.0"), ADMIN_PORT)
    print(f"egress proxy :{PROXY_PORT}  admin :{ADMIN_PORT}  private-ok={sorted(ALLOW_PRIVATE_HOSTS)}", flush=True)
    asyncio.create_task(gc_loop())
    async with proxy, admin:
        await asyncio.gather(proxy.serve_forever(), admin.serve_forever())


if __name__ == "__main__":
    asyncio.run(main())
