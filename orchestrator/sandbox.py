"""
Dispatches one page visit into one throwaway container and returns what
actually happened — including proof that the container is gone.
"""
from __future__ import annotations

import asyncio
import hashlib
import json
import os
import secrets
import subprocess
import time
from pathlib import Path

import httpx

import config

SECRET_HINTS = ("KEY", "TOKEN", "SECRET", "PASSWORD", "PASSWD", "CREDENTIAL", "AUTH")


def sandbox_flags(name: str, out_dir_host: str) -> list[str]:
    flags = [
        "--rm", "-i", "--name", name,
        "--network", config.SANDBOX_NETWORK,      # internal network: no route out
        "--dns", "127.0.0.1",                     # no resolver: blocks DNS exfiltration
        "--read-only",
        "--tmpfs", "/tmp:rw,nosuid,nodev,size=256m",
        "--cap-drop", "ALL",
        "--security-opt", "no-new-privileges",
        "--pids-limit", config.SANDBOX_PIDS,
        "--memory", config.SANDBOX_MEMORY, "--memory-swap", config.SANDBOX_MEMORY,
        "--cpus", config.SANDBOX_CPUS,
        "--ipc", "private",
        "--ulimit", "nofile=2048:2048",
        "--user", "1001:1001",
        "-v", f"{out_dir_host}:/out:rw",
        "--label", "app=witness-sandbox",
    ]
    if config.SANDBOX_RUNTIME:
        flags += ["--runtime", config.SANDBOX_RUNTIME]
    return flags


def describe_flags() -> dict:
    return {
        "runtime": config.SANDBOX_RUNTIME or "runc",
        "network": f"{config.SANDBOX_NETWORK} (internal, egress only via allowlist proxy)",
        "dns": "disabled",
        "root_fs": "read-only",
        "capabilities": "all dropped",
        "no_new_privileges": True,
        "user": "1001 (non-root)",
        "memory": config.SANDBOX_MEMORY,
        "cpus": config.SANDBOX_CPUS,
        "pids": config.SANDBOX_PIDS,
        "wall_clock_s": config.SANDBOX_TIMEOUT_S,
        "secrets_in_env": 0,
        "lifecycle": "one container per page, --rm, existence re-checked after exit",
    }


async def _proxy(method: str, path: str, body: dict | None = None) -> dict:
    async with httpx.AsyncClient(timeout=5) as c:
        r = await c.request(method, config.PROXY_ADMIN_URL + path, json=body,
                            headers={"X-Admin-Token": config.PROXY_ADMIN_TOKEN})
        r.raise_for_status()
        return r.json()


def _container_exists(name: str) -> bool:
    r = subprocess.run(["docker", "ps", "-a", "-q", "--filter", f"name=^{name}$"],
                       capture_output=True, text=True, timeout=10)
    return bool(r.stdout.strip())


def _run_blocking(name: str, flags: list[str], job: dict) -> dict:
    started = time.time()
    killed = False
    try:
        proc = subprocess.run(["docker", "run", *flags, config.RUNNER_IMAGE],
                              input=json.dumps(job), capture_output=True, text=True,
                              timeout=config.SANDBOX_TIMEOUT_S)
        code, stdout, stderr = proc.returncode, proc.stdout, proc.stderr
    except subprocess.TimeoutExpired as exc:
        killed = True
        subprocess.run(["docker", "kill", name], capture_output=True, timeout=15)
        code = None
        stdout = exc.stdout.decode() if isinstance(exc.stdout, bytes) else (exc.stdout or "")
        stderr = "killed by watchdog after %ss" % config.SANDBOX_TIMEOUT_S
    # --rm removes the container asynchronously; confirm it is really gone.
    exists = True
    for _ in range(20):
        exists = _container_exists(name)
        if not exists:
            break
        time.sleep(0.25)
    return {"exit_code": code, "stdout": stdout, "stderr": stderr[-1500:],
            "killed_by_watchdog": killed, "destroyed": not exists,
            "wall_s": round(time.time() - started, 2)}


def _sha256(path: Path) -> str | None:
    if not path.exists():
        return None
    return hashlib.sha256(path.read_bytes()).hexdigest()


async def run_capture(url: str, allow: list[str], run_id: str, step_id: str) -> dict:
    """Visit one URL in a fresh sandbox. Returns untrusted page evidence + trusted
    containment facts (proxy log, exit status, destruction check, hashes)."""
    token = secrets.token_urlsafe(18)
    name = f"wtn-{step_id}"
    out_local = Path(config.ARTIFACTS_DIR) / run_id / step_id
    out_local.mkdir(parents=True, exist_ok=True)
    os.chmod(out_local, 0o777)  # writable by the sandbox's uid 1001 only for this step
    out_host = str(Path(config.HOST_ARTIFACTS_DIR) / run_id / step_id)

    await _proxy("POST", "/jobs", {"token": token, "allow": allow, "ttl": config.SANDBOX_TIMEOUT_S + 30})
    job = {"url": url, "proxy": config.PROXY_URL_FOR_SANDBOX, "token": token,
           "timeout_s": max(5, config.SANDBOX_TIMEOUT_S - 12)}
    try:
        res = await asyncio.to_thread(_run_blocking, name, sandbox_flags(name, out_host), job)
    finally:
        try:
            egress = (await _proxy("GET", f"/jobs/{token}")).get("events", [])
        except Exception:
            egress = []
        try:
            await _proxy("DELETE", f"/jobs/{token}")
        except Exception:
            pass
    os.chmod(out_local, 0o755)

    page: dict = {}
    for line in reversed(res["stdout"].strip().splitlines()):
        try:
            page = json.loads(line)
            break
        except json.JSONDecodeError:
            continue
    page = _sanitize(page)
    shot = out_local / "shot.png"
    leaked_env = [n for n in page.get("env_names", []) if any(h in n.upper() for h in SECRET_HINTS)]

    return {
        "url": url,
        "step_id": step_id,
        "page": page,                      # untrusted: produced inside the sandbox
        "containment": {                   # trusted: observed by the control plane
            "exit_code": res["exit_code"],
            "killed_by_watchdog": res["killed_by_watchdog"],
            "oom_or_signal": res["exit_code"] in (137, 139) and not res["killed_by_watchdog"],
            "destroyed": res["destroyed"],
            "wall_s": res["wall_s"],
            "egress_allowed": [e for e in egress if e["kind"] == "allowed"],
            "egress_blocked": [e for e in egress if e["kind"] == "blocked"],
            "secret_like_env_vars": leaked_env,
            "files_written": sorted(f.name for f in out_local.iterdir()),
            "stderr_tail": res["stderr"][-400:] if res["exit_code"] not in (0,) else "",
        },
        "screenshot": f"/artifacts/{run_id}/{step_id}/shot.png" if shot.exists() else None,
        "screenshot_sha256": _sha256(shot),
    }


def _sanitize(page: dict) -> dict:
    """Runner output is attacker-influenced. Keep only expected keys, cap sizes."""
    if not isinstance(page, dict):
        return {}
    keep = {"url", "final_url", "title", "status", "visible_text", "hidden_text", "links",
            "requests", "failed", "popups", "downloads", "dialogs", "console", "redirects",
            "nav_error", "capture_error", "env_names", "uid", "elapsed_s", "screenshot"}
    out = {k: page[k] for k in keep if k in page}
    if isinstance(out.get("visible_text"), str):
        out["visible_text"] = out["visible_text"][:60_000]
    for k in ("hidden_text", "links", "requests", "failed", "popups", "downloads", "dialogs", "console", "redirects"):
        if not isinstance(out.get(k), list):
            out[k] = []
        out[k] = out[k][:200]
    return out
