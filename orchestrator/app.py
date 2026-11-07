"""Witness control plane — runs on the Vultr VM. Holds the keys, never runs page code."""
from __future__ import annotations

import asyncio
import json
import time
import uuid
from pathlib import Path

from fastapi import FastAPI, HTTPException, Request
from fastapi.responses import FileResponse, StreamingResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel, Field

import agent
import attacks
import config
import evals
import ledger
import sandbox

app = FastAPI(title="Witness", version="0.1")
STATIC = Path(__file__).parent / "static"
TASKS: dict[str, asyncio.Task] = {}


class Company(BaseModel):
    url: str
    name: str | None = None


class RunRequest(BaseModel):
    companies: list[Company] = Field(..., min_length=1, max_length=config.MAX_COMPANIES)
    criteria: list[str] = Field(..., min_length=1, max_length=8)
    strip_hidden: bool = True


class Decision(BaseModel):
    approve: bool
    reason: str = ""


class LabRequest(BaseModel):
    only: list[str] | None = None


class EvalRequest(BaseModel):
    n: int = Field(10, ge=1, le=10)


def _guarded(rid: str, coro_fn, finish_kind: str):
    """Run a background job; if it crashes, record the error so the run never hangs as 'running'."""
    async def go():
        try:
            res = await coro_fn()
            status = "done"
        except Exception as exc:  # noqa: BLE001
            import traceback
            res = {"error": f"{type(exc).__name__}: {exc}"[:500], "trace": traceback.format_exc()[-1500:]}
            ledger.append(rid, finish_kind, {"error": res["error"], "contained": 0, "total": 0,
                                             "results": [], "ledger": ledger.verify(rid)})
            status = "error"
        ledger.db().execute("UPDATE runs SET status=?, result=? WHERE id=?", (status, json.dumps(res), rid))
        ledger.db().commit()
    return go()


_HITS: list[tuple[float, str, str]] = []  # (time, ip, kind)


def _client_ip(request: Request) -> str:
    # Behind Caddy: the first X-Forwarded-For entry is the visitor.
    fwd = request.headers.get("x-forwarded-for", "")
    return fwd.split(",")[0].strip() or (request.client.host if request.client else "?")


def _rate_guard(request: Request, kind: str) -> None:
    now = time.time()
    _HITS[:] = [h for h in _HITS if now - h[0] < 86400]
    ip = _client_ip(request)
    if sum(1 for h in _HITS if now - h[0] < 3600 and h[1] == ip) >= config.RUNS_PER_IP_PER_HOUR:
        raise HTTPException(429, "Demo limit reached for your address. Please try again within the hour.")
    if kind == "eval" and sum(1 for h in _HITS if now - h[0] < 3600 and h[2] == "eval") >= config.EVALS_PER_HOUR:
        raise HTTPException(429, "The injection eval is limited to a few runs per hour on the public demo. The latest result is shown above.")
    if len(_HITS) >= config.RUNS_PER_DAY:
        raise HTTPException(429, "The public demo reached its daily limit. The latest results remain visible.")
    _HITS.append((now, ip, kind))


def _busy_guard() -> None:
    # Public demo URL: cap concurrency so strangers can't turn the VM into a crawler.
    running = sum(1 for t in TASKS.values() if not t.done())
    if running >= config.MAX_CONCURRENT_RUNS:
        raise HTTPException(429, "a run is already in progress — try again in a minute")


def _new_run(kind: str, req: dict) -> str:
    _busy_guard()
    rid = uuid.uuid4().hex[:12]
    ledger.db().execute("INSERT INTO runs VALUES(?,?,?,?,?)", (rid, time.time(), "running", json.dumps({"kind": kind, **req}), None))
    ledger.db().commit()
    return rid


def _validate_url(u: str) -> None:
    full = u if "://" in u else "https://" + u
    if not full.startswith(("http://", "https://")):
        raise HTTPException(400, "only http(s) URLs")
    if not agent.domain_of(full):
        raise HTTPException(400, f"bad URL {u}")


@app.get("/api/health")
def health():
    return {"ok": True, "llm": "offline-fallback" if config.MOCK_LLM else (config.PLANNER_MODEL or "provider default (PLANNER_MODEL unset)"),
            "vision": config.VISION_MODEL or None, "sandbox": sandbox.describe_flags()}


@app.post("/api/runs")
async def create_run(req: RunRequest, request: Request):
    for c in req.companies:
        _validate_url(c.url)
    _busy_guard()
    _rate_guard(request, "research")
    body = req.model_dump()
    rid = _new_run("research", body)
    TASKS[rid] = asyncio.create_task(_guarded(rid, lambda: agent.research_run(rid, body), "run_finished"))
    return {"run_id": rid}


@app.post("/api/lab")
async def create_lab(req: LabRequest, request: Request):
    _busy_guard()
    _rate_guard(request, "lab")
    rid = _new_run("lab", req.model_dump())
    TASKS[rid] = asyncio.create_task(_guarded(rid, lambda: attacks.run_lab(rid, req.only), "lab_finished"))
    return {"run_id": rid}


@app.post("/api/eval")
async def create_eval(req: EvalRequest, request: Request):
    _busy_guard()
    _rate_guard(request, "eval")
    rid = _new_run("eval", req.model_dump())
    TASKS[rid] = asyncio.create_task(_guarded(rid, lambda: evals.run_eval(rid, req.n), "eval_finished"))
    return {"run_id": rid}


@app.get("/api/latest")
def latest(kind: str = "research"):
    """Most recent finished run of a kind, so a first-time visitor sees a filled dashboard."""
    fallback = None
    for r in ledger.db().execute("SELECT id, request, result FROM runs WHERE status='done' ORDER BY created DESC LIMIT 100"):
        if json.loads(r["request"]).get("kind") != kind:
            continue
        fallback = fallback or r["id"]
        res = json.loads(r["result"]) if r["result"] else None
        # Prefer the latest run that actually verified something, so one failed visitor run
        # (e.g. a bot-protected site) does not become everyone's first impression.
        if isinstance(res, list) and any(c.get("verified", 0) > 0 for c in res):
            return get_run(r["id"])
    if fallback:
        return get_run(fallback)
    raise HTTPException(404, "no finished run yet")


@app.get("/api/stats")
def stats():
    """Latest measured numbers, for the landing strip. Read from finished runs only."""
    out = {"lab": None, "eval": None, "checks": 0}
    rows = ledger.db().execute("SELECT request, result FROM runs WHERE status='done' ORDER BY created DESC LIMIT 200").fetchall()
    for r in rows:
        kind = json.loads(r["request"]).get("kind")
        res = json.loads(r["result"]) if r["result"] else None
        if kind == "research":
            out["checks"] += 1
        elif kind == "lab" and out["lab"] is None and res and res.get("total"):
            out["lab"] = {"contained": res["contained"], "total": res["total"]}
        elif kind == "eval" and out["eval"] is None and res and res.get("l3_off", {}).get("trials"):
            out["eval"] = {"model": res["model"], "l3_off": res["l3_off"], "l3_on": res["l3_on"]}
    return out


@app.get("/api/runs")
def list_runs():
    rows = ledger.db().execute("SELECT id, created, status, request FROM runs ORDER BY created DESC LIMIT 30").fetchall()
    return [{"id": r["id"], "created": r["created"], "status": r["status"], "request": json.loads(r["request"])} for r in rows]


@app.get("/api/runs/{rid}")
def get_run(rid: str):
    r = ledger.db().execute("SELECT * FROM runs WHERE id=?", (rid,)).fetchone()
    if not r:
        raise HTTPException(404)
    return {"id": rid, "status": r["status"], "request": json.loads(r["request"]),
            "result": json.loads(r["result"]) if r["result"] else None, "events": ledger.events(rid)}


@app.get("/api/runs/{rid}/stream")
async def stream(rid: str):
    async def gen():
        last = -1
        while True:
            evs = ledger.events(rid, last)
            for e in evs:
                last = e["seq"]
                yield f"data: {json.dumps(e)}\n\n"
                if e["kind"] in ("run_finished", "lab_finished", "eval_finished"):
                    return
            await asyncio.sleep(0.5)
            yield ": keepalive\n\n"
    return StreamingResponse(gen(), media_type="text/event-stream")


@app.get("/api/runs/{rid}/verify")
def verify(rid: str):
    return ledger.verify(rid)


@app.get("/api/actions")
def actions(status: str = "pending"):
    rows = ledger.db().execute("SELECT * FROM actions WHERE status=? ORDER BY created DESC LIMIT 6", (status,)).fetchall()
    return [{"id": r["id"], "run_id": r["run_id"], "kind": r["kind"], "status": r["status"],
             "payload": json.loads(r["payload"])} for r in rows]


@app.post("/api/actions/{aid}")
async def decide(aid: str, d: Decision):
    res = await agent.decide_action(aid, d.approve, d.reason)
    if not res["ok"]:
        raise HTTPException(409, res["error"])
    return res


@app.get("/api/crm")
def crm():
    rows = ledger.db().execute("SELECT * FROM crm ORDER BY created DESC").fetchall()
    return [dict(r) | {"evidence": json.loads(r["evidence"])} for r in rows]


@app.get("/artifacts/{rid}/{step}/{name}")
def artifact(rid: str, step: str, name: str):
    base = Path(config.ARTIFACTS_DIR).resolve()
    p = (base / rid / step / name).resolve()
    if base not in p.parents or not p.is_file() or p.suffix != ".png":
        raise HTTPException(404)
    # Screenshots of hostile pages are served as images only.
    return FileResponse(p, media_type="image/png", headers={"X-Content-Type-Options": "nosniff"})


@app.get("/")
def index():
    return FileResponse(STATIC / "index.html")


app.mount("/static", StaticFiles(directory=STATIC), name="static")
