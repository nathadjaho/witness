"""Witness control plane — runs on the Vultr VM. Holds the keys, never runs page code."""
from __future__ import annotations

import asyncio
import json
import time
import uuid
from pathlib import Path

from fastapi import FastAPI, HTTPException
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
    n: int = Field(10, ge=1, le=50)


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
async def create_run(req: RunRequest):
    for c in req.companies:
        _validate_url(c.url)
    body = req.model_dump()
    rid = _new_run("research", body)
    TASKS[rid] = asyncio.create_task(_guarded(rid, lambda: agent.research_run(rid, body), "run_finished"))
    return {"run_id": rid}


@app.post("/api/lab")
async def create_lab(req: LabRequest):
    rid = _new_run("lab", req.model_dump())
    TASKS[rid] = asyncio.create_task(_guarded(rid, lambda: attacks.run_lab(rid, req.only), "lab_finished"))
    return {"run_id": rid}


@app.post("/api/eval")
async def create_eval(req: EvalRequest):
    rid = _new_run("eval", req.model_dump())
    TASKS[rid] = asyncio.create_task(_guarded(rid, lambda: evals.run_eval(rid, req.n), "eval_finished"))
    return {"run_id": rid}


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
    rows = ledger.db().execute("SELECT * FROM actions WHERE status=? ORDER BY created DESC", (status,)).fetchall()
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
