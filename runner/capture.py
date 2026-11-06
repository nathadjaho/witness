"""
Receipts sandbox runner — runs inside a throwaway container, one page per container.

Input  : one JSON object on stdin  {"url": str, "proxy": str, "token": str, "timeout_s": int}
Output : one JSON object on stdout (last line) + /out/shot.png

What this process can and cannot do is decided by the container, not by this
file: no secrets in its environment, no route to the internet except the
egress proxy, read-only root filesystem, every capability dropped, memory /
CPU / PID caps, and the orchestrator kills it on a wall-clock timeout.

Everything the page does is recorded as evidence: requests, failures (incl.
proxy refusals), popups, download attempts, dialogs, console messages, and
text that is present in the DOM but hidden from a human reader (the usual
carrier for indirect prompt injection).
"""
from __future__ import annotations

import json
import os
import re
import sys
import time

from playwright.sync_api import sync_playwright

OUT = os.environ.get("OUT_DIR", "/out")
MAX_TEXT = 60_000
MAX_LIST = 200

HIDDEN_TEXT_JS = r"""
() => {
  const out = [];
  const push = (where, text) => {
    text = (text || '').replace(/\s+/g, ' ').trim();
    if (text.length >= 12) out.push({ where, text: text.slice(0, 2000) });
  };
  const rgb = s => (s.match(/\d+(\.\d+)?/g) || []).map(Number);
  const same = (a, b) => { a = rgb(a); b = rgb(b); return a.length >= 3 && b.length >= 3 &&
      Math.abs(a[0]-b[0]) + Math.abs(a[1]-b[1]) + Math.abs(a[2]-b[2]) < 30; };
  const bgOf = el => { for (let e = el; e; e = e.parentElement) {
      const c = getComputedStyle(e).backgroundColor;
      if (c && !c.startsWith('rgba(0, 0, 0, 0)') && c !== 'transparent') return c; }
    return 'rgb(255, 255, 255)'; };
  const walker = document.createTreeWalker(document.body || document.documentElement, NodeFilter.SHOW_TEXT);
  const seen = new Set();
  while (walker.nextNode()) {
    const n = walker.currentNode, el = n.parentElement;
    if (!el || seen.has(el) || ['SCRIPT','STYLE','NOSCRIPT'].includes(el.tagName)) continue;
    const t = (n.textContent || '').trim(); if (t.length < 12) continue;
    const cs = getComputedStyle(el), r = el.getBoundingClientRect();
    let why = null;
    if (cs.display === 'none' || cs.visibility === 'hidden') why = 'display/visibility hidden';
    else if (parseFloat(cs.opacity) < 0.05) why = 'opacity ~0';
    else if (parseFloat(cs.fontSize) < 3) why = 'font-size ~0';
    else if (r.width < 2 || r.height < 2) why = 'zero-size box';
    else if (r.right < 0 || r.bottom < 0 || r.left > 10000 || r.top > 100000) why = 'off-screen';
    else if (same(cs.color, bgOf(el))) why = 'text colour = background';
    else if (el.closest('[aria-hidden="true"]')) why = 'aria-hidden';
    if (why) { seen.add(el); push('hidden:' + why, t); }
  }
  document.querySelectorAll('img[alt],[title],meta[name="description"],meta[content]').forEach(e => {
    push('attr:' + e.tagName.toLowerCase(), e.getAttribute('alt') || e.getAttribute('title') || e.getAttribute('content'));
  });
  const cw = document.createTreeWalker(document, NodeFilter.SHOW_COMMENT);
  while (cw.nextNode()) push('html-comment', cw.currentNode.textContent);
  return out.slice(0, 200);
}
"""


def main() -> None:
    job = json.loads(sys.stdin.read() or "{}")
    url = job["url"]
    timeout_ms = int(job.get("timeout_s", 20)) * 1000
    ev: dict = {
        "url": url,
        "requests": [],
        "failed": [],
        "popups": [],
        "downloads": [],
        "dialogs": [],
        "console": [],
        "redirects": [],
        # Secret hygiene self-report: names only, never values.
        "env_names": sorted(k for k in os.environ.keys()),
        "uid": os.getuid(),
    }
    started = time.time()
    with sync_playwright() as p:
        browser = p.chromium.launch(
            headless=True,
            # The container (plus gVisor when enabled) is the sandbox boundary;
            # Chromium's own setuid/userns sandbox can't start with caps dropped.
            chromium_sandbox=False,
            args=["--disable-dev-shm-usage", "--no-first-run", "--disable-extensions",
                  "--disable-background-networking", "--disable-sync"],
            proxy={"server": job["proxy"], "username": job["token"], "password": "x"},
        )
        ctx = browser.new_context(
            accept_downloads=False,
            service_workers="block",
            viewport={"width": 1366, "height": 900},
            java_script_enabled=True,
            permissions=[],
        )
        page = ctx.new_page()

        def on_request(r):
            if len(ev["requests"]) < MAX_LIST:
                ev["requests"].append({"method": r.method, "url": r.url[:500], "type": r.resource_type})
            if r.is_navigation_request() and r.frame == page.main_frame and r.redirected_from:
                ev["redirects"].append(r.url[:500])

        def on_failed(r):
            if len(ev["failed"]) < MAX_LIST:
                ev["failed"].append({"url": r.url[:500], "error": (r.failure or "")[:200]})

        def on_popup(pp):
            ev["popups"].append(pp.url[:500])
            try:
                pp.close()
            except Exception:
                pass

        def on_dialog(d):
            ev["dialogs"].append({"type": d.type, "message": d.message[:300]})
            try:
                d.dismiss()
            except Exception:
                pass

        page.on("request", on_request)
        page.on("requestfailed", on_failed)
        page.on("popup", on_popup)
        page.on("dialog", on_dialog)
        page.on("download", lambda d: ev["downloads"].append(d.url[:500]))
        page.on("console", lambda m: len(ev["console"]) < 50 and ev["console"].append(m.text[:300]))

        status = None
        try:
            resp = page.goto(url, wait_until="domcontentloaded", timeout=timeout_ms)
            status = resp.status if resp else None
            try:
                page.wait_for_load_state("networkidle", timeout=min(6000, timeout_ms))
            except Exception:
                pass
            page.wait_for_timeout(1500)  # let late scripts (and attacks) fire
        except Exception as exc:  # noqa: BLE001
            ev["nav_error"] = str(exc).split("\n")[0][:300]

        try:
            ev["final_url"] = page.url
            ev["title"] = page.title()[:300]
            ev["visible_text"] = page.evaluate("() => document.body ? document.body.innerText : ''")[:MAX_TEXT]
            ev["hidden_text"] = page.evaluate(HIDDEN_TEXT_JS)
            ev["links"] = page.evaluate(
                "() => [...document.querySelectorAll('a[href]')].map(a => ({href: a.href, text: (a.innerText||'').trim().slice(0,80)})).slice(0, 150)"
            )
            page.screenshot(path=os.path.join(OUT, "shot.png"), full_page=True, timeout=10000)
            ev["screenshot"] = "shot.png"
        except Exception as exc:  # noqa: BLE001
            ev["capture_error"] = str(exc).split("\n")[0][:300]

        ev["status"] = status
        ev["elapsed_s"] = round(time.time() - started, 2)
        browser.close()

    # Normalise whitespace in visible text for later exact-quote grounding.
    ev["visible_text"] = re.sub(r"[ \t]+", " ", ev.get("visible_text", ""))
    sys.stdout.write(json.dumps(ev) + "\n")


if __name__ == "__main__":
    main()
