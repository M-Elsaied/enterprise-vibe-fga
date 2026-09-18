"""
Identity gateway for the neuro-san studio (nsflow).

Sits between the nsflow backend and the neuro-san server and does the one job
an SSO layer does in a real deployment: strip any inbound user_id header and
set the verified identity. Here the "verified identity" is the persona you
pick, so you can watch enforcement happen inside the real studio UI.

    browser -> nsflow (:4173) -> THIS GATEWAY (:8210) -> neuro-san (:8123) -> OpenFGA

Why it is needed: nsflow 0.6.19 sends no user_id on its concierge/list call
and hardcodes chat identity to the backend's USER env var - so identity has
to be asserted at the hop the runtime actually trusts, which is exactly how
the production architecture works anyway.

Usage:
    powershell -File authz\\run_e2e.ps1 -KeepUp
    .venv\\Scripts\\python.exe authz\\studio_gateway.py            # gateway on :8210
    $env:NEURO_SAN_SERVER_HOST="127.0.0.1"
    $env:NEURO_SAN_SERVER_HTTP_PORT="8210"
    .venv\\Scripts\\python.exe -m nsflow.run --client-only         # studio on :4173

    Studio:   http://127.0.0.1:4173
    Personas: http://127.0.0.1:8210/__persona   (switch, then refresh the studio)
"""

import os
import threading
import urllib.error
import urllib.request
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

TARGET = os.environ.get("E2E_BASE", "http://127.0.0.1:8123")
PORT = int(os.environ.get("GATEWAY_PORT", "8210"))
# Comma-separated override, e.g. "adam,dina,ana,bob,mia,sam,eve" for the
# studio-profile persona set; default = the full-profile marketplace personas.
PERSONAS = [p.strip() for p in os.environ.get(
    "GATEWAY_PERSONAS", "sam,ada,alice,bob,eve").split(",") if p.strip()]

_state = {"persona": "alice"}
_lock = threading.Lock()

# Headers we must not blindly copy between hops.
HOP_HEADERS = {"connection", "keep-alive", "transfer-encoding", "host",
               "content-length", "te", "upgrade", "proxy-authorization"}

PERSONA_PAGE = """<!doctype html>
<html><head><meta charset="utf-8"><title>Studio Identity Gateway</title>
<style>
 body {{ font-family:'Segoe UI',system-ui,sans-serif; background:#0d1117; color:#e6edf3;
        padding:2.5rem; }}
 h1 {{ font-size:1.2rem; }} .sub {{ color:#8b949e; font-size:.9rem; margin-bottom:1.2rem; }}
 button {{ background:#161b22; color:#e6edf3; border:1px solid #30363d; border-radius:999px;
        padding:.5rem 1.2rem; margin:.25rem; cursor:pointer; font-size:1rem; }}
 button.active {{ background:#1f6feb; border-color:#1f6feb; }}
 .note {{ margin-top:1.2rem; color:#8b949e; font-size:.85rem; }}
</style></head><body>
<h1>Studio Identity Gateway - active persona: <span id="cur">{persona}</span></h1>
<div class="sub">Every request the studio makes to the neuro-san server is stamped with
this identity. Switch, then refresh the studio tab.</div>
<div id="btns">{buttons}</div>
<div class="note">Studio: <a style="color:#58a6ff" href="http://127.0.0.1:4173">http://127.0.0.1:4173</a>
&nbsp;|&nbsp; personas: sam (super admin) &middot; ada (alpha admin) &middot; alice (alpha member)
&middot; bob (beta member) &middot; eve (no grants)</div>
<script>
 async function setP(p) {{ await fetch('/__persona/set?u=' + p); location.reload(); }}
</script></body></html>
"""


class Handler(BaseHTTPRequestHandler):

    # ---- persona control -------------------------------------------------
    def persona_page(self):
        with _lock:
            current = _state["persona"]
        buttons = "".join(
            f'<button class="{"active" if p == current else ""}" onclick="setP(\'{p}\')">{p}</button>'
            for p in PERSONAS)
        body = PERSONA_PAGE.format(persona=current, buttons=buttons).encode("utf-8")
        self.send_response(200)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def persona_set(self):
        persona = self.path.split("u=")[-1]
        if persona in PERSONAS:
            with _lock:
                _state["persona"] = persona
            print(f"*** active persona -> {persona}")
            self.send_response(200)
        else:
            self.send_response(400)
        # CORS so the in-studio widget (served from the nsflow origin) can call us.
        self.send_header("Access-Control-Allow-Origin", "*")
        self.send_header("Content-Length", "0")
        self.end_headers()

    def persona_state(self):
        with _lock:
            body = ('{"persona": "%s"}' % _state["persona"]).encode("utf-8")
        self.send_response(200)
        self.send_header("Access-Control-Allow-Origin", "*")
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    # ---- proxying ---------------------------------------------------------
    def forward(self):
        if self.path.startswith("/__persona/state"):
            self.persona_state()
            return
        if self.path.startswith("/__persona/set"):
            self.persona_set()
            return
        if self.path.startswith("/__persona"):
            self.persona_page()
            return

        length = int(self.headers.get("Content-Length") or 0)
        body = self.rfile.read(length) if length else None

        request = urllib.request.Request(TARGET + self.path, data=body, method=self.command)
        for name, value in self.headers.items():
            if name.lower() not in HOP_HEADERS and name.lower() != "user_id":
                request.add_header(name, value)
        with _lock:
            persona = _state["persona"]
        # An SSO layer's job in a real deployment: strip self-asserted identity, set verified one.
        request.add_header("user_id", persona)

        try:
            upstream = urllib.request.urlopen(request, timeout=600)
        except urllib.error.HTTPError as err:
            upstream = err
        try:
            self.send_response(upstream.status if hasattr(upstream, "status") else upstream.code)
            for name, value in upstream.headers.items():
                if name.lower() not in HOP_HEADERS:
                    self.send_header(name, value)
            self.end_headers()
            # Stream so incremental chat responses reach the studio as they arrive.
            while True:
                chunk = upstream.read(8192)
                if not chunk:
                    break
                self.wfile.write(chunk)
                self.wfile.flush()
        finally:
            upstream.close()

    # Same handling for every method the studio uses.
    do_GET = do_POST = do_PUT = do_DELETE = do_PATCH = do_OPTIONS = forward

    def log_message(self, fmt, *args):
        with _lock:
            persona = _state["persona"]
        print(f"{persona:>8}  {fmt % args}")


if __name__ == "__main__":
    print(f"Studio identity gateway on http://127.0.0.1:{PORT}  ->  {TARGET}")
    print(f"Persona switcher:          http://127.0.0.1:{PORT}/__persona")
    ThreadingHTTPServer(("127.0.0.1", PORT), Handler).serve_forever()
