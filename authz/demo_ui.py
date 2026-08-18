"""
Persona console for Enterprise Vibe FGA.

A zero-dependency local front end to test authorization by hand. Serves a
single page at http://127.0.0.1:8200 and proxies /api/* to the neuro-san
server, forwarding the user_id header the page sets. The proxy plays the role
an SSO layer plays in a real deployment: it is the only thing that sets the
identity header the runtime trusts.

Usage:
    powershell -File authz\\run_e2e.ps1 -KeepUp     # stack stays running
    .venv\\Scripts\\python.exe authz\\demo_ui.py     # then open http://127.0.0.1:8200
"""

import os
import urllib.error
import urllib.request
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

TARGET = os.environ.get("E2E_BASE", "http://127.0.0.1:8123")
PORT = int(os.environ.get("DEMO_UI_PORT", "8200"))

PAGE = """<!doctype html>
<html>
<head>
<meta charset="utf-8">
<title>Enterprise Vibe FGA - Persona Console</title>
<style>
  :root { color-scheme: dark; }
  body { font-family: 'Segoe UI', system-ui, sans-serif; background:#0d1117; color:#e6edf3;
         margin:0; padding:2rem; }
  h1 { font-size:1.3rem; margin:0 0 .3rem; }
  .sub { color:#8b949e; margin-bottom:1.5rem; font-size:.9rem; }
  .personas { display:flex; gap:.5rem; flex-wrap:wrap; margin-bottom:1.5rem; }
  .personas button { background:#161b22; color:#e6edf3; border:1px solid #30363d;
         border-radius:999px; padding:.45rem 1rem; cursor:pointer; font-size:.9rem; }
  .personas button.active { background:#1f6feb; border-color:#1f6feb; }
  .personas button small { display:block; color:#8b949e; font-size:.7rem; }
  .personas button.active small { color:#c9d1d9; }
  .grid { display:grid; grid-template-columns:repeat(auto-fit,minmax(240px,1fr)); gap:1rem; }
  .card { background:#161b22; border:1px solid #30363d; border-radius:10px; padding:1rem; }
  .card h3 { margin:0 0 .4rem; font-size:1rem; font-family:Consolas,monospace; }
  .badge { display:inline-block; border-radius:6px; padding:.15rem .55rem; font-size:.8rem;
         font-weight:600; }
  .ok   { background:#1a7f37; color:#fff; }
  .deny { background:#b62324; color:#fff; }
  .hidden-note { color:#8b949e; font-size:.8rem; margin-top:.4rem; }
  .meta { color:#8b949e; font-size:.78rem; margin-top:.5rem; }
  pre { background:#161b22; border:1px solid #30363d; border-radius:10px; padding:1rem;
        overflow-x:auto; font-size:.78rem; color:#9ecbff; margin-top:1.5rem; }
</style>
</head>
<body>
<h1>Enterprise Vibe FGA - Persona Console</h1>
<div class="sub">Pick a persona. The console calls the live neuro-san server with that
identity; what you see is exactly what the OpenFGA model allows. Networks:
<b>alpha--private</b> (tenant alpha only), <b>alpha--public</b> (published platform-wide),
<b>beta--internal</b> (tenant beta only).</div>

<div class="personas" id="personas"></div>
<div class="grid" id="grid"></div>
<pre id="raw"></pre>

<script>
const PERSONAS = [
  ["sam",   "platform super admin"],
  ["ada",   "tenant alpha admin"],
  ["alice", "alpha member, builder"],
  ["bob",   "beta member"],
  ["eve",   "stranger, zero grants"],
  [null,    "anonymous (no header)"],
];
const NETWORKS = ["alpha--private", "alpha--public", "beta--internal"];
let current = "alice";

function headers(p) { return p ? {"user_id": p} : {}; }

async function refresh() {
  const listResp = await fetch("/api/v1/list", {headers: headers(current)});
  const listJson = await listResp.json();
  const visible = new Set((listJson.agents || []).map(a => a.agent_name));

  const grid = document.getElementById("grid");
  grid.innerHTML = "";
  for (const net of NETWORKS) {
    const probe = await fetch(`/api/v1/${net}/connectivity`, {headers: headers(current)});
    const allowed = probe.status === 200;
    const card = document.createElement("div");
    card.className = "card";
    card.innerHTML = `<h3>${net}</h3>
      <span class="badge ${allowed ? "ok" : "deny"}">${allowed ? "200 ALLOWED" : probe.status + " DENIED"}</span>
      <div class="hidden-note">${visible.has(net) ? "listed in concierge" : "not listed (invisible to this persona)"}</div>`;
    grid.appendChild(card);
  }
  document.getElementById("raw").textContent =
    `GET /api/v1/list  as  ${current === null ? "(anonymous)" : "user:" + current}\n\n`
    + JSON.stringify(listJson, null, 2);
}

function renderPersonas() {
  const bar = document.getElementById("personas");
  bar.innerHTML = "";
  for (const [p, desc] of PERSONAS) {
    const b = document.createElement("button");
    b.className = (p === current) ? "active" : "";
    b.innerHTML = `${p === null ? "anonymous" : p}<small>${desc}</small>`;
    b.onclick = () => { current = p; renderPersonas(); refresh(); };
    bar.appendChild(b);
  }
}
renderPersonas();
refresh();
</script>
</body>
</html>
"""


class Handler(BaseHTTPRequestHandler):

    def do_GET(self):
        if self.path.startswith("/api/"):
            self.proxy()
            return
        body = PAGE.encode("utf-8")
        self.send_response(200)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def proxy(self):
        request = urllib.request.Request(TARGET + self.path)
        user_id = self.headers.get("user_id")
        if user_id:
            # The one job an SSO layer does in a real deployment, played here by us.
            request.add_header("user_id", user_id)
        try:
            with urllib.request.urlopen(request, timeout=30) as upstream:
                status, body = upstream.status, upstream.read()
                content_type = upstream.headers.get("Content-Type", "application/json")
        except urllib.error.HTTPError as err:
            status, body = err.code, err.read()
            content_type = err.headers.get("Content-Type", "application/json")
        self.send_response(status)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, fmt, *args):
        print(f"{self.headers.get('user_id', '(anonymous)'):>12}  {fmt % args}")


if __name__ == "__main__":
    print(f"Persona console on http://127.0.0.1:{PORT}  ->  {TARGET}")
    ThreadingHTTPServer(("127.0.0.1", PORT), Handler).serve_forever()
