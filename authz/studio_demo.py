"""Studio-profile persona console (front-end testing for the 4-role ladder).

A tiny FastAPI app that consumes the REAL enforcement library end to end:
IdentityMiddleware -> GroupMapper -> contextual tuples -> Check/ListObjects.
The page switches personas by sending X-Dev-User / X-Dev-Groups, which the
middleware honors ONLY because this launcher sets OPENFGA_DEV_IDENTITY=enabled.
Unset the flag and every persona collapses to anonymous - that IS the
production posture, and you can demo it live with the "prod mode" persona.

Run (stack first: authz\\run_e2e.ps1 -KeepUp):
    $env:OPENFGA_DEV_IDENTITY="enabled"
    .venv\\Scripts\\python.exe authz\\studio_demo.py     # http://127.0.0.1:8400
"""

import os
import sys

import requests as rq
import uvicorn
from fastapi import FastAPI, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import HTMLResponse

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from enforcement import StudioAuthzClient  # noqa: E402
from enforcement.middleware import IdentityMiddleware  # noqa: E402

FGA = os.environ.get("FGA_API_URL", "http://127.0.0.1:18080")
PORT = int(os.environ.get("STUDIO_DEMO_PORT", "8400"))
STORE_NAME = os.environ.get("STUDIO_STORE_NAME", "studio-e2e")

app = FastAPI(title="Studio RBAC persona console")
app.add_middleware(IdentityMiddleware)
# CORS so the in-studio widget (served from the nsflow origin) can preview
# personas through this console's API. Dev tool only - it runs with the
# dev-identity flag and never in production.
app.add_middleware(CORSMiddleware, allow_origins=["*"],
                   allow_methods=["*"], allow_headers=["*"])
STATE = {"store_id": None, "model_id": None}


@app.on_event("startup")
def resolve_store() -> None:
    stores = rq.get(f"{FGA}/stores", params={"page_size": 50}, timeout=10).json().get("stores", [])
    match = [s for s in stores if s.get("name") == STORE_NAME]
    if not match:
        raise RuntimeError(f"no OpenFGA store named {STORE_NAME} - run authz/run_e2e.ps1 -KeepUp first")
    STATE["store_id"] = match[-1]["id"]
    models = rq.get(f"{FGA}/stores/{STATE['store_id']}/authorization-models",
                    params={"page_size": 1}, timeout=10).json().get("authorization_models", [])
    STATE["model_id"] = models[0]["id"] if models else None
    print(f"studio demo: store={STATE['store_id']} model={STATE['model_id']}")


def client() -> StudioAuthzClient:
    return StudioAuthzClient(api_url=FGA, store_id=STATE["store_id"],
                             model_id=STATE["model_id"])


@app.get("/api/overview")
def overview(request: Request):
    identity = request.state.identity
    if not identity.is_authenticated:
        return {"user": None, "roles": [], "networks": [], "tools": [],
                "special_access": False, "create": {}}
    c = client()
    roles = identity.roles
    networks = []
    for net in c.list_ids(identity.user_id, "read", "agent_network", roles):
        networks.append({
            "id": net,
            "read": True,
            "update": c.check(identity.user_id, "update", net, roles),
            "delete": c.check(identity.user_id, "delete", net, roles),
            "execute": c.check(identity.user_id, "execute", net, roles),
        })
    tools = []
    for tool in c.list_ids(identity.user_id, "read", "tool", roles):
        tools.append({
            "id": tool,
            "read": True,
            "update": c.check(identity.user_id, "update", tool, roles, "tool"),
            "delete": c.check(identity.user_id, "delete", tool, roles, "tool"),
        })
    return {
        "user": identity.user_id,
        "groups": identity.groups,
        "roles": sorted(f"{t}:{r}" for t, r in roles.memberships) +
                 (["platform:super_admin"] if roles.super_admin else []),
        "networks": networks,
        "tools": tools,
        "special_access": c.check(identity.user_id, "access",
                                  "agent_network_designer", roles),
        "create": {t: c.check_create(identity.user_id, t, roles)
                   for t in ("alpha", "beta")},
    }


PAGE = """<!doctype html>
<html><head><meta charset="utf-8"><title>Studio RBAC Persona Console</title>
<style>
 body { font-family:'Segoe UI',system-ui,sans-serif; background:#0d1117; color:#e6edf3; padding:2rem; }
 h1 { font-size:1.25rem; margin:0 0 .25rem; } .sub { color:#8b949e; font-size:.88rem; margin-bottom:1.2rem; }
 .personas button { background:#161b22; color:#e6edf3; border:1px solid #30363d; border-radius:999px;
   padding:.45rem 1rem; margin:.2rem; cursor:pointer; }
 .personas button.active { background:#1f6feb; border-color:#1f6feb; }
 .personas button small { display:block; color:#8b949e; font-size:.68rem; }
 .grid { display:grid; grid-template-columns:repeat(auto-fit,minmax(250px,1fr)); gap:1rem; margin-top:1.2rem; }
 .card { background:#161b22; border:1px solid #30363d; border-radius:10px; padding:1rem; }
 .card h3 { margin:0 0 .5rem; font-family:Consolas,monospace; font-size:.95rem; }
 .chip { display:inline-block; border-radius:6px; padding:.12rem .5rem; font-size:.75rem; margin:.1rem; font-weight:600; }
 .ok { background:#1a7f37; color:#fff; } .no { background:#3d1418; color:#f85149; border:1px solid #f85149; }
 .roles { color:#7ee1f5; font-family:Consolas,monospace; font-size:.85rem; margin:.4rem 0 0; }
 pre { background:#161b22; border:1px solid #30363d; border-radius:10px; padding:1rem; font-size:.75rem;
   color:#9ecbff; overflow-x:auto; margin-top:1.4rem; }
</style></head><body>
<h1>Studio RBAC Persona Console</h1>
<div class="sub">Four-role ladder, multi-tenant, Option B: every click sends the persona's
IdP groups; the backend maps them to roles and injects contextual tuples per request.
The <b>prod mode</b> persona proves the dev flag is the only door.</div>
<div class="personas" id="bar"></div>
<div class="roles" id="roles"></div>
<div class="grid" id="grid"></div>
<pre id="raw"></pre>
<script>
const PERSONAS = [
 ["alpha-admin",  "Alpha Admin",      "NSAN-ALPHA-ADMINS"],
 ["alpha-dev",    "Alpha Developer",  "NSAN-ALPHA-DEVELOPERS"],
 ["alpha-analyst","Alpha Analyst",    "NSAN-ALPHA-ANALYSTS"],
 ["beta-dev",     "Beta Developer",   "NSAN-BETA-DEVELOPERS"],
 ["mia",          "Multi-team",       "NSAN-ALPHA-DEVELOPERS,NSAN-BETA-ANALYSTS"],
 ["sam",          "Super Admin",      "NSAN-SUPERADMINS"],
 ["eve",          "Stranger",         ""],
 [null,           "prod mode",        ""],
];
let current = "alpha-dev";
function chips(o, keys) {
  return keys.map(k => `<span class="chip ${o[k] ? "ok" : "no"}">${k}</span>`).join("");
}
async function refresh() {
  const p = PERSONAS.find(x => x[0] === current);
  const headers = {};
  if (p && p[0] !== null) { headers["X-Dev-User"] = p[0]; headers["X-Dev-Groups"] = p[2]; }
  const data = await (await fetch("/api/overview", {headers})).json();
  document.getElementById("roles").textContent = data.user
    ? `user:${data.user}  ->  roles: ${data.roles.join("  ") || "(none)"}`
    : "anonymous - no identity accepted (this is what production sees without the SSO proxy)";
  const grid = document.getElementById("grid"); grid.innerHTML = "";
  for (const net of data.networks) {
    grid.insertAdjacentHTML("beforeend",
      `<div class="card"><h3>${net.id}</h3>${chips(net, ["read","update","delete","execute"])}</div>`);
  }
  for (const tool of data.tools) {
    grid.insertAdjacentHTML("beforeend",
      `<div class="card"><h3>tool: ${tool.id}</h3>${chips(tool, ["read","update","delete"])}</div>`);
  }
  grid.insertAdjacentHTML("beforeend",
    `<div class="card"><h3>special agents</h3><span class="chip ${data.special_access ? "ok" : "no"}">
     agent_network_designer</span></div>`);
  const create = Object.entries(data.create || {}).map(([t, v]) =>
    `<span class="chip ${v ? "ok" : "no"}">create in ${t}</span>`).join("");
  grid.insertAdjacentHTML("beforeend", `<div class="card"><h3>create resources</h3>${create || "-"}</div>`);
  document.getElementById("raw").textContent = JSON.stringify(data, null, 2);
}
function render() {
  const bar = document.getElementById("bar"); bar.innerHTML = "";
  for (const [id, label, groups] of PERSONAS) {
    const b = document.createElement("button");
    b.className = (id === current) ? "active" : "";
    b.innerHTML = `${label}<small>${groups || (id === null ? "dev headers ignored" : "no groups")}</small>`;
    b.onclick = () => { current = id; render(); refresh(); };
    bar.appendChild(b);
  }
}
render(); refresh();
</script></body></html>
"""


@app.get("/", response_class=HTMLResponse)
def page() -> str:
    return PAGE


if __name__ == "__main__":
    uvicorn.run(app, host="127.0.0.1", port=PORT, log_level="warning")
