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

from enforcement import (  # noqa: E402
    AuthorizationInspector, GroupMapper, InspectorForbidden, StudioAuthzClient,
    assert_openfga_reachable)
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
                   for t in ("alpha", "beta", "gamma", "delta")},
    }


@app.get("/api/inspect")
def inspect(request: Request, subject: str = "", subject_groups: str = "",
            tenant: str = "", resource: str = "", action: str = "execute"):
    """Read-only inspector, driven by the REAL AuthorizationInspector.

    The CALLER is the active persona (its X-Dev-* headers set identity via the
    middleware), so the panel demonstrates the gating live: an analyst/developer/
    stranger caller is refused; an admin can only inspect their own tenant.
    The SUBJECT (whose access is being examined) is chosen separately; its groups
    are mapped to contextual roles so the verdict is exact in Option B.
    """
    identity = request.state.identity
    if not identity.is_authenticated:
        return {"gated": False,
                "reason": "caller is anonymous (no dev identity / SSO) - inspector refused"}
    caller = identity.user_id
    caller_roles = identity.roles
    sub_roles = None
    if subject_groups:
        sub_roles = GroupMapper().map_groups(
            [g.strip() for g in subject_groups.split(",") if g.strip()])
    insp = AuthorizationInspector(client())
    try:
        access = insp.resource_access(caller, subject, resource, tenant,
                                      caller_roles=caller_roles, subject_roles=sub_roles)
        explain = insp.explain(caller, subject, action, resource, tenant,
                               caller_roles=caller_roles, subject_roles=sub_roles)
        who = insp.who_can(caller, "read", resource, tenant, caller_roles=caller_roles)
    except InspectorForbidden as err:
        return {"gated": False, "caller": caller, "reason": str(err)}
    return {
        "gated": True, "caller": caller, "subject": subject, "tenant": tenant,
        "resource": access["resource"],
        "subject_roles": sorted(f"{t}:{r}" for t, r in (sub_roles.memberships if sub_roles else []))
                         + (["platform:super_admin"] if sub_roles and sub_roles.super_admin else []),
        "access": access["access"],
        "explain": {"action": action, "relation": explain["relation"],
                    "allowed": explain["allowed"], "tree": explain["tree"]},
        "who": who["who"],
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
 .panel { background:#0f151d; border:1px solid #30363d; border-radius:12px; padding:1.1rem 1.2rem; margin-top:1.6rem; }
 .panel h2 { font-size:1rem; margin:0 0 .2rem; } .panel .sub { margin-bottom:.9rem; }
 .controls { display:flex; flex-wrap:wrap; gap:.6rem; align-items:center; }
 .controls label { font-size:.72rem; color:#8b949e; display:flex; flex-direction:column; gap:.2rem; }
 .controls select { background:#161b22; color:#e6edf3; border:1px solid #30363d; border-radius:8px; padding:.4rem .5rem; }
 .controls button { background:#1f6feb; color:#fff; border:0; border-radius:8px; padding:.55rem 1.1rem;
   cursor:pointer; align-self:flex-end; font-weight:600; }
 .banner { border-radius:8px; padding:.6rem .8rem; margin:1rem 0 .4rem; font-size:.85rem; }
 .banner.allow { background:#0d2a14; border:1px solid #1a7f37; color:#7ee787; }
 .banner.deny  { background:#2d0f13; border:1px solid #f85149; color:#ff9a91; }
 .verbs { margin:.5rem 0; } .verbs .lbl { color:#8b949e; font-size:.75rem; margin-right:.4rem; }
 .tree { background:#0b0f14; border:1px solid #30363d; border-radius:8px; padding:.7rem; font-size:.72rem;
   color:#9ecbff; overflow-x:auto; max-height:220px; margin-top:.4rem; }
 .note { color:#8b949e; font-size:.72rem; margin-top:.3rem; }
</style></head><body>
<h1>Studio RBAC Persona Console</h1>
<div class="sub">Four-role ladder, multi-tenant, Option B: every click sends the persona's
IdP groups; the backend maps them to roles and injects contextual tuples per request.
The <b>prod mode</b> persona proves the dev flag is the only door.</div>
<div class="personas" id="bar"></div>
<div class="roles" id="roles"></div>
<div class="grid" id="grid"></div>

<div class="panel">
  <h2>Authorization inspector <span style="color:#8b949e;font-weight:400">(read-only)</span></h2>
  <div class="sub">Answers "can <b>subject</b> do X on this resource, and why" - the effective
  permission after the ladder resolves. The <b>caller is the active persona above</b>, so the
  inspector is itself gated: only an <b>admin/super_admin of the owning tenant</b> may inspect it.
  Switch the top persona to an analyst or another tenant's admin and watch it refuse. This is
  NOT role assignment (that lives in the IdP).</div>
  <div class="controls">
    <label>Subject<select id="i-subject"></select></label>
    <label>Resource<select id="i-target"></select></label>
    <label>Action<select id="i-action">
      <option>execute</option><option>read</option><option>update</option><option>delete</option>
    </select></label>
    <button onclick="inspect()">Inspect</button>
  </div>
  <div id="i-out"></div>
</div>

<pre id="raw"></pre>
<script>
const PERSONAS = [
 ["adam", "Alpha Admin",      "NSAN-ALPHA-ADMINS"],
 ["dina", "Alpha Developer",  "NSAN-ALPHA-DEVELOPERS"],
 ["ana",  "Alpha Analyst",    "NSAN-ALPHA-ANALYSTS"],
 ["bob",  "Beta Developer",   "NSAN-BETA-DEVELOPERS"],
 ["gil",  "Gamma Developer",  "NSAN-GAMMA-DEVELOPERS"],
 ["dora", "Delta Admin",      "NSAN-DELTA-ADMINS"],
 ["mia",  "Multi-team",       "NSAN-ALPHA-DEVELOPERS,NSAN-BETA-ANALYSTS"],
 ["sam",  "Super Admin",      "NSAN-SUPERADMINS"],
 ["eve",  "Stranger",         ""],
 [null,   "prod mode",        ""],
];
let current = "dina";
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
// ---- inspector panel -------------------------------------------------------
const TARGETS = [
 ["alpha--private", "alpha"],
 ["alpha--public",  "alpha"],
 ["beta--internal", "beta"],
 ["gamma--research", "gamma"],
 ["delta--onboarding", "delta"],
];
function callerHeaders() {
  const p = PERSONAS.find(x => x[0] === current);
  const h = {};
  if (p && p[0] !== null) { h["X-Dev-User"] = p[0]; h["X-Dev-Groups"] = p[2]; }
  return h;
}
function populateInspector() {
  const subj = document.getElementById("i-subject");
  subj.innerHTML = "";
  for (const [id, label, groups] of PERSONAS) {
    if (id === null) continue;                    // 'prod mode' is a caller state, not a subject
    const o = document.createElement("option");
    o.value = id; o.dataset.groups = groups || ""; o.textContent = `${id} - ${label}`;
    subj.appendChild(o);
  }
  const tgt = document.getElementById("i-target");
  tgt.innerHTML = "";
  for (const [res, tenant] of TARGETS) {
    const o = document.createElement("option");
    o.value = res; o.dataset.tenant = tenant; o.textContent = `${res}  (tenant:${tenant})`;
    tgt.appendChild(o);
  }
}
async function inspect() {
  const subjEl = document.getElementById("i-subject");
  const tgtEl = document.getElementById("i-target");
  const subject = subjEl.value;
  const subject_groups = subjEl.selectedOptions[0].dataset.groups;
  const resource = tgtEl.value;
  const tenant = tgtEl.selectedOptions[0].dataset.tenant;
  const action = document.getElementById("i-action").value;
  const qs = new URLSearchParams({subject, subject_groups, tenant, resource, action});
  const data = await (await fetch("/api/inspect?" + qs, {headers: callerHeaders()})).json();
  const out = document.getElementById("i-out");
  const callerName = current === null ? "prod mode (no identity)" : current;
  if (!data.gated) {
    out.innerHTML = `<div class="banner deny"><b>Inspector refused for caller ${callerName}.</b>
      ${data.reason || ""}</div>
      <div class="note">The inspector requires admin or super_admin on the owning tenant -
      exactly the guard that stops a developer/analyst/stranger, or a cross-tenant peek.</div>`;
    return;
  }
  const verbs = Object.entries(data.access)
    .map(([k, v]) => `<span class="chip ${v ? "ok" : "no"}">${k}</span>`).join("");
  const ex = data.explain;
  out.innerHTML = `
    <div class="banner ${ex.allowed ? "allow" : "deny"}">
      caller <b>${callerName}</b> - subject <b>${data.subject}</b> may ${ex.allowed ? "" : "NOT "}
      <b>${ex.action}</b> ${data.resource} <span style="opacity:.7">(relation ${ex.relation})</span>
    </div>
    <div class="note">subject roles: ${data.subject_roles.join("  ") || "(none)"}</div>
    <div class="verbs"><span class="lbl">effective verb set:</span>${verbs}</div>
    <div class="lbl" style="color:#8b949e;font-size:.75rem;margin-top:.6rem">grant tree (the "why", persisted graph):</div>
    <pre class="tree">${JSON.stringify(ex.tree, null, 2)}</pre>
    <div class="lbl" style="color:#8b949e;font-size:.75rem">who can read ${data.resource}: ${data.who.join(", ") || "(none)"}</div>
    <div class="note">who-can lists persisted holders only - empty here because Option B
    persists no roles (they arrive per request); it is populated in persisted mode.</div>`;
}

render(); refresh(); populateInspector();
</script></body></html>
"""


@app.get("/", response_class=HTMLResponse)
def page() -> str:
    return PAGE


if __name__ == "__main__":
    assert_openfga_reachable(FGA)   # friendly hint before startup, not a traceback
    uvicorn.run(app, host="127.0.0.1", port=PORT, log_level="warning")
