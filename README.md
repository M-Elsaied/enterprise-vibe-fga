# Enterprise Vibe FGA

Fine-grained, multi-tenant authorization for vibe-to-production agent platforms.

This repo takes the [neuro-san](https://github.com/cognizant-ai-lab/neuro-san) agent runtime
(via a snapshot of [neuro-san-studio](https://github.com/cognizant-ai-lab/neuro-san-studio))
and adds an enterprise authorization layer on [OpenFGA](https://openfga.dev), the
Zanzibar-descended relationship-based access control engine. The result: teams operate as
isolated tenants on one shared cluster, publish agent networks and connectors to a
marketplace with a single tuple write, and LLM usage and bring-your-own-model rights are
governed as super-admin-controlled entitlements.

Everything here is verified end to end: model-layer tests run against the FGA CLI's built-in
engine, and a live E2E suite runs a real OpenFGA server plus a real neuro-san server and
asserts allow/deny per persona over HTTP.

## What the model gives you

| Requirement | How |
|---|---|
| Teams segregated as tenants | `type tenant`; isolation is structural - no tuple path, no access |
| Platform super users | `platform.super_admin` (one Entra group), transitive over everything |
| Every tenant has an admin | `tenant.admin`, required at onboarding |
| Marketplace publish | `published_to: [user:*, tenant#member]` - one tuple publishes platform-wide or to one tenant |
| Common LLM by default | `user:* available_to llm_model:centralized-default` |
| Per-tenant LLM approval | super admin writes `tenant:X#member available_to llm_model:Y` |
| BYOM with own API key | `feature:byom` entitlement; the key itself lives in the secret store |
| Time-boxed access | `time_boxed` CEL condition (used on connector grants) |

Model sources: `authz/model/` (modular OpenFGA files under `fga.mod`).

## Quick start (Windows)

```powershell
# 1. toolchain (one time)
py -3.12 -m venv .venv
.venv\Scripts\python.exe -m pip install -r authz\requirements-authz.txt
# download openfga.exe and fga.exe into tools\ (see authz\README.md)

# 2. the whole thing: model tests -> OpenFGA -> seed -> neuro-san -> E2E pytest
powershell -ExecutionPolicy Bypass -File authz\run_e2e.ps1
```

Expected output: `Tests 4/4 passing`, then `18 passed`, then `ALL GREEN`.

### Test it yourself from a front end

```powershell
powershell -ExecutionPolicy Bypass -File authz\run_e2e.ps1 -KeepUp   # stack stays running
.venv\Scripts\python.exe authz\demo_ui.py                            # persona console
# open http://127.0.0.1:8200
```

The persona console lets you switch between sam / ada / alice / bob / eve / anonymous and
watch the concierge list and per-network 200/403 change live. Its tiny proxy injects the
`user_id` header exactly the way the SSO reverse proxy does in production - the browser
never talks to the runtime directly with a self-asserted identity.

### See enforcement in the real studio (nsflow)

```powershell
.venv\Scripts\python.exe -m pip install nsflow==0.6.19                # one time
.venv\Scripts\python.exe authz\studio_gateway.py                      # identity gateway on :8210
$env:NEURO_SAN_SERVER_HOST="127.0.0.1"; $env:NEURO_SAN_SERVER_HTTP_PORT="8210"
.venv\Scripts\python.exe -m nsflow.run --client-only                  # studio on :4173
```

Then put the persona switcher INSIDE the studio (one-time, idempotent; re-run after any
nsflow reinstall; `--remove` to undo):

```powershell
.venv\Scripts\python.exe authz\install_studio_widget.py
```

Open the studio at http://127.0.0.1:4173. A floating "FGA persona" pill bar sits in the
bottom-right corner: click sam / ada / alice / bob / eve and the studio reloads as that
persona - the Available Agents sidebar changes (alice sees `alpha--private` +
`alpha--public`, bob sees `beta--internal` + `alpha--public`, sam sees everything), and
chat and connectivity are authorized the same way. The standalone switcher page also
remains at http://127.0.0.1:8210/__persona.

Why the gateway is required: nsflow 0.6.19 sends no `user_id` on its concierge call and
hardcodes chat identity to the backend's `USER` env var, so identity must be asserted at
the hop the runtime trusts - the same place the SSO reverse proxy asserts it in production
(`browser -> nsflow -> gateway -> neuro-san -> OpenFGA`).

## How enforcement works

The neuro-san runtime checks exactly one relation on one type for every HTTP/MCP request:
`can_invoke` on `agent_network:<served-name>` (wired through env vars, no fork). Everything
else - create, publish, LLM approval, BYOM - is checked and written by the platform's own
services against the same store, so one model answers every "who can do what" question.

| Operation | Enforcement point | FGA interaction |
|---|---|---|
| Invoke / chat / connectivity / MCP | neuro-san runtime (built in) | Check `can_invoke` |
| List networks (concierge, marketplace) | neuro-san runtime (built in) | ListObjects `can_invoke` |
| Create network in a tenant | publish service | Check `can_create_network`, write `tenant` + `builder` |
| Publish / unpublish | publish service | Check `can_publish`, write/delete `published_to` |
| Approve an LLM for a tenant | admin API | Check `can_approve`, write `available_to` |
| Register a BYOM key | key-registration API | Check `can_use` on `feature:byom` |

Runtime wiring (see `authz/run_e2e.ps1` for the working set):

```
AGENT_AUTHORIZER=neuro_san.internals.authorization.openfga.open_fga_authorizer.OpenFgaAuthorizer
AGENT_AUTHORIZER_ACTOR_KEY=user
AGENT_AUTHORIZER_RESOURCE_KEY=agent_network
AGENT_AUTHORIZER_ALLOW_RELATION=can_invoke
AGENT_AUTHORIZER_ACTOR_ID_METADATA_KEY=user_id
FGA_API_URL=...   FGA_STORE_NAME=...   FGA_MODEL_ID=<pinned>   FGA_POLICY_FILE=authz/model/model.json
```

## Hard-won gotchas (each one is asserted by a test)

1. **Pin `FGA_MODEL_ID`.** Without it the runtime writes a new model on every store bootstrap.
2. **The `agent_network` object id must equal the hocon filename stem.** Use
   `<tenant-slug>--<network-slug>` names (see `registries/vibe/`).
3. **Conditions do not evaluate on runtime checks.** The stock authorizer sends no query
   context, so keep conditioned tuples off `can_invoke`; they are safe on relations checked
   by platform services that pass `current_time`.
4. **Grant `user:system`** for networks the periodic event watcher must reach.
5. **A missing `user_id` header authorizes as the literal string `"None"`** - it can still
   invoke `user:*`-published networks. Authentication in front of the runtime is mandatory;
   the SSO proxy must strip and re-set the header from the verified token.
6. **Authorization runs before existence**: probing an unknown network returns 403, not 404.
7. **Catalog objects need their platform link tuple** (`platform:vibe platform llm_model:X`)
   or super-admin inheritance silently fails. Found by the model test suite.

## Repo layout

```
authz/model/          fga.mod + core / agents / connectors / entitlements modules
authz/tests/          tenancy.fga.yaml - model tests (fga model test, runs in CI, no server)
authz/seed/           tuples.yaml - demo personas and grants
authz/run_e2e.ps1     one-command end-to-end run
registries/vibe/      three demo tenant networks (alpha--private, alpha--public, beta--internal)
tests/e2e_authz/      pytest suite against the live stack (18 assertions)
docs/UPSTREAM-README.md   the original neuro-san-studio README
```

Demo personas: `sam` (platform super admin), `ada` (tenant alpha admin), `alice` (alpha
member, builder), `bob` (beta member), `eve` (authenticated stranger with zero grants).

## Provenance and license

Built on a snapshot of neuro-san-studio (Apache License 2.0, see `LICENSE.txt`); the studio's
own examples, tools, and docs are retained unmodified. The authorization layer, tenancy
model, demo registries, and E2E harness are this repo's addition.
