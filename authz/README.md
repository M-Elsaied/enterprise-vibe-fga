# The authorization layer

This directory holds the OpenFGA model (modular, two manifests - see the root README's
"Profiles" section), its tests, the demo seed state, the E2E runner, and the
`enforcement/` library for the studio profile (Entra-style header identity -> group
naming convention -> per-request contextual tuples -> Check/ListObjects; provisioning
routed through the same `resource_map` as checking, so an object can never be written
under one type and checked under another).

Model commands (the `--format modular` flag matters - manifest names must end in
`fga.mod` and module paths may not use `..`):

```powershell
cd authz\model
..\..\tools\fga.exe model validate --file core.fga.mod --format modular
..\..\tools\fga.exe model validate --file full.fga.mod --format modular
cd ..\tests
..\..\tools\fga.exe model test --tests studio-persisted.fga.yaml
..\..\tools\fga.exe model test --tests studio-contextual.fga.yaml   # Option B: per-test
                                    # tuples are sent as CONTEXTUAL tuples by the CLI
..\..\tools\fga.exe model test --tests tenancy.fga.yaml
```

## Getting the binaries (one time)

```powershell
New-Item -ItemType Directory -Force tools | Out-Null
Invoke-WebRequest "https://github.com/openfga/openfga/releases/download/v1.18.3/openfga_1.18.3_windows_amd64.tar.gz" -OutFile tools\openfga.tar.gz
Invoke-WebRequest "https://github.com/openfga/cli/releases/download/v0.7.20/fga_0.7.20_windows_amd64.tar.gz" -OutFile tools\fga.tar.gz
tar -xzf tools\openfga.tar.gz -C tools openfga.exe
tar -xzf tools\fga.tar.gz -C tools fga.exe
```

`tools/` is gitignored; any recent version works (OpenFGA >= 1.6 for default-on modular
models and consistency parameters).

## The four test layers

1. **Model tests** (`tests/tenancy.fga.yaml`): `fga model test` against the CLI's built-in
   engine. Runs in CI with no server. Asserts grants AND denials: tenant isolation,
   marketplace publish (org-wide and targeted), super-admin transitivity, time-boxed
   connector access (condition context both sides of expiry), LLM and BYOM entitlements,
   and ListObjects visibility per user.
2. **Live-store sanity**: the seed steps in `run_e2e.ps1` (store create, `fga model write`
   from `fga.mod`, tuple writes) fail loudly if the model and tuples disagree.
3. **Runtime E2E** (`../tests/e2e_authz/`): pytest against a real neuro-san server wired to
   a real OpenFGA. Asserts the concierge list is filtered per persona and per-network
   requests return 200/403 exactly as the model says, including the anonymous and
   unknown-network edge cases.
4. **Production assurance** (not in this repo): shadow-check on model changes, nightly
   IdP-vs-tuple reconcile, a zero-grant tripwire identity probed on a schedule, and
   quarterly ListUsers/ListObjects recertification sweeps.

## Working on the model

- Edit the module files, then validate and test from this directory's `model/` and `tests/`:
  ```powershell
  cd authz\model;  ..\..\tools\fga.exe model validate --file fga.mod
  cd ..\tests;     ..\..\tools\fga.exe model test --tests tenancy.fga.yaml
  ```
  (the CLI resolves module paths relative to the current directory)
- Every PR that touches `model/` must extend `tenancy.fga.yaml` with the new grant and at
  least one denial that proves the change does not widen access elsewhere.
- `model/model.json` is generated (`fga model get --format json` after a model write) and
  gitignored; the runtime's `FGA_POLICY_FILE` points at it, and `FGA_MODEL_ID` is pinned to
  the written model so the runtime never uploads a model itself.

## Onboarding runbook (what writes which tuples)

The governed writer is `admin_api.py` (port 8300): every endpoint checks the caller
against OpenFGA before writing, enforces the born-with-an-admin and last-admin
invariants, and appends to the JSONL audit trail. The `/idp/*` endpoints simulate the
IdP sync path of the hybrid model. See the root README for the endpoint matrix; the
table below maps events to tuples regardless of which writer performs them.

| Event | Writer | Tuples |
|---|---|---|
| Platform bootstrap | pipeline seed | `group:core#member super_admin platform:<name>` |
| New tenant | admin API / seed | `platform` link, `admin` group binding, `member` group binding |
| Group membership | IdP sync only | `user:<oid> member group:<gid>` |
| Network created | publish service | `tenant` link + `builder` |
| Marketplace publish | publish service | `published_to` (`user:*` or `tenant:X#member`) |
| LLM approved for tenant | admin API (super admin) | `available_to` + the object's `platform` link |
| BYOM enabled | admin API (super admin) | `enabled_for` on `feature:byom` |
| Scheduled networks | seed | `user:system can_invoke agent_network:<name>` |
