# Role delivery: Option B, persisted, and the hybrid

This document explains **where role tuples come from** at check time, why the
recommended shape is a **hybrid**, how it handles the multi-team case, and how it
scales. It complements the model docs in the main README (the model itself is the
same in every mode described here).

## The one idea to hold onto

**The model is identical in every mode.** "Developer in team A, analyst in team B",
per-tenant isolation, the four-role ladder - these are properties of the *model*,
not of how roles are delivered. Choosing a delivery mode never changes what is
expressible; it changes only **where the role tuples live when a check runs**.

There are three delivery modes, and they compose:

| Mode | Where role tuples come from | What is persisted | Best for |
|---|---|---|---|
| **Option B (contextual)** | The caller's IdP groups, mapped per request | Only the structural graph (tenants, resources) | Routine team x role; scales with zero per-user maintenance |
| **Persisted** | Stored role tuples, materialized from groups by a sync | Structural graph + role tuples | High group-count-per-user (avoids header bloat); offline reasoning |
| **Direct (exception)** | Written by hand through the admin API | The individual grant | Contractors, break-glass, one-offs groups can't express |

Production is a **hybrid**: Option B for the routine bulk, direct grants for the
exceptions, optionally materialized to persisted when scale demands it.

## Option B in one picture

The proxy forwards identity **and** the caller's groups in one header:

```
user_id = "<oid>|NSAN-ALPHA-DEVELOPERS,NSAN-BETA-ANALYSTS"
```

`ContextualOpenFgaAuthorizer` splits it, the group mapper turns each group name
into a `(tenant, role)` pair, and the context builder rides them on the check as
**contextual tuples**:

```
user:<oid>  developer  tenant:alpha
user:<oid>  analyst    tenant:beta
```

Nothing about the user is stored. The multi-team case is *native*: the header
carries every group, so the same person gets developer verbs in `alpha` and
analyst verbs in `beta`, resolved per request. Onboarding a person is a single
Entra group-membership change - no tuples, no app-side work, at any scale.

The naming convention **is** the mapping (configurable via `OPENFGA_GROUP_PATTERN`
/ `OPENFGA_SUPERADMIN_GROUPS`):

```
NSAN-<TEAM>-ADMINS       -> (team, admin)
NSAN-<TEAM>-DEVELOPERS   -> (team, developer)
NSAN-<TEAM>-ANALYSTS     -> (team, analyst)
NSAN-SUPERADMINS         -> platform super_admin (spans all tenants)
```

## The two lanes (the hybrid)

OpenFGA **unions contextual tuples (from groups) with persisted tuples (from the
app)** at check time, so the two lanes coexist on one model:

| Grant | Lane | Managed in | Mechanism |
|---|---|---|---|
| Routine team x role (incl. multi-team) | **Group** | The IdP | Group membership -> contextual tuple (Option B) |
| Contractor / break-glass / one-off | **Direct** | The app | `POST /tenants/{t}/direct-grants` -> persisted tuple (FGA-checked + audited) |
| One user on one specific resource | **Per-object** (future) | The app | A directly-assignable relation on the resource (reserved hook in `resources.fga`) |

**Why routine assignment should stay in the IdP:** one source of truth, no shadow
access, free joiner/mover/leaver, and it is governed where the enterprise already
governs identity (access reviews, PIM, entitlement management). Building app-level
*role assignment* creates a second source of truth to reconcile and audit - avoid
it. App-level control is for the **exceptions** groups can't express, layered on
top of the group-derived roles.

## How it scales, and the one honest limit

Operationally Option B scales well: membership lives in the IdP; the store holds
only structural tuples. The single ceiling is **header/token size** - a user in
*dozens* of teams means dozens of groups in the header (the group-overage /
HTTP-431 limit; see the governance section of the main README). Mitigations, in
order of preference:

1. **App roles** - assign groups to app roles and emit a compact, tenant-stable
   `roles` claim instead of raw group lists.
2. **Materialize to persisted** - a SCIM/Graph sync writes the `user:<oid>` role
   tuples from the same groups (reference: `authz/scim_sync.py`, with reconcile).
   The header then carries **only the oid**. Same model, same relations, same
   multi-team behavior - a migration, not a redesign.

## Identity: always the immutable `oid`

Use the Azure AD **object id (`oid`)**, never username or email, in the header
*and* in every persisted `user:<id>` tuple. Emails/UPNs change and can be
reassigned to a different person, which would orphan or mis-route grants. For
human-readable views, keep an `oid -> display name` lookup **outside** OpenFGA
(the admin/inspector UI resolves it); authorize on the oid, show the name.

## Adopting Option B: what changes

Almost all of it is configuration and a re-seed - the code already supports both
modes.

**Deployment / env**
1. `AGENT_AUTHORIZER = authz.enforcement.contextual_authorizer.ContextualOpenFgaAuthorizer`
   (and `PYTHONPATH` includes `authz/`).
2. Proxy sends `user_id = "<oid>|<group names>"` (was `<oid>` alone in persisted
   mode). Entra must emit group **names**, not GUIDs.
3. `OPENFGA_GROUP_PATTERN` / `OPENFGA_SUPERADMIN_GROUPS` matched to your group
   naming (or rename the groups to the convention).
4. `AGENT_AUTHORIZER_ALLOW_RELATION` matches the profile (`can_invoke` full /
   `can_execute` studio); `OPENFGA_PLATFORM_ID` identical everywhere.

**Data**
5. Seed the store **structural-only** (tenants -> platform, resources -> tenants).
   Do **not** persist role tuples in Option B - they arrive contextually. The only
   persisted role-ish tuples are direct-grant exceptions.

**Decisions to settle first**
- **Group naming -> (tenant, role).** The most important decision; the whole
  mapping depends on it. Nail the convention, then set the pattern.
- **Four roles vs five.** The ladder is exactly four; a plain `member`/"user" tier
  grants *no* resource access. A genuine fifth role is a model change.
- **Built-in agents' type.** If the runtime *runs* the built-in designer/editor
  agents, they are `agent_network` objects (invoke verb) with a tenant parent; if
  they are governed via the library's `can_access`, they are `special_agent`.
- **Per-object exceptions.** Add the reserved directly-assignable relation on the
  resource (see `resources.fga`) only when the first "groups can't express this"
  case appears.

## What does not change

The model modules, the four-role semantics, `resource_map`, the contextual
authorizer, the group mapper, the inspector, and tenant isolation. Switching modes
moves *where role tuples come from*; it never re-architects the policy.

## A note on the inspector in Option B

The inspector's allow/deny verdict and effective-verb views are exact in Option B
(the caller's/subject's contextual roles are passed through). Its `who_can` and
grant-tree show **persisted** holders only, so in pure Option B they will not list
group-derived users. To answer "who can run X" globally, resolve group membership
from the IdP, or run the inspector against a SCIM-materialized store.
