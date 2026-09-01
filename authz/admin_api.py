"""
Admin API: onboarding and membership management for the tenancy model.

The write side of the platform, hybrid style:
  - Steady state: membership lives in IdP security groups (Entra, Okta, ...).
    A tenant's admin manages their own group in the IdP; the sync service
    turns group deltas into `group` membership tuples. /idp/* below SIMULATES
    that sync path so the flow is testable without an IdP.
  - Exceptions: direct user tuples written here (contractors, one-offs).

Every endpoint authorizes the CALLER against OpenFGA before writing - the
authorization system authorizes its own administration:

  operation                     caller must pass                    write
  create tenant                 super_admin on platform             platform link + admin/member group bindings
  add/remove member (direct)    can_administer on tenant            user member tuple
  promote/demote admin          can_administer on tenant            user admin tuple (last-admin protected)
  IdP group membership (sync)   admin of a tenant bound to group,   user member group tuple
                                or super_admin
  access review                 can_administer on tenant            (read-only ListUsers sweep)

Identity: the `user_id` header, set by an SSO layer in a real deployment (same
trusted-header contract as the runtime). Every write lands in a JSONL audit
log - the stand-in for a transactional outbox.

Run:  .venv\\Scripts\\python.exe authz\\admin_api.py   (port 8300)
"""

import json
import os
import time
from typing import Any, Dict, List, Optional

import requests as rq
import uvicorn
from fastapi import FastAPI, Header, HTTPException
from pydantic import BaseModel

FGA = os.environ.get("FGA_API_URL", "http://127.0.0.1:18080")
STORE_NAME = os.environ.get("FGA_STORE_NAME", "vibe-e2e")
# Single platform-singleton id, shared with the enforcement library
# (context_builder reads the same var). Both MUST resolve to the same value or
# super-admin tuples land on a different platform object than checks look at.
PLATFORM = os.environ.get("OPENFGA_PLATFORM_ID", "main")
PORT = int(os.environ.get("ADMIN_API_PORT", "8300"))
AUDIT_LOG = os.environ.get(
    "ADMIN_AUDIT_LOG",
    os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
                 ".e2e-logs", "admin-audit.jsonl"))

app = FastAPI(title="Enterprise Vibe FGA - Admin API")
STATE: Dict[str, Optional[str]] = {"store_id": None, "model_id": None}


# ---------------------------------------------------------------- FGA client

def fga_post(path: str, body: Dict[str, Any]) -> Dict[str, Any]:
    response = rq.post(f"{FGA}/stores/{STATE['store_id']}{path}", json=body, timeout=15)
    if response.status_code >= 500:
        raise HTTPException(502, f"OpenFGA error on {path}: {response.text[:200]}")
    return {"status": response.status_code, "body": response.json() if response.text else {}}


def fga_check(user: str, relation: str, obj: str) -> bool:
    result = fga_post("/check", {
        "tuple_key": {"user": user, "relation": relation, "object": obj},
        "authorization_model_id": STATE["model_id"],
    })
    return bool(result["body"].get("allowed"))


def fga_write(user: str, relation: str, obj: str) -> str:
    result = fga_post("/write", {
        "writes": {"tuple_keys": [{"user": user, "relation": relation, "object": obj}]},
        "authorization_model_id": STATE["model_id"],
    })
    if result["status"] == 200:
        return "written"
    if "already existed" in json.dumps(result["body"]):
        return "already-existed"
    raise HTTPException(502, f"tuple write failed: {result['body']}")


def fga_delete(user: str, relation: str, obj: str) -> str:
    result = fga_post("/write", {
        "deletes": {"tuple_keys": [{"user": user, "relation": relation, "object": obj}]},
        "authorization_model_id": STATE["model_id"],
    })
    if result["status"] == 200:
        return "deleted"
    if "did not exist" in json.dumps(result["body"]):
        return "did-not-exist"
    raise HTTPException(502, f"tuple delete failed: {result['body']}")


def fga_list_users(obj_type: str, obj_id: str, relation: str) -> List[str]:
    result = fga_post("/list-users", {
        "object": {"type": obj_type, "id": obj_id},
        "relation": relation,
        "user_filters": [{"type": "user"}],
        "authorization_model_id": STATE["model_id"],
    })
    users = []
    for entry in result["body"].get("users", []):
        if "object" in entry:
            users.append(entry["object"]["id"])
    return sorted(users)


def fga_read(user: str, obj: str) -> List[Dict[str, Any]]:
    result = fga_post("/read", {"tuple_key": {"user": user, "object": obj}})
    return [t["key"] for t in result["body"].get("tuples", [])]


# ------------------------------------------------------------------- helpers

def caller_id(user_id: Optional[str]) -> str:
    if not user_id:
        raise HTTPException(401, "user_id header required (set by an SSO layer in a real deployment)")
    return user_id


def is_super_admin(caller: str) -> bool:
    return fga_check(f"user:{caller}", "super_admin", f"platform:{PLATFORM}")


def require_super_admin(caller: str) -> None:
    if not is_super_admin(caller):
        raise HTTPException(403, f"user:{caller} is not a platform super admin")


def require_tenant_admin(caller: str, tenant: str) -> None:
    if not fga_check(f"user:{caller}", "can_administer", f"tenant:{tenant}"):
        raise HTTPException(403, f"user:{caller} cannot administer tenant:{tenant}")


def audit(actor: str, operation: str, target: str, outcome: str) -> None:
    os.makedirs(os.path.dirname(AUDIT_LOG), exist_ok=True)
    entry = {"ts": time.strftime("%Y-%m-%dT%H:%M:%S%z"), "actor": actor,
             "operation": operation, "target": target, "outcome": outcome}
    with open(AUDIT_LOG, "a", encoding="utf-8") as handle:
        handle.write(json.dumps(entry) + "\n")


def admins_of(tenant: str) -> List[str]:
    return fga_list_users("tenant", tenant, "admin")


# -------------------------------------------------------------------- models

class TenantCreate(BaseModel):
    slug: str
    admin_group: str            # invariant: a tenant is born with an admin group
    member_group: Optional[str] = None


class UserRef(BaseModel):
    user: str


# ----------------------------------------------------------------- endpoints

@app.get("/healthz")
def healthz() -> Dict[str, Any]:
    return {"ok": True, "store_id": STATE["store_id"], "model_id": STATE["model_id"]}


@app.post("/tenants", status_code=201)
def create_tenant(body: TenantCreate, user_id: str = Header(None, convert_underscores=False)):
    caller = caller_id(user_id)
    require_super_admin(caller)
    fga_write(f"platform:{PLATFORM}", "platform", f"tenant:{body.slug}")
    fga_write(f"group:{body.admin_group}#member", "admin", f"tenant:{body.slug}")
    if body.member_group:
        fga_write(f"group:{body.member_group}#member", "member", f"tenant:{body.slug}")
    audit(caller, "create_tenant", f"tenant:{body.slug}", "created")
    return {"tenant": body.slug, "admin_group": body.admin_group, "member_group": body.member_group}


@app.post("/tenants/{tenant}/members")
def add_member(tenant: str, body: UserRef, user_id: str = Header(None, convert_underscores=False)):
    """Direct membership tuple - the EXCEPTION path of the hybrid model."""
    caller = caller_id(user_id)
    require_tenant_admin(caller, tenant)
    outcome = fga_write(f"user:{body.user}", "member", f"tenant:{tenant}")
    audit(caller, "add_member", f"user:{body.user} -> tenant:{tenant}", outcome)
    return {"tenant": tenant, "user": body.user, "outcome": outcome}


@app.delete("/tenants/{tenant}/members/{user}")
def remove_member(tenant: str, user: str, user_id: str = Header(None, convert_underscores=False)):
    caller = caller_id(user_id)
    require_tenant_admin(caller, tenant)
    outcome = fga_delete(f"user:{user}", "member", f"tenant:{tenant}")
    audit(caller, "remove_member", f"user:{user} -x- tenant:{tenant}", outcome)
    return {"tenant": tenant, "user": user, "outcome": outcome}


@app.post("/tenants/{tenant}/admins")
def add_admin(tenant: str, body: UserRef, user_id: str = Header(None, convert_underscores=False)):
    caller = caller_id(user_id)
    require_tenant_admin(caller, tenant)
    outcome = fga_write(f"user:{body.user}", "admin", f"tenant:{tenant}")
    audit(caller, "add_admin", f"user:{body.user} -> tenant:{tenant}", outcome)
    return {"tenant": tenant, "user": body.user, "outcome": outcome}


@app.delete("/tenants/{tenant}/admins/{user}")
def remove_admin(tenant: str, user: str, user_id: str = Header(None, convert_underscores=False)):
    caller = caller_id(user_id)
    require_tenant_admin(caller, tenant)
    current = admins_of(tenant)
    # The invariant OpenFGA cannot express: a tenant always keeps >= 1 admin.
    if user in current and len(current) <= 1:
        audit(caller, "remove_admin", f"user:{user} -x- tenant:{tenant}", "refused-last-admin")
        raise HTTPException(409, f"user:{user} is the last admin of tenant:{tenant}")
    outcome = fga_delete(f"user:{user}", "admin", f"tenant:{tenant}")
    audit(caller, "remove_admin", f"user:{user} -x- tenant:{tenant}", outcome)
    return {"tenant": tenant, "user": user, "outcome": outcome}


@app.post("/idp/groups/{group}/members")
def idp_add_group_member(group: str, body: UserRef,
                         user_id: str = Header(None, convert_underscores=False)):
    """
    The STEADY-STATE path of the hybrid model, simulating IdP + sync service:
    a tenant admin manages their team's IdP group; the sync writes the tuple.
    Authorization mirrors IdP group ownership: the caller must administer a
    tenant this group is bound to (or be a super admin).
    """
    caller = caller_id(user_id)
    if not is_super_admin(caller):
        bound_tenants = [t["object"].split(":", 1)[1]
                         for t in fga_read(f"group:{group}#member", "tenant:")]
        if not any(fga_check(f"user:{caller}", "can_administer", f"tenant:{t}")
                   for t in bound_tenants):
            raise HTTPException(403, f"user:{caller} does not own group:{group} "
                                     f"(not an admin of any tenant it is bound to)")
    outcome = fga_write(f"user:{body.user}", "member", f"group:{group}")
    audit(caller, "idp_add_group_member", f"user:{body.user} -> group:{group}", outcome)
    return {"group": group, "user": body.user, "outcome": outcome}


@app.delete("/idp/groups/{group}/members/{user}")
def idp_remove_group_member(group: str, user: str,
                            user_id: str = Header(None, convert_underscores=False)):
    """Leaver/mover via the group path - what the IdP sync does on a delta."""
    caller = caller_id(user_id)
    if not is_super_admin(caller):
        bound_tenants = [t["object"].split(":", 1)[1]
                         for t in fga_read(f"group:{group}#member", "tenant:")]
        if not any(fga_check(f"user:{caller}", "can_administer", f"tenant:{t}")
                   for t in bound_tenants):
            raise HTTPException(403, f"user:{caller} does not own group:{group}")
    outcome = fga_delete(f"user:{user}", "member", f"group:{group}")
    audit(caller, "idp_remove_group_member", f"user:{user} -x- group:{group}", outcome)
    return {"group": group, "user": user, "outcome": outcome}


@app.get("/tenants/{tenant}/access-review")
def access_review(tenant: str, user_id: str = Header(None, convert_underscores=False)):
    """The recertification sweep: who holds what on this tenant, right now."""
    caller = caller_id(user_id)
    require_tenant_admin(caller, tenant)
    return {
        "tenant": tenant,
        "admins": admins_of(tenant),
        "members": fga_list_users("tenant", tenant, "member"),
    }


# ------------------------------------------------------------------ startup

@app.on_event("startup")
def resolve_store() -> None:
    stores = rq.get(f"{FGA}/stores", params={"page_size": 50}, timeout=15).json().get("stores", [])
    matches = [s for s in stores if s.get("name") == STORE_NAME]
    if not matches:
        raise RuntimeError(f"No OpenFGA store named {STORE_NAME} at {FGA}")
    STATE["store_id"] = matches[-1]["id"]
    models = rq.get(f"{FGA}/stores/{STATE['store_id']}/authorization-models",
                    params={"page_size": 1}, timeout=15).json().get("authorization_models", [])
    STATE["model_id"] = models[0]["id"] if models else None
    print(f"Admin API: store={STATE['store_id']} model={STATE['model_id']}")


if __name__ == "__main__":
    uvicorn.run(app, host="127.0.0.1", port=PORT, log_level="warning")
