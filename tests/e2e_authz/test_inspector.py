"""Authorization inspector THROUGH the admin API, against live OpenFGA.

The inspector is read-only visibility for admins/super_admins - NOT a
role-assignment console. These tests prove the two guards that make it safe:
  1. it is itself authorization-gated (admin/super_admin of the tenant only;
     a member/developer/analyst/stranger is refused);
  2. a resource is only inspectable through the tenant that OWNS it (no
     cross-tenant peeking by naming a tenant you happen to administer);
and that its verdict never disagrees with the enforced request path.

Runs against the admin API started by authz/run_e2e.ps1|.sh (vibe-e2e store,
full profile). Personas (from authz/seed/tuples.yaml): sam=super_admin,
ada=admin of tenant alpha, alice=member of alpha, bob=member of beta,
eve=authenticated stranger.
"""

import os

import pytest
import requests

ADMIN = os.environ.get("ADMIN_BASE")
BASE = os.environ.get("E2E_BASE", "http://127.0.0.1:8123")

pytestmark = pytest.mark.skipif(
    not ADMIN, reason="admin API not running (set ADMIN_BASE via run_e2e)")


def inspect(path, caller, **params):
    return requests.get(f"{ADMIN}{path}", params=params,
                        headers={"user_id": caller}, timeout=30)


def runtime_status(user, network):
    return requests.get(f"{BASE}/api/v1/{network}/connectivity",
                        headers={"user_id": user}, timeout=30).status_code


# ---- guard 1: the inspector is authorization-gated ----------------------

def test_admin_can_inspect_own_tenant():
    r = inspect("/inspect/tenants/alpha/resource/alpha--private", "ada", subject="ada")
    assert r.status_code == 200
    # ada is admin of alpha -> full verb set on an alpha resource
    assert r.json()["access"] == {"read": True, "update": True,
                                  "delete": True, "execute": True, "invoke": True}


def test_super_admin_can_inspect_any_tenant():
    assert inspect("/inspect/tenants/alpha/resource/alpha--private",
                   "sam", subject="sam").status_code == 200
    assert inspect("/inspect/tenants/beta/resource/beta--internal",
                   "sam", subject="sam").status_code == 200


def test_member_cannot_inspect_even_own_tenant():
    # bob is a MEMBER of beta, not an admin -> the inspector refuses him
    assert inspect("/inspect/tenants/beta/resource/beta--internal",
                   "bob", subject="bob").status_code == 403


def test_stranger_cannot_inspect():
    assert inspect("/inspect/tenants/alpha/resource/alpha--private",
                   "eve", subject="eve").status_code == 403


# ---- guard 2: a resource is inspectable only through its owning tenant ---

def test_admin_cannot_peek_other_tenant_via_own():
    # ada administers alpha (gate 1 passes) but names a BETA resource -> refused
    r = inspect("/inspect/tenants/alpha/resource/beta--internal", "ada", subject="ada")
    assert r.status_code == 403


# ---- explain: verdict + the grant tree, and it matches enforcement ------

def test_explain_matches_enforced_path():
    r = inspect("/inspect/tenants/alpha/explain", "ada",
                subject="ada", action="execute", resource="alpha--private")
    assert r.status_code == 200
    body = r.json()
    assert body["allowed"] is True
    assert body["relation"] == "can_execute"
    assert body["tree"]                                  # the 'why' is present
    # the inspector can never disagree with what the runtime actually enforces
    assert runtime_status("ada", "alpha--private") == 200

    denied = inspect("/inspect/tenants/alpha/explain", "ada",
                     subject="bob", action="execute", resource="alpha--private").json()
    assert denied["allowed"] is False
    assert runtime_status("bob", "alpha--private") == 403


# ---- who-can: reverse lookup -------------------------------------------

def test_who_can_lists_holders():
    r = inspect("/inspect/tenants/alpha/who-can", "ada",
                action="read", resource="alpha--private")
    assert r.status_code == 200
    who = r.json()["who"]
    assert "ada" in who        # admin of alpha
    assert "bob" not in who     # member of beta, no path to alpha
