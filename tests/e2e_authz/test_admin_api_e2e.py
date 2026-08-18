"""
End-to-end tests for the admin API (onboarding / membership management).

Runs against the live stack started by authz/run_e2e.ps1: OpenFGA, the
neuro-san server, and the admin API. The decisive assertions are the ones
that cross services: an admin API write immediately changes what the
RUNTIME allows (grant -> 200, revoke -> 403).

Tests are order-dependent within this file (a scenario that builds up
tenant gamma and mutates tenant alpha's membership).
"""

import os

import requests

ADMIN = os.environ.get("ADMIN_BASE", "http://127.0.0.1:8300")
BASE = os.environ.get("E2E_BASE", "http://127.0.0.1:8123")


def admin(method, path, user, body=None):
    return requests.request(method, f"{ADMIN}{path}", json=body,
                            headers={"user_id": user}, timeout=30)


def runtime_status(user, network):
    response = requests.get(f"{BASE}/api/v1/{network}/connectivity",
                            headers={"user_id": user}, timeout=30)
    return response.status_code


# ---- tenant creation ---------------------------------------------------

def test_01_stranger_cannot_create_tenant():
    response = admin("POST", "/tenants", "eve",
                     {"slug": "gamma", "admin_group": "g-gamma-admins"})
    assert response.status_code == 403


def test_02_super_admin_creates_tenant():
    response = admin("POST", "/tenants", "sam",
                     {"slug": "gamma", "admin_group": "g-gamma-admins"})
    assert response.status_code == 201


def test_03_first_admin_arrives_via_group_path():
    # sam puts carol in the tenant's admin group (the IdP/sync path);
    # carol is then a working admin: she can read her tenant's access review.
    response = admin("POST", "/idp/groups/g-gamma-admins/members", "sam", {"user": "carol"})
    assert response.status_code == 200
    review = admin("GET", "/tenants/gamma/access-review", "carol")
    assert review.status_code == 200
    assert "carol" in review.json()["admins"]


# ---- direct membership (the exception path) ----------------------------

def test_04_non_admin_cannot_add_members():
    response = admin("POST", "/tenants/alpha/members", "bob", {"user": "mallory"})
    assert response.status_code == 403


def test_05_admin_grant_changes_runtime_immediately():
    assert runtime_status("newhire", "alpha--private") == 403      # before
    response = admin("POST", "/tenants/alpha/members", "ada", {"user": "newhire"})
    assert response.status_code == 200
    assert runtime_status("newhire", "alpha--private") == 200      # after
    assert runtime_status("newhire", "beta--internal") == 403      # still isolated


# ---- group membership (the steady-state path) ---------------------------

def test_06_admin_grant_via_group_changes_runtime():
    assert runtime_status("frank", "alpha--private") == 403
    # ada administers tenant alpha, which binds group alpha-team -> she owns it
    response = admin("POST", "/idp/groups/alpha-team/members", "ada", {"user": "frank"})
    assert response.status_code == 200
    assert runtime_status("frank", "alpha--private") == 200


def test_07_group_path_denied_for_non_owner():
    response = admin("POST", "/idp/groups/alpha-team/members", "bob", {"user": "mallory"})
    assert response.status_code == 403
    assert runtime_status("mallory", "alpha--private") == 403


def test_08_leaver_via_group_removal_revokes_runtime():
    response = admin("DELETE", "/idp/groups/alpha-team/members/frank", "ada")
    assert response.status_code == 200
    assert runtime_status("frank", "alpha--private") == 403        # gone at once


# ---- invariants ----------------------------------------------------------

def test_09_last_admin_cannot_be_removed():
    response = admin("DELETE", "/tenants/gamma/admins/carol", "carol")
    assert response.status_code == 409


def test_10_second_admin_then_demotion_works():
    response = admin("POST", "/tenants/gamma/admins", "carol", {"user": "dave"})
    assert response.status_code == 200
    response = admin("DELETE", "/tenants/gamma/admins/dave", "carol")
    assert response.status_code == 200


# ---- lifecycle close-out --------------------------------------------------

def test_11_access_review_reflects_reality():
    review = admin("GET", "/tenants/alpha/access-review", "ada").json()
    assert "ada" in review["admins"]
    assert "alice" in review["members"]
    assert "newhire" in review["members"]
    assert "frank" not in review["members"]


def test_12_member_removal_revokes_runtime():
    response = admin("DELETE", "/tenants/alpha/members/newhire", "ada")
    assert response.status_code == 200
    assert runtime_status("newhire", "alpha--private") == 403
