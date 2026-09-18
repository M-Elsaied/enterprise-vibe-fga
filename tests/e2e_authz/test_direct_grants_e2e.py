"""Direct ladder-role grants - the hybrid model's EXCEPTION lane - through the
admin API, proven across services against the live runtime.

Routine roles come from IdP groups (Option B). This covers what groups cannot
express: a direct grant to a single user on a single tenant (contractor /
break-glass). The decisive assertions cross services: a direct grant flips the
runtime from 403 to 200, a revoke flips it back, isolation holds, and the grant
is itself authorization-gated + role-validated.

Runs against the stack started by authz/run_e2e.ps1 (admin API + full-profile
runtime). Personas (authz/seed/tuples.yaml): sam=super_admin, ada=admin of
alpha, bob=member of beta. `carlos` is a fresh user with no grants.
"""

import os

import pytest
import requests

ADMIN = os.environ.get("ADMIN_BASE")
BASE = os.environ.get("E2E_BASE", "http://127.0.0.1:8123")

pytestmark = pytest.mark.skipif(
    not ADMIN, reason="admin API not running (set ADMIN_BASE via run_e2e)")


def admin(method, path, caller, body=None):
    return requests.request(method, f"{ADMIN}{path}", json=body,
                            headers={"user_id": caller}, timeout=30)


def runtime_status(user, network):
    return requests.get(f"{BASE}/api/v1/{network}/connectivity",
                        headers={"user_id": user}, timeout=30).status_code


def test_direct_grant_flips_runtime_and_revoke_flips_back():
    assert runtime_status("carlos", "alpha--private") == 403          # before: nothing
    r = admin("POST", "/tenants/alpha/direct-grants", "sam",
              {"user": "carlos", "role": "developer"})
    assert r.status_code == 200
    assert runtime_status("carlos", "alpha--private") == 200          # granted -> runs
    assert runtime_status("carlos", "beta--internal") == 403          # isolated to alpha
    # revoke: group-derived roles would be untouched; this direct tuple goes away
    r = admin("DELETE", "/tenants/alpha/direct-grants/developer/carlos", "sam")
    assert r.status_code == 200
    assert runtime_status("carlos", "alpha--private") == 403          # gone again


def test_direct_grant_is_authorization_gated():
    # bob is only a member of beta, not an admin anywhere -> cannot direct-grant
    r = admin("POST", "/tenants/alpha/direct-grants", "bob",
              {"user": "mallory", "role": "developer"})
    assert r.status_code == 403


def test_invalid_role_rejected():
    r = admin("POST", "/tenants/alpha/direct-grants", "sam",
              {"user": "carlos", "role": "wizard"})
    assert r.status_code == 400
    # super_admin is platform-scoped, not grantable through this tenant path
    r = admin("POST", "/tenants/alpha/direct-grants", "sam",
              {"user": "carlos", "role": "super_admin"})
    assert r.status_code == 400
