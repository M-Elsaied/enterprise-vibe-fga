"""Option B (contextual) enforcement THROUGH the real neuro-san HTTP runtime.

This is the end-to-end proof that group-derived roles enforce on the actual
request path - not just in the enforcement library. A neuro-san server is wired
to authz.enforcement.contextual_authorizer.ContextualOpenFgaAuthorizer against a
studio-profile store that holds ONLY structural tuples (no roles persisted).
Roles arrive solely in the group-encoded user_id header
("<user>|<comma-separated NSAN group names>"), are mapped to (tenant, role), and
injected as OpenFGA contextual tuples per request.

Requires the Option-B server started by authz/run_e2e.ps1|.sh (sets OPTIONB_BASE).
"""

import os

import pytest
import requests

BASE = os.environ.get("OPTIONB_BASE")

pytestmark = pytest.mark.skipif(
    not BASE, reason="Option B server not running (set OPTIONB_BASE via run_e2e)")


def status(user_id, network):
    r = requests.get(f"{BASE}/api/v1/{network}/connectivity",
                     headers={"user_id": user_id}, timeout=15)
    return r.status_code


def listed(user_id):
    r = requests.get(f"{BASE}/api/v1/list", headers={"user_id": user_id}, timeout=15)
    assert r.status_code == 200
    return {a["agent_name"] for a in r.json()["agents"]}


# user_id carries identity AND groups: "<uid>|<GROUP1>,<GROUP2>"
@pytest.mark.parametrize("user_id,network,expected", [
    # developer in alpha: runs alpha, denied cross-tenant
    ("dina|NSAN-ALPHA-DEVELOPERS", "alpha--private", 200),
    ("dina|NSAN-ALPHA-DEVELOPERS", "beta--internal", 403),
    # developer in beta: the mirror image
    ("bob|NSAN-BETA-DEVELOPERS", "beta--internal", 200),
    ("bob|NSAN-BETA-DEVELOPERS", "alpha--private", 403),
    # analyst can run (execute) in own tenant
    ("ana|NSAN-ALPHA-ANALYSTS", "alpha--private", 200),
    # super admin spans all tenants
    ("sam|NSAN-SUPERADMINS", "alpha--private", 200),
    ("sam|NSAN-SUPERADMINS", "beta--internal", 200),
    # multi-team: developer@alpha + analyst@beta -> can execute in both
    ("mia|NSAN-ALPHA-DEVELOPERS,NSAN-BETA-ANALYSTS", "alpha--private", 200),
    ("mia|NSAN-ALPHA-DEVELOPERS,NSAN-BETA-ANALYSTS", "beta--internal", 200),
    # no groups in the header -> no roles -> deny (nothing persisted)
    ("dina", "alpha--private", 403),
    # a role on a tenant that does not exist grants nothing
    ("evil|NSAN-GHOST-ADMINS", "alpha--private", 403),
    # missing identity entirely
    ("", "alpha--private", 403),
])
def test_option_b_http_enforcement(user_id, network, expected):
    assert status(user_id, network) == expected


def test_option_b_list_filtered_by_contextual_roles():
    # ListObjects with contextual tuples, over HTTP, through the runtime.
    dina = listed("dina|NSAN-ALPHA-DEVELOPERS")
    assert "alpha--private" in dina
    assert "beta--internal" not in dina
    # no groups -> empty listing (roles are never persisted in Option B)
    assert listed("dina") == set()
