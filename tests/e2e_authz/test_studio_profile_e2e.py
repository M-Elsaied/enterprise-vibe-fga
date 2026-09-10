"""Studio-profile E2E: the enforcement library against a LIVE OpenFGA.

Exercises the real Option B path: synthetic IdP groups -> GroupMapper ->
contextual tuples -> Check / ListObjects, plus the provisioning path and the
write-type vs check-type regression. Requires the studio store seeded by
run_e2e.ps1 (STUDIO_STORE_ID / STUDIO_MODEL_ID in the environment).
"""

import os
import sys

import pytest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "..", "authz"))

from enforcement import GroupMapper, Provisioner, StudioAuthzClient  # noqa: E402

pytestmark = pytest.mark.skipif(
    not os.environ.get("STUDIO_STORE_ID"),
    reason="studio store not seeded (run via authz/run_e2e.ps1)")

MAPPER = GroupMapper()


def client() -> StudioAuthzClient:
    return StudioAuthzClient(
        api_url=os.environ["FGA_API_URL"],
        store_id=os.environ["STUDIO_STORE_ID"],
        model_id=os.environ.get("STUDIO_MODEL_ID"),
    )


def roles_for(*groups):
    return MAPPER.map_groups(groups)


# ---------------------------------------------------------- the ladder, live

def test_developer_matrix_contextual():
    c = client()
    roles = roles_for("NSAN-ALPHA-DEVELOPERS")
    assert c.check("dina", "read", "alpha--net", roles)
    assert c.check("dina", "update", "alpha--net", roles)
    assert c.check("dina", "execute", "alpha--net", roles)
    assert not c.check("dina", "delete", "alpha--net", roles)
    assert c.check("dina", "access", "agent_network_designer", roles)
    assert c.check_create("dina", "alpha", roles)


def test_analyst_matrix_contextual():
    c = client()
    roles = roles_for("NSAN-ALPHA-ANALYSTS")
    assert c.check("ana", "read", "alpha--net", roles)
    assert c.check("ana", "execute", "alpha--net", roles)
    assert not c.check("ana", "update", "alpha--net", roles)
    assert not c.check("ana", "access", "agent_network_designer", roles)
    assert not c.check_create("ana", "alpha", roles)


def test_cross_tenant_isolation():
    c = client()
    roles = roles_for("NSAN-BETA-DEVELOPERS")
    assert c.check("bob", "read", "beta--net", roles)
    assert not c.check("bob", "read", "alpha--net", roles)
    assert not c.check("bob", "delete", "alpha--net", roles)


def test_super_admin_spans_all_tenants():
    c = client()
    roles = roles_for("NSAN-SUPERADMINS")
    assert c.check("sam", "delete", "alpha--net", roles)
    assert c.check("sam", "delete", "beta--net", roles)
    assert c.check("sam", "access", "agent_network_designer", roles)
    assert c.check_create("sam", "beta", roles)


MIA_READ = ["agent_network_html_creator", "alpha--net", "alpha--private",
            "alpha--public", "alpha--reports", "alpha--support", "beta--internal",
            "beta--net", "beta--pipeline", "ddgs_search"]
MIA_UPDATE = ["alpha--net", "alpha--private", "alpha--public", "alpha--reports",
              "alpha--support", "ddgs_search"]


def test_multi_team_user_and_listing():
    c = client()
    roles = roles_for("NSAN-ALPHA-DEVELOPERS", "NSAN-BETA-ANALYSTS")
    assert c.check("mia", "update", "alpha--net", roles)
    assert not c.check("mia", "update", "beta--net", roles)
    # developer across all of alpha, analyst (read-only) across all of beta,
    # and nothing from gamma/delta where mia holds no role
    assert c.list_ids("mia", "read", "agent_network", roles) == MIA_READ
    assert c.list_ids("mia", "update", "agent_network", roles) == MIA_UPDATE


def test_no_roles_sees_nothing():
    c = client()
    roles = roles_for()          # authenticated stranger: no mapped groups
    assert not c.check("eve", "read", "alpha--net", roles)
    assert c.list_ids("eve", "read", "agent_network", roles) == []


# ------------------------------------------------- provisioning + regression

def test_provisioning_uses_the_checked_type():
    api = os.environ["FGA_API_URL"]
    store = os.environ["STUDIO_STORE_ID"]
    model = os.environ.get("STUDIO_MODEL_ID")
    p = Provisioner(api, store, model)
    assert p.provision_tenant("gamma") in ("written", "already-existed")
    assert p.provision_resource("gamma--net", "gamma") in ("written", "already-existed")
    # even DECLARED as agent_network, a built-in is provisioned as special_agent
    assert p.provision_resource("agent_network_designer", "gamma",
                                "agent_network") in ("written", "already-existed")

    c = client()
    roles = roles_for("NSAN-GAMMA-DEVELOPERS")
    assert c.check("gia", "read", "gamma--net", roles)
    assert c.check("gia", "access", "agent_network_designer", roles)


def test_checker_refuses_wrong_question_for_builtins():
    # the other half of the regression: you cannot even ASK for agent_network
    # verbs on a built-in name - the shared resource map rejects it.
    c = client()
    with pytest.raises(ValueError):
        c.check("adam", "read", "agent_network_designer", roles_for("NSAN-ALPHA-ADMINS"))
