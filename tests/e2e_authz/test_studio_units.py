"""Unit tests for the studio enforcement library (no server required)."""

import os
import sys

import pytest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "..", "authz"))

from enforcement import resource_map  # noqa: E402
from enforcement.context_builder import build_contextual_tuples  # noqa: E402
from enforcement.dev_identity import resolve_dev_identity  # noqa: E402
from enforcement.group_mapper import GroupMapper, RoleMemberships  # noqa: E402


# ---------------------------------------------------------------- group mapper

def test_convention_maps_team_and_role():
    roles = GroupMapper().map_groups(["NSAN-ALPHA-DEVELOPERS", "NSAN-BETA-ANALYSTS"])
    assert roles.memberships == frozenset({("alpha", "developer"), ("beta", "analyst")})
    assert not roles.super_admin


def test_superadmin_group_is_platform_level():
    roles = GroupMapper().map_groups(["NSAN-SUPERADMINS"])
    assert roles.super_admin
    assert roles.memberships == frozenset()


def test_unknown_groups_are_ignored():
    roles = GroupMapper().map_groups(["Random-Team", "NSAN-ALPHA-OWNERS", ""])
    assert not roles


def test_hyphenated_team_names_map():
    # regression: real team names with hyphens/underscores must not silently
    # produce zero roles (the F1 lockout bug)
    roles = GroupMapper().map_groups(
        ["NSAN-data-science-ADMINS", "NSAN-med_affairs-DEVELOPERS"])
    assert roles.memberships == frozenset(
        {("data-science", "admin"), ("med_affairs", "developer")})


def test_seed_owned_resources_have_single_tenant_parent():
    # F3 invariant: an OWNED resource (agent_network/tool) must have exactly ONE
    # tenant parent, or a second tenant's ladder (incl. delete) leaks onto it.
    # special_agent is exempt: the built-ins are shared platform types,
    # intentionally parented to every tenant (multi-parent = available to all).
    import re
    seed = os.path.join(os.path.dirname(__file__), "..", "..",
                        "authz", "seed", "studio-structural.yaml")
    parents = {}
    with open(seed, encoding="utf-8") as handle:
        for line in handle:
            m = re.search(r'relation:\s*tenant,\s*object:\s*"((?:agent_network|tool):[^"]+)"', line)
            if m:
                parents[m.group(1)] = parents.get(m.group(1), 0) + 1
    multi = {obj: n for obj, n in parents.items() if n > 1}
    assert not multi, f"owned resources with >1 tenant parent (isolation leak): {multi}"


# ---------------------------------------------------------------- resource map

def test_builtin_names_always_route_to_special_agent():
    # the write-type vs check-type regression: even a caller declaring
    # agent_network cannot make a built-in resolve to it
    assert resource_map.resolve_type("agent_network_designer", "agent_network") == "special_agent"
    assert resource_map.fga_object("agent_network_designer") == "special_agent:agent_network_designer"
    parent = resource_map.parent_tuple("agent_network_designer", "alpha", "agent_network")
    assert parent["object"] == "special_agent:agent_network_designer"


def test_relation_routing_per_action():
    assert resource_map.relation_for("execute", "some--net") == "can_execute"
    assert resource_map.relation_for("delete", "some-tool", "tool") == "can_delete"
    with pytest.raises(ValueError):
        resource_map.relation_for("execute", "some-tool", "tool")   # tools don't execute
    with pytest.raises(ValueError):
        resource_map.relation_for("read", "agent_network_designer")  # built-ins: access only


# ------------------------------------------------------------- context builder

def test_contextual_tuples_shape():
    roles = RoleMemberships(frozenset({("alpha", "developer"), ("beta", "analyst")}), True)
    tuples = build_contextual_tuples("abc-123", roles)
    assert {"user": "user:abc-123", "relation": "super_admin",
            "object": "platform:main"} in tuples
    assert {"user": "user:abc-123", "relation": "developer",
            "object": "tenant:alpha"} in tuples
    assert {"user": "user:abc-123", "relation": "analyst",
            "object": "tenant:beta"} in tuples
    assert len(tuples) == 3


def test_no_roles_no_tuples():
    assert build_contextual_tuples("abc", RoleMemberships()) == []


# ---------------------------------------------------------------- dev identity

def test_dev_identity_off_by_default(monkeypatch):
    monkeypatch.delenv("OPENFGA_DEV_IDENTITY", raising=False)
    assert resolve_dev_identity({"x-dev-user": "mallory", "x-dev-groups": "NSAN-SUPERADMINS"}) is None


def test_dev_identity_on_when_enabled(monkeypatch):
    monkeypatch.setenv("OPENFGA_DEV_IDENTITY", "enabled")
    user, groups = resolve_dev_identity(
        {"x-dev-user": "tester", "x-dev-groups": "NSAN-ALPHA-ADMINS, NSAN-SUPERADMINS"})
    assert user == "tester"
    assert groups == ["NSAN-ALPHA-ADMINS", "NSAN-SUPERADMINS"]


# ---------------------------------------------------- contextual authorizer parsing

def test_contextual_authorizer_identity_group_split():
    # the Option B carrier splits "<uid>|<groups>" and maps the group segment;
    # tested without instantiating the FGA client (pure parsing helpers).
    from enforcement.contextual_authorizer import ContextualOpenFgaAuthorizer as C
    assert C._split_identity("abc-oid|NSAN-ALPHA-DEVELOPERS,NSAN-SUPERADMINS") == (
        "abc-oid", "NSAN-ALPHA-DEVELOPERS,NSAN-SUPERADMINS")
    # no delimiter -> plain user id, persisted mode still works
    assert C._split_identity("abc-oid") == ("abc-oid", "")
    assert C._split_identity(None) == ("", "")
