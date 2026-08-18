"""
End-to-end tenancy authorization tests.

Requires a running stack (see authz/run_e2e.ps1):
  - OpenFGA server seeded with authz/model + authz/seed/tuples.yaml
  - neuro-san server on E2E_BASE serving registries/vibe with
    AGENT_AUTHORIZER=OpenFgaAuthorizer and AGENT_AUTHORIZER_ALLOW_RELATION=can_invoke

Personas: sam = platform super admin, ada = tenant alpha admin,
alice = alpha member, bob = beta member, eve = authenticated stranger.
"""

import os

import pytest
import requests

BASE = os.environ.get("E2E_BASE", "http://127.0.0.1:8080")

ALL_NETWORKS = {"alpha--private", "alpha--public", "beta--internal"}


def list_agents(user):
    headers = {"user_id": user} if user is not None else {}
    response = requests.get(f"{BASE}/api/v1/list", headers=headers, timeout=30)
    assert response.status_code == 200
    return {agent["agent_name"] for agent in response.json()["agents"]}


def connectivity_status(user, network):
    headers = {"user_id": user} if user is not None else {}
    response = requests.get(f"{BASE}/api/v1/{network}/connectivity", headers=headers, timeout=30)
    return response.status_code


# ---------- concierge listing: each persona sees exactly their world ----------

@pytest.mark.parametrize("user,expected", [
    ("alice", {"alpha--private", "alpha--public"}),
    ("ada",   {"alpha--private", "alpha--public"}),
    ("bob",   {"beta--internal", "alpha--public"}),
    ("sam",   ALL_NETWORKS),
    ("eve",   {"alpha--public"}),
])
def test_list_is_filtered_per_persona(user, expected):
    assert list_agents(user) == expected


def test_anonymous_sees_only_platform_published():
    # No user_id header: the runtime substitutes the literal string "None",
    # which matches nothing except user:* published networks. In production
    # the SSO proxy guarantees the header exists; this documents the behavior.
    assert list_agents(None) == {"alpha--public"}


# ---------- per-network enforcement: 200 vs 403 ----------

@pytest.mark.parametrize("user,network,expected_status", [
    # tenant isolation
    ("alice", "alpha--private", 200),
    ("ada",   "alpha--private", 200),
    ("bob",   "alpha--private", 403),
    ("eve",   "alpha--private", 403),
    ("alice", "beta--internal", 403),
    ("bob",   "beta--internal", 200),
    # marketplace publish opens a network to everyone
    ("eve",   "alpha--public",  200),
    ("bob",   "alpha--public",  200),
    # super admin reaches everything
    ("sam",   "alpha--private", 200),
    ("sam",   "beta--internal", 200),
])
def test_connectivity_enforcement(user, network, expected_status):
    assert connectivity_status(user, network) == expected_status


def test_unknown_network_is_denied_not_404():
    # Authorization runs before existence: an unauthorized probe of a
    # non-existent network gets 403, revealing nothing about what exists.
    assert connectivity_status("eve", "nosuch--network") == 403


def test_anonymous_denied_on_private_network():
    assert connectivity_status(None, "alpha--private") == 403
