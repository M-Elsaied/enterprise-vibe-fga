"""Provisioning writes: the persisted structural graph.

Writes go through resource_map, so the object type written is BY CONSTRUCTION
the type later checked. Structural tuples are the only thing Option B persists:
tenant->platform parents and resource->tenant parents.
"""

import json
from typing import Dict, List, Optional

import requests

from . import resource_map
from .context_builder import platform_id

# The three convention groups a persisted-mode tenant is born with, bound to the
# ladder roles. The group segment mirrors the IdP group names the request path
# maps (NSAN-<TEAM>-<ROLE>); the tenant object id is the lowercased team.
_ONBOARD_ROLE_GROUPS = (("ADMINS", "admin"), ("DEVELOPERS", "developer"),
                        ("ANALYSTS", "analyst"))


def onboard_tuples(tenant: str, platform: Optional[str] = None,
                   group_prefix: str = "NSAN") -> List[Dict[str, str]]:
    """The tuples that atomically onboard a persisted-mode tenant: the
    tenant->platform structural link PLUS its three convention groups bound to
    the ladder roles. Pure (no I/O) so the shape is unit-testable.

    Option B needs only the first tuple (provision_tenant) - roles arrive per
    request and are never persisted; the group bindings below are what persisted
    mode uses so the naming convention resolves against stored membership.
    """
    plat = platform or platform_id()
    team = tenant.upper()
    tuples = [{"user": f"platform:{plat}", "relation": "platform",
               "object": f"tenant:{tenant}"}]
    for suffix, role in _ONBOARD_ROLE_GROUPS:
        tuples.append({"user": f"group:{group_prefix}-{team}-{suffix}#member",
                       "relation": role, "object": f"tenant:{tenant}"})
    return tuples


class Provisioner:

    def __init__(self, api_url: str, store_id: str, model_id: Optional[str] = None,
                 token: Optional[str] = None, timeout: float = 5.0):
        self.api_url = api_url.rstrip("/")
        self.store_id = store_id
        self.model_id = model_id
        self.token = token
        self.timeout = timeout

    def _write(self, tuple_key: Dict[str, str]) -> str:
        return self._write_many([tuple_key])

    def _write_many(self, tuple_keys: List[Dict[str, str]]) -> str:
        """One OpenFGA write call = one atomic transaction (all or nothing).
        Used by onboarding so a tenant can never come up half-bound."""
        body: Dict = {"writes": {"tuple_keys": tuple_keys}}
        if self.model_id:
            body["authorization_model_id"] = self.model_id
        headers = {"Content-Type": "application/json"}
        if self.token:
            headers["Authorization"] = f"Bearer {self.token}"
        response = requests.post(f"{self.api_url}/stores/{self.store_id}/write",
                                 json=body, headers=headers, timeout=self.timeout)
        if response.status_code == 200:
            return "written"
        if "already existed" in json.dumps(response.json() if response.text else {}):
            return "already-existed"
        response.raise_for_status()
        return "error"

    def provision_tenant(self, tenant: str) -> str:
        """A new team, Option B style: bind its tenant object to the platform.
        Roles arrive per request; nothing about users is persisted."""
        return self._write({
            "user": f"platform:{platform_id()}",
            "relation": "platform",
            "object": f"tenant:{tenant}",
        })

    def onboard_tenant(self, tenant: str, group_prefix: str = "NSAN") -> str:
        """Persisted-mode onboarding: the platform link AND the three convention
        groups bound to the ladder roles, in ONE atomic write (see
        onboard_tuples). A tenant is never left half-provisioned."""
        return self._write_many(onboard_tuples(tenant, group_prefix=group_prefix))

    def provision_resource(self, resource_id: str, tenant: str,
                           declared_type: Optional[str] = None) -> str:
        """A new network/tool/built-in: bind it to its OWNING tenant.

        The type is resolved by resource_map - a built-in agent name can never
        be written under agent_network here.

        OWNERSHIP IS SINGLE-TENANT. A resource must have exactly one `tenant`
        parent; adding a second grants that tenant's full ladder (including
        delete) over an object another tenant owns - the isolation leak from
        the audit. To SHARE a resource across tenants, use a marketplace
        `published_to` relation (full profile), never a second tenant parent.
        This method does not add a second parent for an already-owned resource.
        """
        return self._write(resource_map.parent_tuple(resource_id, tenant, declared_type))
