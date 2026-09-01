"""Provisioning writes: the persisted structural graph.

Writes go through resource_map, so the object type written is BY CONSTRUCTION
the type later checked. Structural tuples are the only thing Option B persists:
tenant->platform parents and resource->tenant parents.
"""

import json
from typing import Dict, Optional

import requests

from . import resource_map
from .context_builder import platform_id


class Provisioner:

    def __init__(self, api_url: str, store_id: str, model_id: Optional[str] = None,
                 token: Optional[str] = None, timeout: float = 5.0):
        self.api_url = api_url.rstrip("/")
        self.store_id = store_id
        self.model_id = model_id
        self.token = token
        self.timeout = timeout

    def _write(self, tuple_key: Dict[str, str]) -> str:
        body: Dict = {"writes": {"tuple_keys": [tuple_key]}}
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
        """A new team: bind its tenant object to the platform."""
        return self._write({
            "user": f"platform:{platform_id()}",
            "relation": "platform",
            "object": f"tenant:{tenant}",
        })

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
