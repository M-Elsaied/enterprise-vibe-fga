"""OpenFGA client for the studio profile: Check + ListObjects, Option B aware.

Every call resolves its relation/object through resource_map (never ad hoc)
and attaches the caller's role memberships as contextual tuples when present -
in persisted mode simply pass empty roles and the stored tuples decide.
"""

import os
from typing import Dict, List, Optional

import requests

from . import resource_map
from .context_builder import build_contextual_tuples
from .group_mapper import RoleMemberships

# ListObjects server defaults: max 1000 results, 3s deadline. Results beyond
# the cap are silently absent - see authz/README.md before raising limits.


class StudioAuthzClient:

    def __init__(self, api_url: Optional[str] = None, store_id: Optional[str] = None,
                 model_id: Optional[str] = None, token: Optional[str] = None,
                 profile: Dict[str, resource_map.ResourceSpec] = resource_map.STUDIO_PROFILE,
                 timeout: float = 5.0):
        self.api_url = (api_url or os.environ["FGA_API_URL"]).rstrip("/")
        self.store_id = store_id or os.environ["FGA_STORE_ID"]
        self.model_id = model_id or os.environ.get("FGA_MODEL_ID")
        self.token = token or os.environ.get("FGA_API_TOKEN")
        self.profile = profile
        self.timeout = timeout

    # ---------------------------------------------------------------- helpers
    def _headers(self) -> Dict[str, str]:
        headers = {"Content-Type": "application/json"}
        if self.token:
            headers["Authorization"] = f"Bearer {self.token}"
        return headers

    def _post(self, path: str, body: Dict) -> Dict:
        if self.model_id:
            body.setdefault("authorization_model_id", self.model_id)
        response = requests.post(f"{self.api_url}/stores/{self.store_id}{path}",
                                 json=body, headers=self._headers(), timeout=self.timeout)
        response.raise_for_status()
        return response.json()

    @staticmethod
    def _user(user_id: str) -> str:
        return user_id if user_id.startswith("user:") else f"user:{user_id}"

    @staticmethod
    def _contextual(user_id: str, roles: Optional[RoleMemberships]) -> Optional[Dict]:
        if not roles:
            return None
        tuples = build_contextual_tuples(user_id, roles)
        return {"tuple_keys": tuples} if tuples else None

    # ------------------------------------------------------------------- API
    def check(self, user_id: str, action: str, resource_id: str,
              roles: Optional[RoleMemberships] = None,
              declared_type: Optional[str] = None) -> bool:
        """May user perform `action` on the resource? Fail-closed on errors."""
        body: Dict = {
            "tuple_key": {
                "user": self._user(user_id),
                "relation": resource_map.relation_for(action, resource_id,
                                                      declared_type, self.profile),
                "object": resource_map.fga_object(resource_id, declared_type),
            },
        }
        contextual = self._contextual(user_id, roles)
        if contextual:
            body["contextual_tuples"] = contextual
        return bool(self._post("/check", body).get("allowed"))

    def check_create(self, user_id: str, tenant: str,
                     roles: Optional[RoleMemberships] = None) -> bool:
        """Create is tenant-scoped: checked on the tenant object."""
        body: Dict = {
            "tuple_key": {
                "user": self._user(user_id),
                "relation": resource_map.CREATE_RELATION,
                "object": f"tenant:{tenant}",
            },
        }
        contextual = self._contextual(user_id, roles)
        if contextual:
            body["contextual_tuples"] = contextual
        return bool(self._post("/check", body).get("allowed"))

    def list_ids(self, user_id: str, action: str, resource_type: str,
                 roles: Optional[RoleMemberships] = None) -> List[str]:
        """Ids of `resource_type` objects the user may `action` (per-user list)."""
        spec = self.profile[resource_type]
        body: Dict = {
            "user": self._user(user_id),
            "relation": spec.actions[action],
            "type": spec.fga_type,
        }
        contextual = self._contextual(user_id, roles)
        if contextual:
            body["contextual_tuples"] = contextual
        objects = self._post("/list-objects", body).get("objects", [])
        return sorted(obj.split(":", 1)[1] for obj in objects)
