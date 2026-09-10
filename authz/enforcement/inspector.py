"""Authorization inspector: read-mostly visibility over the graph.

NOT a role-assignment console. Assignment stays in the IdP (Entra Entitlement
Management + PIM / access reviews); building an "add user to role" button here
would create a second source of truth and re-open the group-creation security
boundary. This module only ANSWERS questions about the model as it stands:

  - resource_access: subject X's full verb set on resource R (read/update/...)
  - explain:         can subject X do action A on R, and WHY (the grant tree)
  - who_can:         which users can do action A on R (reverse lookup)

Every call is itself authorization-gated. Two guards, both enforced against
OpenFGA (never trusting the caller's claim):

  1. The caller must administer the tenant being inspected (`can_administer`,
     i.e. admin or super_admin). A developer/analyst/member holds it on no
     tenant and is refused outright.
  2. A resource is only inspectable through the tenant that actually OWNS it, so
     an admin of tenant A cannot read tenant B's resources by naming tenant A.

Both modes: pass the caller's / subject's RoleMemberships for Option B
(contextual), or None for persisted mode where stored tuples decide. The verdict
(explain.allowed, resource_access) uses Check and is exact in both modes; the
grant TREE reflects the persisted graph only (Expand takes no contextual tuples).
"""

from typing import Dict, List, Optional

from . import resource_map
from .client import StudioAuthzClient
from .group_mapper import RoleMemberships


class InspectorForbidden(Exception):
    """The caller may not run this inspection (fail-closed, translated to 403)."""


class AuthorizationInspector:

    def __init__(self, client: StudioAuthzClient):
        self.client = client
        self.profile = client.profile

    # ------------------------------------------------------------------ guards
    def _require_inspector(self, caller: str, tenant: str,
                           caller_roles: Optional[RoleMemberships] = None) -> None:
        if not self.client.check_relation(caller, "can_administer",
                                          f"tenant:{tenant}", caller_roles):
            raise InspectorForbidden(
                f"user:{caller} may not inspect tenant:{tenant} - the inspector "
                "requires admin or super_admin on the tenant")

    def _require_resource_in_tenant(self, resource_id: str, tenant: str,
                                    declared_type: Optional[str] = None) -> None:
        obj = resource_map.fga_object(resource_id, declared_type)
        spec = self.profile[resource_map.resolve_type(resource_id, declared_type)]
        if not self.client.check_relation(f"tenant:{tenant}", spec.parent_relation, obj):
            raise InspectorForbidden(
                f"{obj} is not owned by tenant:{tenant} - inspect it through its "
                "own tenant")

    # ------------------------------------------------------------------- reads
    def resource_access(self, caller: str, subject: str, resource_id: str,
                        tenant: str, declared_type: Optional[str] = None,
                        caller_roles: Optional[RoleMemberships] = None,
                        subject_roles: Optional[RoleMemberships] = None) -> Dict:
        """The subject's full verb set on one resource (one Check per action)."""
        self._require_inspector(caller, tenant, caller_roles)
        self._require_resource_in_tenant(resource_id, tenant, declared_type)
        rtype = resource_map.resolve_type(resource_id, declared_type)
        spec = self.profile[rtype]
        obj = resource_map.fga_object(resource_id, declared_type)
        access = {action: self.client.check_relation(subject, relation, obj, subject_roles)
                  for action, relation in sorted(spec.actions.items())}
        return {"subject": subject, "resource": obj, "tenant": tenant,
                "type": rtype, "access": access}

    def explain(self, caller: str, subject: str, action: str, resource_id: str,
                tenant: str, declared_type: Optional[str] = None,
                caller_roles: Optional[RoleMemberships] = None,
                subject_roles: Optional[RoleMemberships] = None) -> Dict:
        """Allow/deny verdict for (subject, action, resource) plus the grant tree."""
        self._require_inspector(caller, tenant, caller_roles)
        self._require_resource_in_tenant(resource_id, tenant, declared_type)
        relation = resource_map.relation_for(action, resource_id, declared_type, self.profile)
        obj = resource_map.fga_object(resource_id, declared_type)
        return {
            "subject": subject, "action": action, "relation": relation,
            "resource": obj, "tenant": tenant,
            "allowed": self.client.check_relation(subject, relation, obj, subject_roles),
            "tree": self.client.expand(relation, obj),
        }

    def who_can(self, caller: str, action: str, resource_id: str, tenant: str,
                declared_type: Optional[str] = None,
                caller_roles: Optional[RoleMemberships] = None) -> Dict:
        """Which users hold the relation for `action` on the resource (persisted)."""
        self._require_inspector(caller, tenant, caller_roles)
        self._require_resource_in_tenant(resource_id, tenant, declared_type)
        relation = resource_map.relation_for(action, resource_id, declared_type, self.profile)
        rtype = resource_map.resolve_type(resource_id, declared_type)
        who: List[str] = self.client.list_users(rtype, resource_id, relation)
        return {"action": action, "relation": relation,
                "resource": resource_map.fga_object(resource_id, declared_type),
                "tenant": tenant, "who": who}
