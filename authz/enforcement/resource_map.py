"""Single source of truth for resource <-> FGA type/relation routing.

Both the tuple WRITERS (provisioning) and the CHECKERS (authorizer) import this
module, so an object can never be written under one type and checked under
another - the class of bug where a built-in agent provisioned as
``agent_network:designer`` silently fails every ``special_agent:designer``
check is structurally impossible.
"""

from dataclasses import dataclass
from typing import Dict, FrozenSet, Optional

# The privileged built-in agents. Anything with one of these ids IS a
# special_agent, whatever the caller thinks it is asking about.
SPECIAL_AGENT_NAMES: FrozenSet[str] = frozenset({
    "agent_network_designer",
    "agent_network_editor",
    "agent_network_instruction_editor",
})


@dataclass(frozen=True)
class ResourceSpec:
    fga_type: str
    parent_relation: str            # the relation naming the owning tenant
    actions: Dict[str, str]         # action name -> FGA relation


_LADDER_NETWORK = {
    "read": "can_read",
    "update": "can_update",
    "delete": "can_delete",
    "execute": "can_execute",
}
_LADDER_TOOL = {
    "read": "can_read",
    "update": "can_update",
    "delete": "can_delete",
}

STUDIO_PROFILE: Dict[str, ResourceSpec] = {
    "agent_network": ResourceSpec("agent_network", "tenant", dict(_LADDER_NETWORK)),
    "tool": ResourceSpec("tool", "tenant", dict(_LADDER_TOOL)),
    "special_agent": ResourceSpec("special_agent", "tenant", {"access": "can_access"}),
}

FULL_PROFILE: Dict[str, ResourceSpec] = {
    **STUDIO_PROFILE,
    "agent_network": ResourceSpec(
        "agent_network", "tenant", {**_LADDER_NETWORK, "invoke": "can_invoke"}),
}

# "create" is a tenant-scoped question (create WHAT, WHERE) - it is checked on
# the tenant object, not on a not-yet-existing resource.
CREATE_RELATION = "can_create_resources"


def resolve_type(resource_id: str, declared_type: Optional[str] = None) -> str:
    """Route an id to its FGA type. Built-in names ALWAYS win."""
    if resource_id in SPECIAL_AGENT_NAMES:
        return "special_agent"
    return declared_type or "agent_network"


def fga_object(resource_id: str, declared_type: Optional[str] = None) -> str:
    return f"{resolve_type(resource_id, declared_type)}:{resource_id}"


def relation_for(action: str, resource_id: str,
                 declared_type: Optional[str] = None,
                 profile: Dict[str, ResourceSpec] = STUDIO_PROFILE) -> str:
    spec = profile[resolve_type(resource_id, declared_type)]
    try:
        return spec.actions[action]
    except KeyError as err:
        raise ValueError(
            f"action '{action}' is not defined for {spec.fga_type} "
            f"(valid: {sorted(spec.actions)})") from err


def parent_tuple(resource_id: str, tenant: str,
                 declared_type: Optional[str] = None,
                 profile: Dict[str, ResourceSpec] = STUDIO_PROFILE) -> Dict[str, str]:
    """The provisioning tuple binding a resource to its owning tenant."""
    spec = profile[resolve_type(resource_id, declared_type)]
    return {
        "user": f"tenant:{tenant}",
        "relation": spec.parent_relation,
        "object": fga_object(resource_id, declared_type),
    }
