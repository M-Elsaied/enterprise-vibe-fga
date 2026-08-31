"""Studio-profile enforcement library: Entra headers in, OpenFGA decisions out.

Pipeline per request:
    IdentityMiddleware  (trusted proxy headers -> RequestIdentity)
      -> GroupMapper    (group names -> (tenant, role) memberships)
      -> StudioAuthzClient.check / list_ids
           (resource_map routes action->relation and id->type;
            context_builder injects role tuples - Option B)

Provisioning writes the persisted structural graph through the SAME
resource_map, making write-type vs check-type drift impossible.
"""

from .client import StudioAuthzClient
from .context_builder import build_contextual_tuples, platform_id
from .dev_identity import is_enabled as dev_identity_enabled
from .group_mapper import GroupMapper, RoleMemberships
from .middleware import IdentityMiddleware, RequestIdentity, get_identity
from .provision import Provisioner
from . import resource_map

__all__ = [
    "StudioAuthzClient", "build_contextual_tuples", "platform_id",
    "dev_identity_enabled", "GroupMapper", "RoleMemberships",
    "IdentityMiddleware", "RequestIdentity", "get_identity",
    "Provisioner", "resource_map",
]
