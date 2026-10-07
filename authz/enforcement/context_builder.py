"""Role memberships -> per-request contextual tuples ("Option B").

ONLY role tuples are ever contextual. The structural graph (tenant->platform,
resource->tenant parents) is persisted at provisioning time and never injected
here - mixing the two is how scope confusion starts.
"""

import logging
import os
from typing import Dict, List

from .group_mapper import RoleMemberships

logger = logging.getLogger(__name__)

# OpenFGA accepts at most 100 contextual tuples per request; a caller holding
# roles in ~30 teams is unusual enough to warrant a warning well before that.
CONTEXTUAL_TUPLE_LIMIT = 100
WARN_THRESHOLD = 30


def platform_id() -> str:
    return os.environ.get("OPENFGA_PLATFORM_ID", "main")


def build_contextual_tuples(user_id: str, roles: RoleMemberships) -> List[Dict[str, str]]:
    user = user_id if user_id.startswith("user:") else f"user:{user_id}"
    tuples: List[Dict[str, str]] = []
    if roles.super_admin:
        tuples.append({
            "user": user,
            "relation": "super_admin",
            "object": f"platform:{platform_id()}",
        })
    for tenant, role in sorted(roles.memberships):
        tuples.append({
            "user": user,
            "relation": role,
            "object": f"tenant:{tenant}",
        })
    if len(tuples) > WARN_THRESHOLD:
        logger.warning("caller %s carries %d role tuples (server limit %d)",
                       user, len(tuples), CONTEXTUAL_TUPLE_LIMIT)
    return tuples[:CONTEXTUAL_TUPLE_LIMIT]
