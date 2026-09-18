"""Flag-gated persona testing - OFF by default, one env var to disable.

When OPENFGA_DEV_IDENTITY=enabled, requests may carry X-Dev-User /
X-Dev-Groups headers that REPLACE the proxy identity, so testers can switch
personas from the front end exactly as with the persona-switcher gateway.
When the flag is unset or anything other than "enabled" (the production
default), those headers are stripped and ignored, and only the trusted
reverse-proxy headers count. A loud warning is logged once when enabled.
"""

import logging
import os
from typing import List, Optional, Tuple

logger = logging.getLogger(__name__)

DEV_USER_HEADER = "x-dev-user"
DEV_GROUPS_HEADER = "x-dev-groups"

_warned = False


def is_enabled() -> bool:
    return os.environ.get("OPENFGA_DEV_IDENTITY", "").lower() == "enabled"


def warn_if_enabled() -> None:
    global _warned
    if is_enabled() and not _warned:
        logger.warning(
            "OPENFGA_DEV_IDENTITY is ENABLED - X-Dev-User/X-Dev-Groups headers "
            "override real identity. NEVER run production with this flag.")
        _warned = True


def resolve_dev_identity(headers) -> Optional[Tuple[str, List[str]]]:
    """Return (user_id, groups) from dev headers, or None.

    `headers` is any case-insensitive mapping (Starlette Headers qualifies).
    Returns None when the flag is off OR no dev user header is present - the
    caller then proceeds with the trusted proxy headers only.
    """
    if not is_enabled():
        return None
    dev_user = headers.get(DEV_USER_HEADER)
    if not dev_user:
        return None
    warn_if_enabled()
    raw_groups = headers.get(DEV_GROUPS_HEADER, "")
    groups = [g.strip() for g in raw_groups.split(",") if g.strip()]
    return dev_user.strip(), groups
