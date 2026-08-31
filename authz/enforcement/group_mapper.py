"""IdP group names -> (tenant, role) memberships.

The naming convention IS the mapping: one security group per team x role,
plus one global super-admin group. A new team needs NO code or config change -
create its tenant tuple and its three groups, and the convention does the rest.

    NSAN-<TEAM>-ADMINS      -> (team, admin)
    NSAN-<TEAM>-DEVELOPERS  -> (team, developer)
    NSAN-<TEAM>-ANALYSTS    -> (team, analyst)
    NSAN-SUPERADMINS        -> platform super_admin (spans all tenants)

Configurable via:
    OPENFGA_GROUP_PATTERN      regex with named groups `tenant` and `role`
    OPENFGA_SUPERADMIN_GROUPS  comma-separated exact group names
"""

import logging
import os
import re
from dataclasses import dataclass, field
from typing import FrozenSet, Set, Tuple

logger = logging.getLogger(__name__)

DEFAULT_PATTERN = r"^NSAN-(?P<tenant>[A-Za-z0-9]+)-(?P<role>ADMINS|DEVELOPERS|ANALYSTS)$"
DEFAULT_SUPERADMIN_GROUPS = "NSAN-SUPERADMINS"

_ROLE_BY_SUFFIX = {
    "ADMINS": "admin",
    "DEVELOPERS": "developer",
    "ANALYSTS": "analyst",
}


@dataclass(frozen=True)
class RoleMemberships:
    """What the caller's groups amount to, in model terms."""
    memberships: FrozenSet[Tuple[str, str]] = field(default_factory=frozenset)  # (tenant, role)
    super_admin: bool = False

    def __bool__(self) -> bool:
        return self.super_admin or bool(self.memberships)


class GroupMapper:

    def __init__(self, pattern: str = None, superadmin_groups: str = None):
        self.pattern = re.compile(
            pattern or os.environ.get("OPENFGA_GROUP_PATTERN", DEFAULT_PATTERN))
        raw = superadmin_groups or os.environ.get(
            "OPENFGA_SUPERADMIN_GROUPS", DEFAULT_SUPERADMIN_GROUPS)
        self.superadmin_groups = {g.strip() for g in raw.split(",") if g.strip()}

    def map_groups(self, groups) -> RoleMemberships:
        memberships: Set[Tuple[str, str]] = set()
        super_admin = False
        for group in groups:
            group = group.strip()
            if not group:
                continue
            if group in self.superadmin_groups:
                super_admin = True
                continue
            match = self.pattern.match(group)
            if not match:
                logger.debug("ignoring unmapped group %r", group)
                continue
            role = _ROLE_BY_SUFFIX.get(match.group("role").upper())
            if role is None:
                logger.debug("ignoring group with unknown role %r", group)
                continue
            memberships.add((match.group("tenant").lower(), role))
        return RoleMemberships(memberships=frozenset(memberships), super_admin=super_admin)
