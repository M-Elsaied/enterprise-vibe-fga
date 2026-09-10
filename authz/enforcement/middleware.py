"""Starlette/FastAPI middleware: trusted proxy headers -> request identity.

The reverse proxy (e.g. mod_auth_openidc) authenticates the caller and sets
X-Auth-Request-User (the stable IdP object id) and X-Auth-Request-Groups
(comma-separated group names). This middleware validates the id, maps groups
to (tenant, role) memberships via the naming convention, and exposes a
request-scoped identity. Dev personas (dev_identity) can substitute the
headers ONLY when the dev flag is enabled.
"""

import os
import re
from contextvars import ContextVar
from dataclasses import dataclass, field
from typing import List, Optional

from starlette.middleware.base import BaseHTTPMiddleware

from .dev_identity import resolve_dev_identity, warn_if_enabled
from .group_mapper import GroupMapper, RoleMemberships

USER_HEADER = os.environ.get("OPENFGA_USER_HEADER", "x-auth-request-user")
GROUPS_HEADER = os.environ.get("OPENFGA_GROUPS_HEADER", "x-auth-request-groups")

# Stable IdP object ids: letters, digits, dot, dash, underscore, at.
# Deliberately forbids ':' and '|' so ids can never smuggle type or tenant
# segments into the FGA object grammar.
_SAFE_USER_ID = re.compile(r"^[A-Za-z0-9._@-]{1,128}$")


@dataclass(frozen=True)
class RequestIdentity:
    user_id: str
    groups: List[str] = field(default_factory=list)
    roles: RoleMemberships = field(default_factory=RoleMemberships)

    @property
    def is_authenticated(self) -> bool:
        return bool(self.user_id)


_identity_var: ContextVar[Optional[RequestIdentity]] = ContextVar(
    "openfga_request_identity", default=None)


def get_identity() -> Optional[RequestIdentity]:
    return _identity_var.get()


class IdentityMiddleware(BaseHTTPMiddleware):

    def __init__(self, app, group_mapper: Optional[GroupMapper] = None):
        super().__init__(app)
        self.group_mapper = group_mapper or GroupMapper()
        warn_if_enabled()

    async def dispatch(self, request, call_next):
        headers = request.headers

        dev = resolve_dev_identity(headers)
        if dev is not None:
            user_id, groups = dev
        else:
            user_id = (headers.get(USER_HEADER) or "").strip()
            raw = headers.get(GROUPS_HEADER, "")
            groups = [g.strip() for g in raw.split(",") if g.strip()]

        if user_id and not _SAFE_USER_ID.match(user_id):
            user_id = ""          # malformed id -> anonymous -> fail closed
            groups = []

        identity = RequestIdentity(
            user_id=user_id,
            groups=groups,
            roles=self.group_mapper.map_groups(groups) if user_id else RoleMemberships(),
        )
        token = _identity_var.set(identity)
        try:
            request.state.identity = identity
            return await call_next(request)
        finally:
            _identity_var.reset(token)
