"""ContextualOpenFgaAuthorizer - the Option B carrier for the neuro-san runtime.

THE PROBLEM this solves: the stock neuro-san OpenFgaAuthorizer checks persisted
tuples only and never sends contextual tuples, so the group->role->contextual
flow (Option B) is not enforced on the real request path. This subclass makes
Option B run on the runtime with NO fork of neuro-san.

HOW IT GETS GROUPS without patching neuro-san: the runtime hands the authorizer
only an actor id (the value of the AGENT_AUTHORIZER_ACTOR_ID_METADATA_KEY
header, default `user_id`). So the SSO proxy encodes identity AND groups into
that one header value, delimited:

    user_id: <user-id>|<GROUP1>,<GROUP2>,<GROUP3>

This class splits on the delimiter, maps the group segment via GroupMapper into
(tenant, role) contextual tuples, and attaches them to every Check and
ListObjects. The bare user id (before the delimiter) is used as the FGA user.
If no delimiter is present the value is treated as a plain user id (persisted
mode still works), so the same authorizer is safe in both modes.

Wire-in:
    AGENT_AUTHORIZER=authz.enforcement.contextual_authorizer.ContextualOpenFgaAuthorizer
    AGENT_AUTHORIZER_ACTOR_KEY=user
    AGENT_AUTHORIZER_RESOURCE_KEY=agent_network
    AGENT_AUTHORIZER_ALLOW_RELATION=can_execute        # studio/core profile
    AGENT_AUTHORIZER_ACTOR_ID_METADATA_KEY=user_id
Proxy sets: user_id = "<oid>|<comma-separated NSAN group names>", stripping any
client-supplied copy first.
"""

import os
from typing import Any, Dict, List

from neuro_san.internals.authorization.openfga.open_fga_authorizer import OpenFgaAuthorizer

from .context_builder import build_contextual_tuples
from .group_mapper import GroupMapper, RoleMemberships

IDENTITY_GROUP_DELIM = os.environ.get("OPENFGA_IDENTITY_DELIM", "|")


class ContextualOpenFgaAuthorizer(OpenFgaAuthorizer):
    """OpenFgaAuthorizer that injects group-derived roles as contextual tuples."""

    def __init__(self, fga_client: Any = None):
        super().__init__(fga_client=fga_client)
        self._group_mapper = GroupMapper()

    # ---- identity|groups parsing -----------------------------------------
    @staticmethod
    def _split_identity(raw_id: str):
        if raw_id is None:
            return "", ""
        if IDENTITY_GROUP_DELIM in raw_id:
            uid, _, groups = raw_id.partition(IDENTITY_GROUP_DELIM)
            return uid.strip(), groups.strip()
        return raw_id.strip(), ""

    def _roles_for(self, groups_str: str) -> RoleMemberships:
        if not groups_str:
            return RoleMemberships()
        groups: List[str] = [g.strip() for g in groups_str.split(",") if g.strip()]
        return self._group_mapper.map_groups(groups)

    def _contextual_tuple_objects(self, uid: str, roles: RoleMemberships) -> List[Any]:
        # Build openfga_sdk ClientTuple objects for contextual_tuples.
        # pylint: disable=invalid-name
        ClientTuple = self.openfga_sdk.client.models.tuple.ClientTuple
        out = []
        for t in build_contextual_tuples(uid, roles):
            out.append(ClientTuple(user=t["user"], relation=t["relation"], object=t["object"]))
        return out

    @staticmethod
    def _clean_actor(actor: Dict[str, Any], uid: str) -> Dict[str, Any]:
        return {"type": actor.get("type", "user"), "id": uid}

    # ---- overrides -------------------------------------------------------
    async def authorize(self, actor: Dict[str, Any], action: str,
                        resource: Dict[str, Any]) -> bool:
        uid, groups_str = self._split_identity(actor.get("id"))
        # Empty/whitespace identity -> deny (never send an invalid "user:" to
        # OpenFGA, which would raise a 500). Fail closed.
        if not uid:
            return False
        roles = self._roles_for(groups_str)
        clean_actor = self._clean_actor(actor, uid)

        # Fast path: no groups encoded -> behave exactly like the stock authorizer.
        if not roles:
            return await super().authorize(clean_actor, action, resource)

        use_action = action if isinstance(action, str) else action.value
        use_resource_type = resource.get("type")
        if not isinstance(use_resource_type, str):
            use_resource_type = use_resource_type.value
        # pylint: disable=invalid-name
        ClientCheckRequest = self.openfga_sdk.client.models.check_request.ClientCheckRequest
        request = ClientCheckRequest(
            user=f"{clean_actor.get('type')}:{clean_actor.get('id')}",
            relation=use_action,
            object=f"{use_resource_type}:{resource.get('id')}",
            contextual_tuples=self._contextual_tuple_objects(clean_actor["id"], roles),
        )
        response = await self.fga_client.check(request)
        return bool(response.allowed)

    async def list(self, actor: Dict[str, Any], relation: str,
                   resource: Dict[str, Any]) -> List[str]:
        uid, groups_str = self._split_identity(actor.get("id"))
        if not uid:
            return []
        roles = self._roles_for(groups_str)
        clean_actor = self._clean_actor(actor, uid)
        if not roles:
            return await super().list(clean_actor, relation, resource)

        actor_type = clean_actor.get("type", "")
        resource_type = resource.get("type", "")
        request_user = f"{actor_type}:{clean_actor.get('id')}"
        # pylint: disable=invalid-name
        ClientListObjectsRequest = \
            self.openfga_sdk.client.models.list_objects_request.ClientListObjectsRequest
        body = ClientListObjectsRequest(
            user=request_user, relation=relation, type=resource_type,
            contextual_tuples=self._contextual_tuple_objects(clean_actor["id"], roles),
        )
        response = await self.fga_client.list_objects(body, {})
        return [obj.split(":")[1] for obj in response.objects]
