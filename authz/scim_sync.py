"""Reference IdP -> OpenFGA role sync + reconcile (NON-PRODUCTION stub).

Demonstrates the industry-dominant provisioning pattern (SCIM 2.0 / Graph pull):
the IdP is the source of truth for membership, but the application AUTHORIZES
against its OWN materialized copy - it never trusts token/header group lists at
scale. GitHub/Snowflake/Slack/Databricks all do this and run a periodic
RECONCILE to correct drift.

This reads a group->members feed (exactly what a SCIM push or a Microsoft Graph
`transitiveMembers` pull gives you) and materializes the equivalent PERSISTED
role tuples in OpenFGA, then reconciles - deleting role tuples the feed no
longer justifies (the leaver/mover half). Roles are derived through the SAME
GroupMapper naming convention used on the request path, so there is exactly one
mapping and it can never drift from enforcement.

The pure planning core (desired_from_feed / plan_sync) has no I/O and is
unit-tested without a server. `apply` is the thin OpenFGA side. This is a
reference: a real deployment runs a hardened SCIM endpoint or a scheduled Graph
job with real auth, paging, and alerting - not this script.

    python authz/scim_sync.py feed.json            # dry run (prints the plan)
    python authz/scim_sync.py feed.json --apply     # materialize + reconcile

feed.json: {"NSAN-ALPHA-DEVELOPERS": ["oid-dina", ...], "NSAN-SUPERADMINS": [...]}
"""

import json
import os
import sys
from typing import Dict, Iterable, List, Optional, Set, Tuple

import requests

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from enforcement.context_builder import platform_id  # noqa: E402
from enforcement.group_mapper import GroupMapper  # noqa: E402

# The relations this sync OWNS. Reconcile only ever adds/removes these; it never
# touches structural tuples (tenant->platform, resource->tenant) or group#member
# edges written by other paths.
TENANT_ROLE_RELATIONS = ("admin", "developer", "analyst")
PLATFORM_ROLE_RELATION = "super_admin"

Tuple3 = Tuple[str, str, str]  # (user, relation, object)


# ------------------------------------------------------------------ pure core

def desired_from_feed(feed: Dict[str, Iterable[str]],
                      mapper: Optional[GroupMapper] = None,
                      platform: Optional[str] = None) -> Set[Tuple3]:
    """The role tuples the feed justifies. Group names map through the SAME
    convention the request path uses; unknown groups contribute nothing."""
    mapper = mapper or GroupMapper()
    plat = platform or platform_id()
    desired: Set[Tuple3] = set()
    for group, members in feed.items():
        roles = mapper.map_groups([group])
        if not roles:
            continue
        for oid in members:
            user = oid if str(oid).startswith("user:") else f"user:{oid}"
            if roles.super_admin:
                desired.add((user, PLATFORM_ROLE_RELATION, f"platform:{plat}"))
            for tenant, role in roles.memberships:
                desired.add((user, role, f"tenant:{tenant}"))
    return desired


def plan_sync(feed: Dict[str, Iterable[str]], current: Iterable[Tuple3],
              mapper: Optional[GroupMapper] = None,
              platform: Optional[str] = None) -> Tuple[List[Tuple3], List[Tuple3]]:
    """(adds, deletes) to make the store match the feed. Deletes are the drift
    correction - role tuples present in the store but no longer in the feed."""
    desired = desired_from_feed(feed, mapper, platform)
    current_set = set(current)
    return sorted(desired - current_set), sorted(current_set - desired)


# ------------------------------------------------------------------- OpenFGA io

class _Store:
    def __init__(self, api_url: str, store_id: str, model_id: Optional[str],
                 token: Optional[str], timeout: float = 15.0):
        self.api_url = api_url.rstrip("/")
        self.store_id = store_id
        self.model_id = model_id
        self.timeout = timeout
        self.headers = {"Content-Type": "application/json"}
        if token:
            self.headers["Authorization"] = f"Bearer {token}"

    def _post(self, path: str, body: Dict) -> Dict:
        if self.model_id:
            body.setdefault("authorization_model_id", self.model_id)
        r = requests.post(f"{self.api_url}/stores/{self.store_id}{path}",
                          json=body, headers=self.headers, timeout=self.timeout)
        r.raise_for_status()
        return r.json() if r.text else {}

    def holders(self, obj_type: str, obj_id: str, relation: str) -> List[str]:
        body = {"object": {"type": obj_type, "id": obj_id}, "relation": relation,
                "user_filters": [{"type": "user"}]}
        out = []
        for e in self._post("/list-users", body).get("users", []):
            if "object" in e:
                out.append(f"user:{e['object']['id']}")
        return out

    def write(self, adds: List[Tuple3], deletes: List[Tuple3]) -> None:
        if adds:
            self._post("/write", {"writes": {"tuple_keys": [
                {"user": u, "relation": r, "object": o} for u, r, o in adds]}})
        if deletes:
            self._post("/write", {"deletes": {"tuple_keys": [
                {"user": u, "relation": r, "object": o} for u, r, o in deletes]}})


def current_managed_tuples(store: _Store, feed_desired: Set[Tuple3]) -> Set[Tuple3]:
    """Read the store's CURRENT holders of the managed relations, scoped to the
    objects the feed touches (so reconcile never reaches outside its lane)."""
    objects = {obj for _, _, obj in feed_desired}
    current: Set[Tuple3] = set()
    for obj in objects:
        otype, oid = obj.split(":", 1)
        relations = (PLATFORM_ROLE_RELATION,) if otype == "platform" else TENANT_ROLE_RELATIONS
        for relation in relations:
            for user in store.holders(otype, oid, relation):
                current.add((user, relation, obj))
    return current


def apply(feed: Dict[str, Iterable[str]], store: _Store,
          mapper: Optional[GroupMapper] = None,
          platform: Optional[str] = None) -> Tuple[List[Tuple3], List[Tuple3]]:
    desired = desired_from_feed(feed, mapper, platform)
    current = current_managed_tuples(store, desired)
    adds, deletes = plan_sync(feed, current, mapper, platform)
    store.write(adds, deletes)
    return adds, deletes


# ------------------------------------------------------------------------- cli

def _main(argv: List[str]) -> int:
    if not argv:
        print(__doc__)
        return 2
    feed_path = argv[0]
    do_apply = "--apply" in argv[1:]
    with open(feed_path, encoding="utf-8") as handle:
        feed = json.load(handle)

    if not do_apply:
        adds, deletes = plan_sync(feed, current=[])
        print(f"DRY RUN (feed only, no store read). Would materialize {len(adds)} role tuples:")
        for t in adds:
            print("  +", t)
        print("Pass --apply with FGA_API_URL/FGA_STORE_ID set to sync + reconcile.")
        return 0

    store = _Store(
        api_url=os.environ["FGA_API_URL"],
        store_id=os.environ["FGA_STORE_ID"],
        model_id=os.environ.get("FGA_MODEL_ID"),
        token=os.environ.get("FGA_API_TOKEN"))
    adds, deletes = apply(feed, store)
    print(f"synced: +{len(adds)} role tuples, -{len(deletes)} pruned (drift corrected)")
    for t in adds:
        print("  +", t)
    for t in deletes:
        print("  -", t)
    return 0


if __name__ == "__main__":
    raise SystemExit(_main(sys.argv[1:]))
