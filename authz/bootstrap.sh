#!/usr/bin/env bash
# Cross-platform (Linux/macOS) bootstrap for the authz layer against a real,
# persistent OpenFGA. Produces the pinned model.json, creates the store, writes
# the model, seeds the structural graph + first super admin, and prints the env
# the runtime needs. Idempotent where OpenFGA allows.
#
# Prereqs: the `fga` CLI on PATH (neuro_san_studio/plugins/openfga/install_fga_cli.sh
# installs it on Linux), jq, and FGA_API_URL pointing at your OpenFGA.
#
# Usage:
#   PROFILE=full  FGA_API_URL=http://openfga:8080  FGA_STORE_NAME=nsan \
#   FGA_API_TOKEN=... ./authz/bootstrap.sh
#
#   PROFILE=studio ...   # core.fga.mod + can_execute, Option B
set -euo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROFILE="${PROFILE:-full}"
# fga CLI reads FGA_API_URL / FGA_API_TOKEN from the environment.
export FGA_API_URL="${FGA_API_URL:?set FGA_API_URL to your OpenFGA endpoint}"
FGA_STORE_NAME="${FGA_STORE_NAME:-nsan}"

case "$PROFILE" in
  full)   MANIFEST="full.fga.mod"; SEED="$HERE/seed/tuples.yaml";            RELATION="can_invoke" ;;
  studio) MANIFEST="core.fga.mod"; SEED="$HERE/seed/studio-structural.yaml"; RELATION="can_execute" ;;
  *) echo "PROFILE must be 'full' or 'studio'" >&2; exit 2 ;;
esac

echo "== creating store '$FGA_STORE_NAME' on $FGA_API_URL =="
STORE_ID="$(fga store create --name "$FGA_STORE_NAME" | jq -r '.store.id')"

echo "== writing model from $MANIFEST (profile: $PROFILE) =="
MODEL_ID="$(cd "$HERE/model" && fga model write --store-id "$STORE_ID" \
  --file "$MANIFEST" --format modular | jq -r '.authorization_model_id')"

echo "== exporting model.json (FGA_POLICY_FILE) =="
fga model get --store-id "$STORE_ID" --format json > "$HERE/model/model.json"

echo "== seeding structural graph + super admin ($SEED) =="
fga tuple write --store-id "$STORE_ID" --file "$SEED"

cat <<EOF

== BOOTSTRAP COMPLETE ==
Set these on the neuro-san runtime (and mount authz/model/model.json into the image):

  FGA_API_URL=$FGA_API_URL
  FGA_STORE_NAME=$FGA_STORE_NAME
  FGA_MODEL_ID=$MODEL_ID
  FGA_POLICY_FILE=/app/authz/model/model.json
  AGENT_AUTHORIZER=neuro_san.internals.authorization.openfga.open_fga_authorizer.OpenFgaAuthorizer
  AGENT_AUTHORIZER_ACTOR_KEY=user
  AGENT_AUTHORIZER_RESOURCE_KEY=agent_network
  AGENT_AUTHORIZER_ALLOW_RELATION=$RELATION
  AGENT_AUTHORIZER_ACTOR_ID_METADATA_KEY=user_id
  OPENFGA_PLATFORM_ID=main

For Option B (studio profile) also set:
  AGENT_AUTHORIZER=authz.enforcement.contextual_authorizer.ContextualOpenFgaAuthorizer
  and have the SSO proxy set user_id="<oid>|<comma-separated NSAN group names>".
EOF
