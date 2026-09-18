#!/usr/bin/env bash
# End-to-end authorization test run for Enterprise Vibe FGA (macOS / Linux).
# Bash port of run_e2e.ps1 - same steps, same output:
#   1. model tests  2. start OpenFGA (memory)  3. seed both stores
#   4. start neuro-san + admin API  5. pytest  6. teardown (unless --keep-up)
#
# Prereqs: .venv with requirements-authz.txt installed; tools/openfga and
# tools/fga on disk; jq on PATH (brew install jq / apt install jq).
set -euo pipefail

KEEP_UP=0; HTTP_PORT=8123
for arg in "$@"; do case "$arg" in --keep-up) KEEP_UP=1 ;; --http-port=*) HTTP_PORT="${arg#*=}" ;; esac; done

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
FGA="$ROOT/tools/fga"
OPENFGA="$ROOT/tools/openfga"
PY="$ROOT/.venv/bin/python"
LOGS="$ROOT/.e2e-logs"; mkdir -p "$LOGS"
cd "$ROOT"   # backgrounded procs inherit this CWD; $! is then the real pid

FGA_PID=""; SERVER_PID=""; ADMIN_PID=""; OPTIONB_PID=""
cleanup() {
  if [ "$KEEP_UP" -eq 0 ]; then
    echo "== teardown =="
    [ -n "$OPTIONB_PID" ] && kill "$OPTIONB_PID" 2>/dev/null || true
    [ -n "$ADMIN_PID" ]  && kill "$ADMIN_PID"  2>/dev/null || true
    [ -n "$SERVER_PID" ] && kill "$SERVER_PID" 2>/dev/null || true
    [ -n "$FGA_PID" ]    && kill "$FGA_PID"    2>/dev/null || true
  else
    echo "KeepUp: openfga pid $FGA_PID, full-profile server pid $SERVER_PID, admin pid $ADMIN_PID, Option-B server pid $OPTIONB_PID"
  fi
}
trap cleanup EXIT

wait_http() { # url deadline_secs
  local url="$1" end=$(( $(date +%s) + $2 ))
  until curl -sf "$url" >/dev/null 2>&1; do
    [ "$(date +%s)" -ge "$end" ] && return 1
    sleep 1
  done
}

# ---- 1. model tests -------------------------------------------------------
echo "== fga model test =="
( cd "$ROOT/authz/tests" && "$FGA" model test --tests tenancy.fga.yaml )

# ---- 2. OpenFGA -----------------------------------------------------------
echo "== starting OpenFGA =="
"$OPENFGA" run --datastore-engine memory \
  --http-addr 127.0.0.1:18080 --grpc-addr 127.0.0.1:18081 --playground-enabled=false \
  >"$LOGS/openfga.out.log" 2>"$LOGS/openfga.err.log" &
FGA_PID=$!
export FGA_API_URL="http://127.0.0.1:18080"
wait_http "$FGA_API_URL/healthz" 30 || { echo "OpenFGA not healthy"; exit 1; }

# ---- 3. seed full-profile store ------------------------------------------
echo "== seeding store, model, tuples =="
SID=$("$FGA" store create --name vibe-e2e | jq -r '.store.id')
MID=$(cd "$ROOT/authz/model" && "$FGA" model write --store-id "$SID" --file full.fga.mod --format modular | jq -r '.authorization_model_id')
( cd "$ROOT/authz/model" && "$FGA" model get --store-id "$SID" --format json > model.json )
"$FGA" tuple write --store-id "$SID" --file "$ROOT/authz/seed/tuples.yaml" >/dev/null
echo "store=$SID model=$MID"

# ---- 3b. studio-profile store --------------------------------------------
echo "== seeding studio-profile store =="
SSID=$("$FGA" store create --name studio-e2e | jq -r '.store.id')
SMID=$(cd "$ROOT/authz/model" && "$FGA" model write --store-id "$SSID" --file core.fga.mod --format modular | jq -r '.authorization_model_id')
( cd "$ROOT/authz/model" && "$FGA" model get --store-id "$SSID" --format json > "$LOGS/studio-model.json" )
"$FGA" tuple write --store-id "$SSID" --file "$ROOT/authz/seed/studio-structural.yaml" >/dev/null
echo "studio store=$SSID model=$SMID"

# ---- 4. neuro-san server --------------------------------------------------
echo "== starting neuro-san server =="
export AGENT_MANIFEST_FILE="$ROOT/registries/vibe/manifest.hocon"
export AGENT_AUTHORIZER="neuro_san.internals.authorization.openfga.open_fga_authorizer.OpenFgaAuthorizer"
export AGENT_AUTHORIZER_ACTOR_KEY="user"
export AGENT_AUTHORIZER_RESOURCE_KEY="agent_network"
export AGENT_AUTHORIZER_ALLOW_RELATION="can_invoke"
export AGENT_AUTHORIZER_ACTOR_ID_METADATA_KEY="user_id"
export AGENT_FORWARDED_REQUEST_METADATA="request_id user_id"
export FGA_STORE_NAME="vibe-e2e"
export FGA_MODEL_ID="$MID"
export FGA_POLICY_FILE="$ROOT/authz/model/model.json"
export AGENT_DEBUG_AUTH="true"
"$PY" -m neuro_san.service.main_loop.server_main_loop --http_port "$HTTP_PORT" \
  >"$LOGS/server.out.log" 2>"$LOGS/server.err.log" &
SERVER_PID=$!
wait_http "http://127.0.0.1:$HTTP_PORT/readyz" 90 || { echo "server not ready; see $LOGS/server.err.log"; exit 1; }

# ---- 4b. admin API --------------------------------------------------------
echo "== starting admin API =="
"$PY" "$ROOT/authz/admin_api.py" >"$LOGS/admin.out.log" 2>"$LOGS/admin.err.log" &
ADMIN_PID=$!
wait_http "http://127.0.0.1:8300/healthz" 30 || { echo "admin API not ready"; exit 1; }

# ---- 4c. Option B server: neuro-san wired to the contextual authorizer ----
# Studio store (structural only - NO roles persisted); roles arrive in the
# group-encoded user_id header and become contextual tuples. Proves Option B.
echo "== starting Option B server (contextual authorizer) =="
export PYTHONPATH="$ROOT"
export AGENT_AUTHORIZER="authz.enforcement.contextual_authorizer.ContextualOpenFgaAuthorizer"
export AGENT_AUTHORIZER_ALLOW_RELATION="can_execute"
export FGA_STORE_NAME="studio-e2e"
export FGA_MODEL_ID="$SMID"
export FGA_POLICY_FILE="$LOGS/studio-model.json"
"$PY" -m neuro_san.service.main_loop.server_main_loop --http_port 8124 \
  >"$LOGS/optionb.out.log" 2>"$LOGS/optionb.err.log" &
OPTIONB_PID=$!
wait_http "http://127.0.0.1:8124/readyz" 90 || { echo "Option B server not ready; see $LOGS/optionb.err.log"; exit 1; }

# ---- 5. E2E suite ---------------------------------------------------------
echo "== pytest tests/e2e_authz =="
export E2E_BASE="http://127.0.0.1:$HTTP_PORT"
export ADMIN_BASE="http://127.0.0.1:8300"
export STUDIO_STORE_ID="$SSID"
export STUDIO_MODEL_ID="$SMID"
export OPTIONB_BASE="http://127.0.0.1:8124"
"$PY" -m pytest "$ROOT/tests/e2e_authz" -v
echo "== ALL GREEN =="
