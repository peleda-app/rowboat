#!/usr/bin/env bash
# Generates the test CA (once), brings up Skein's compose stack with the node's TLS layer over it,
# runs Skein's integration suites and the node's (the node's even when Skein's fail), then takes
# the stack down, its volumes and the test CA with it.
# Usage: it.sh [extra cargo test args for both suites]
# SKEIN_IT_ARGS / ROWBOAT_IT_ARGS: extra cargo test args for one suite only.
# ROWBOAT_IT_KEEP=1 leaves the stack up (CI collects the logs and takes it down itself).
# On a failure the containers' logs are written to tests/integration/.logs/compose.log first.
set -euo pipefail
root="$(cd "$(dirname "$0")/../.." && pwd)"
here="$root/tests/integration"
cd "$root"
compose=(docker compose -f skein/tests/integration/compose.yaml -f "$here/compose.yaml")

python3 -c 'import socket; socket.getaddrinfo("mail.localhost", 993)' 2>/dev/null || {
  echo "mail.localhost does not resolve; add '127.0.0.1 mail.localhost' to /etc/hosts" >&2
  exit 1
}

finish() {
  local status=$?
  if [[ $status -ne 0 ]]; then
    mkdir -p "$here/.logs"
    { "${compose[@]}" ps -a; "${compose[@]}" logs --no-color --timestamps; } >"$here/.logs/compose.log" 2>&1 || true
    echo "container logs: $here/.logs/compose.log" >&2
  fi
  if [[ "${ROWBOAT_IT_KEEP:-}" != 1 ]]; then
    "${compose[@]}" down -v --remove-orphans >/dev/null 2>&1 || true
    rm -rf "$here/.certs"
  fi
  exit "$status"
}
rm -rf "$here/.logs"
trap finish EXIT

if [[ ! -f "$here/.certs/tls.key" ]]; then
  cargo run -q -p rowboat-integration --bin rowboat-it-certs -- "$here/.certs"
fi
"${compose[@]}" up -d --wait --remove-orphans

# Stalwart creates its inbound SMTP throttles on the first normal start (five connections a
# second per address), which would refuse the parallel tests; drop them and reload the settings.
# JMAP answers 200 even when a method fails, so the answer is checked for error invocations.
answer=$(curl -fsS http://127.0.0.1:49280/jmap/ -u admin:it-stalwart-admin-password \
  -H 'content-type: application/json' --data-binary @- <<'JSON'
{"using":["urn:ietf:params:jmap:core","urn:stalwart:jmap"],
 "methodCalls":[
  ["x:MtaInboundThrottle/get",{"properties":["id"]},"t"],
  ["x:MtaInboundThrottle/set",{"#destroy":{"resultOf":"t","name":"x:MtaInboundThrottle/get","path":"/list/*/id"}},"d"],
  ["x:Action/set",{"create":{"reload":{"@type":"ReloadSettings"}}},"r"]]}
JSON
)
python3 -c '
import json, sys
calls = json.loads(sys.argv[1])["methodResponses"]
bad = [c for c in calls if c[0] == "error" or c[1].get("notDestroyed") or c[1].get("notCreated")]
assert len(calls) == 3 and not bad, f"Stalwart refused the throttle removal: {calls}"
' "$answer"

read -r -a skein_args <<<"${SKEIN_IT_ARGS:-}"
read -r -a node_args <<<"${ROWBOAT_IT_ARGS:-}"
skein=0
SKEIN_IT_STACK=up bash skein/tests/integration/it.sh "$@" ${skein_args[@]+"${skein_args[@]}"} || skein=$?

node=0
ROWBOAT_IT=1 ROWBOAT_IT_CA="$here/.certs/ca.crt" \
  cargo test -p rowboat-integration --test node "$@" ${node_args[@]+"${node_args[@]}"} || node=$?

[[ $skein -eq 0 ]] || echo "Skein's integration suites failed ($skein)" >&2
[[ $node -eq 0 ]] || echo "the node's integration suite failed ($node)" >&2
[[ $skein -eq 0 && $node -eq 0 ]]
