#!/bin/sh
# Configures a fresh Stalwart data volume once: the example.com domain, plain IMAP and HTTP
# listeners, no rate limits or bans, and the test user ada@example.com.
set -eu
marker=/var/lib/stalwart/.it-seeded
if [ -f "$marker" ]; then
  exit 0
fi

STALWART_RECOVERY_MODE=1 stalwart --config /etc/stalwart/config.json &
server=$!
trap 'kill "$server" 2>/dev/null || true' EXIT

api() {
  curl -fsS http://127.0.0.1:8080/jmap/ -u "$STALWART_RECOVERY_ADMIN" \
    -H 'content-type: application/json' --data-binary @-
}

tries=0
until curl -fs -o /dev/null http://127.0.0.1:8080/jmap/session -u "$STALWART_RECOVERY_ADMIN"; do
  tries=$((tries + 1))
  if [ "$tries" -gt 60 ]; then
    echo "Stalwart did not start in recovery mode" >&2
    exit 1
  fi
  sleep 0.5
done

refused() {
  case "$1" in
    *notCreated* | *notUpdated* | *'"error"'*) return 0 ;;
  esac
  return 1
}

answer=$(api < /seed/plan.json)
echo "$answer"
if refused "$answer"; then
  echo "Stalwart refused part of the plan" >&2
  exit 1
fi

domain=$(printf '%s' "$answer" | sed -n 's/.*"created":{"domain":{"id":"\([^"]*\)".*/\1/p')
if [ -z "$domain" ]; then
  echo "no domain id in the answer" >&2
  exit 1
fi
user=$(api <<JSON
{"using":["urn:ietf:params:jmap:core","urn:stalwart:jmap"],
 "methodCalls":[["x:Account/set",{"create":{"user":{
   "@type":"User","name":"ada","domainId":"$domain",
   "credentials":{"0":{"@type":"Password","secret":"$SKEIN_IT_PASSWORD"}},
   "roles":{"@type":"User"},"permissions":{"@type":"Inherit"},
   "encryptionAtRest":{"@type":"Disabled"}}}},"user"]]}
JSON
)
echo "$user"
if refused "$user"; then
  echo "Stalwart refused the test user" >&2
  exit 1
fi

application=$(printf '%s' "$answer" | sed -n 's/.*"x:Application\/get".*"id":"\([^"]*\)".*/\1/p')
if [ -n "$application" ]; then
  api <<JSON
{"using":["urn:ietf:params:jmap:core","urn:stalwart:jmap"],
 "methodCalls":[["x:Application/set",{"update":{"$application":{"enabled":false}}},"webui"]]}
JSON
  echo
fi

kill "$server"
wait "$server" || true
trap - EXIT
touch "$marker"
