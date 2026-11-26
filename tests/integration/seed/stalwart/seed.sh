#!/bin/sh
# Runs Skein's seed, then installs the test CA's server certificate and the TLS listeners
# (IMAPS 993, submissions 465, submission with STARTTLS 587) once per data volume.
set -eu
/bin/sh /seed/seed.sh
marker=/var/lib/stalwart/.it-node-seeded
if [ -f "$marker" ]; then
  exit 0
fi

STALWART_RECOVERY_MODE=1 stalwart --config /etc/stalwart/config.json &
server=$!
trap 'kill "$server" 2>/dev/null || true' EXIT
tries=0
until curl -fs -o /dev/null http://127.0.0.1:8080/jmap/session -u "$STALWART_RECOVERY_ADMIN"; do
  tries=$((tries + 1))
  if [ "$tries" -gt 60 ]; then
    echo "Stalwart did not start in recovery mode" >&2
    exit 1
  fi
  sleep 0.5
done

pem() { awk '{printf "%s\\n", $0}' "$1"; }
answer=$(curl -fsS http://127.0.0.1:8080/jmap/ -u "$STALWART_RECOVERY_ADMIN" \
  -H 'content-type: application/json' --data-binary @- <<JSON
{"using":["urn:ietf:params:jmap:core","urn:stalwart:jmap"],
 "methodCalls":[
  ["x:Certificate/set",{"create":{"it":{
    "certificate":{"@type":"Text","value":"$(pem /certs/tls.crt)"},
    "privateKey":{"@type":"Text","secret":"$(pem /certs/tls.key)"}}}},"certificate"],
  ["x:NetworkListener/set",{"create":{
    "imaps":{"name":"imaps","bind":{"[::]:993":true},"protocol":"imap","tlsImplicit":true},
    "submissions":{"name":"submissions","bind":{"[::]:465":true},"protocol":"smtp","tlsImplicit":true},
    "submission":{"name":"submission","bind":{"[::]:587":true},"protocol":"smtp","tlsImplicit":false}}},"listeners"]]}
JSON
)
echo "$answer"
case "$answer" in
  *notCreated* | *'"error"'*)
    echo "Stalwart refused the TLS setup" >&2
    exit 1
    ;;
esac
kill "$server"
wait "$server" || true
trap - EXIT
touch "$marker"
