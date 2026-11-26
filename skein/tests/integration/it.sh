#!/usr/bin/env bash
# Starts the containers in compose.yaml and runs every integration suite against them: the
# storage requirements against both S3 servers (RustFS, Versity), everything else against Versity.
# Usage: it.sh [extra cargo test args]; SKEIN_IT_STACK=up when the caller already started it.
set -euo pipefail
here="$(cd "$(dirname "$0")" && pwd)"
if [[ "${SKEIN_IT_STACK:-}" != up ]]; then
  docker compose -f "$here/compose.yaml" up -d --wait --remove-orphans
fi

make_bucket() {
  for _ in $(seq 1 60); do
    code=$(curl -s -o /dev/null -w '%{http_code}' --aws-sigv4 'aws:amz:us-east-1:s3' \
      --user skein-it:skein-it-secret -X PUT "$1/skein-it" || true)
    [[ "$code" == 200 || "$code" == 409 ]] && return 0
    sleep 1
  done
  echo "no S3 server at $1" >&2
  return 1
}

export SKEIN_IT=1
export SKEIN_IT_S3_BUCKET=skein-it
export SKEIN_IT_S3_ACCESS_KEY=skein-it
export SKEIN_IT_S3_SECRET_KEY=skein-it-secret
export SKEIN_IT_IMAP_HOST=127.0.0.1
export SKEIN_IT_IMAP_PORT=49143
export SKEIN_IT_SMTP_PORT=49025
export SKEIN_IT_IMAP_USER=ada
export SKEIN_IT_IMAP_PASSWORD=it-password
export SKEIN_IT_DOVECOT_PORT=49243
export SKEIN_IT_DOVECOT_USER=ada
export SKEIN_IT_DOVECOT_PASSWORD=it-password
export SKEIN_IT_STALWART_URL=http://127.0.0.1:49280
export SKEIN_IT_STALWART_IMAP_PORT=49244
export SKEIN_IT_STALWART_USER=ada@example.com
export SKEIN_IT_STALWART_PASSWORD=it-stalwart-password
export SKEIN_IT_RADICALE_URL=http://127.0.0.1:49232
export SKEIN_IT_RADICALE_USER=ada
export SKEIN_IT_RADICALE_PASSWORD=it-radicale-password

for endpoint in http://127.0.0.1:49100 http://127.0.0.1:49101; do
  make_bucket "$endpoint"
  SKEIN_IT_S3_ENDPOINT="$endpoint" cargo test -p skein-storage-s3 --test endpoint "$@"
done
cargo build -p skein
export SKEIN_IT_BIN="$(cargo metadata --format-version 1 --no-deps | python3 -c 'import json,sys; print(json.load(sys.stdin)["target_directory"])')/debug/skein"
SKEIN_IT_S3_ENDPOINT=http://127.0.0.1:49101 cargo test -p skein-integration --test it --test binary --test imap_write --test jmap_write "$@" -- --test-threads=1
