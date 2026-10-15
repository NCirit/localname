#!/bin/sh
# HTTPS trust-mode scenarios: ACME DNS-01 (Pebble) and the local CA in a system store.
set -eu
cd "$(dirname "$0")/../.."
compose="docker compose -p localname-https -f tests/https/compose.yml"
trap '$compose down --volumes >/dev/null 2>&1' EXIT
$compose build -q host
$compose up --abort-on-container-exit --exit-code-from host
docker run --rm --entrypoint /usr/local/bin/local-ca-scenario localname-https-host
