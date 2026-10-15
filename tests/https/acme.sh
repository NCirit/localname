#!/bin/sh
# ACME DNS-01 for an owned domain against Pebble (strict validation through challtestsrv).
set -eu
. /usr/local/lib/localname-test.sh
write_config home.example.net
L service add photos 127.0.0.1:9000 >/dev/null
L service add broken 127.0.0.1:9000 >/dev/null
acme="--mode acme-dns01 --listen 127.0.0.1:8443 --acme-directory https://pebble:14000/dir --acme-ca-bundle /etc/pebble/minica.pem --acme-contact mailto:test@example.net --dns01-hook /usr/local/bin/dns01-hook --dns01-wait-seconds 0"
# Terms of service must be accepted explicitly.
expect_exit 3 L https plan $acme
L https plan $acme --agree-tos > /tmp/plan.json
grep -q '"trust_store_changes":\[\]' /tmp/plan.json
L https apply $acme --agree-tos --service photos >/dev/null
start_daemon
for _ in $(seq 1 30); do
    curl -fsS --cacert /etc/pebble/minica.pem https://pebble:15000/roots/0 > /tmp/root.pem 2>/dev/null && break
    sleep 1
done
L https verify --ca-file /tmp/root.pem --timeout-seconds 120 > /tmp/verify.json || { cat /tmp/verify.json /tmp/daemon.log; exit 1; }
grep -q '"status":"passed"' /tmp/verify.json
grep -qx "set _acme-challenge.photos.home.example.net" /tmp/dns01.log
grep -qx "clear _acme-challenge.photos.home.example.net" /tmp/dns01.log
curl -fsS --cacert /tmp/root.pem --resolve photos.home.example.net:8443:127.0.0.1 https://photos.home.example.net:8443/ | grep -q "hello over https"
first=$(L https status | field sha256)
echo "acme: certificate issued through DNS-01 and served"

L https renew > /tmp/renew.json || { cat /tmp/renew.json; exit 1; }
second=$(L https status | field sha256)
[ -n "$second" ] && [ "$first" != "$second" ]
echo "acme: forced renewal replaced the certificate"

stop_daemon
start_daemon
[ "$(L https status | field sha256)" = "$second" ]
L https verify --ca-file /tmp/root.pem --timeout-seconds 10 >/dev/null
echo "acme: certificate reused after restart"

# A hook that cannot publish the record is reported, and verification fails.
stop_daemon
expect_exit 0 L https apply $acme --agree-tos
start_daemon
expect_exit 7 L https verify --ca-file /tmp/root.pem --timeout-seconds 15
for _ in $(seq 1 30); do
    L https status | grep -q 'refusing to publish _acme-challenge.broken' && break
    sleep 1
done
L https status | grep -q 'refusing to publish _acme-challenge.broken'
echo "acme: hook failures are reported"

test "$(stat -c %a /var/lib/localname/config.tls/acme-account.json)" = 600
if grep -rq "PRIVATE KEY" /tmp/*.json; then echo "key material in output" >&2; exit 1; fi
stop_daemon
L https rollback >/dev/null
L https rollback >/dev/null 2>&1 && { echo "second rollback should fail" >&2; exit 1; } || true
echo "acme: rolled back"
echo "ACME DNS-01 scenario passed"
