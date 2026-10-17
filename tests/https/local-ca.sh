#!/bin/sh
# The local CA in the Debian system trust store: nothing is trusted until a confirmed
# install, and rollback refuses while the CA is trusted.
set -eu
. /usr/local/lib/localname-test.sh
write_config home.arpa
L service add photos 127.0.0.1:9000 >/dev/null
L https apply --mode local-ca --listen 127.0.0.1:8443 >/dev/null
start_daemon
L https verify --timeout-seconds 20 >/dev/null
get() { curl -fsS --resolve photos.home.arpa:8443:127.0.0.1 https://photos.home.arpa:8443/; }
if get >/dev/null 2>&1; then echo "untrusted CA was accepted" >&2; exit 1; fi
before=$(sha256sum /etc/ssl/certs/ca-certificates.crt)
expect_exit 4 L https trust install
L https trust install --dry-run | grep -q update-ca-certificates
[ "$(sha256sum /etc/ssl/certs/ca-certificates.crt)" = "$before" ]
echo "local-ca: no trust change without confirmation"

L https trust install --yes >/dev/null
get | grep -q "hello over https"
echo "local-ca: trusted after confirmed install"

stop_daemon
expect_exit 5 L https rollback
L https trust remove --yes >/dev/null
[ "$(sha256sum /etc/ssl/certs/ca-certificates.crt)" = "$before" ]
start_daemon
if get >/dev/null 2>&1; then echo "removed CA still trusted" >&2; exit 1; fi
stop_daemon
L https rollback >/dev/null
test ! -e /var/lib/localname/config.tls
echo "local-ca: trust removed and HTTPS rolled back"
echo "local CA trust scenario passed"
