#!/bin/sh
# Fresh boot: start a localname server, then apply client split DNS and check it.
set -eu
expect_exit() {
    expected=$1
    shift
    set +e
    "$@" > /tmp/out.json
    code=$?
    set -e
    if [ "$code" != "$expected" ]; then
        echo "expected exit $expected, got $code: $*" >&2
        cat /tmp/out.json >&2
        exit 1
    fi
}
systemd-sysusers
systemd-tmpfiles --create
LOCALNAME_CONFIG=/var/lib/localname/config.toml
export LOCALNAME_CONFIG
setpriv --reuid=localname --regid=localname --init-groups \
    localname setup --apply --listen 127.0.0.1:5354 --advertise 192.168.1.10 --upstream 192.0.2.1:53 >/dev/null
systemctl enable --now localname >/dev/null 2>&1
for _ in $(seq 1 50); do
    localname status --check >/dev/null 2>&1 && break
    sleep 0.2
done
localname add nas 192.168.1.20 --output json | grep -q '"status":"passed"'
unset LOCALNAME_CONFIG

# With resolv.conf pointing elsewhere, applications bypass resolved: unsupported.
cp /etc/resolv.conf /tmp/resolv.conf.stub
echo "nameserver 192.0.2.53" > /etc/resolv.conf
expect_exit 6 localname client setup --server 127.0.0.1 --port 5354 --apply --output json
grep -q 'resolv.conf does not point at systemd-resolved' /tmp/out.json
cp /tmp/resolv.conf.stub /etc/resolv.conf
for _ in $(seq 1 50); do
    resolvectl domain | grep -q 'vpn0.*corp.example' && break
    sleep 0.2
done
resolvectl dns > /tmp/baseline-dns
resolvectl domain > /tmp/baseline-domain
cp /tmp/baseline-dns /tmp/baseline-domain /var/tmp/

# Plan changes nothing.
localname client setup --server 127.0.0.1 --port 5354 --output json > /tmp/plan.json
grep -q '"changed":true' /tmp/plan.json
test ! -e /etc/systemd/resolved.conf.d/60-localname-home.arpa.conf

# A server that does not answer is refused before anything changes.
expect_exit 6 localname client setup --server 127.0.0.1 --port 9 --apply --timeout-ms 300 --output json
test ! -e /etc/systemd/resolved.conf.d/60-localname-home.arpa.conf

localname client setup --server 127.0.0.1 --port 5354 --apply --output json > /tmp/apply.json
cat /tmp/apply.json
grep -q '"changed":true' /tmp/apply.json
grep -q '"status":"passed"' /tmp/apply.json
grep -q 'unchanged' /tmp/apply.json
getent hosts nas.home.arpa | grep -q 192.168.1.20
# The VPN link and search domains are exactly as before.
resolvectl domain | grep 'vpn0' | grep -q 'corp.example'
resolvectl domain | grep 'Global' | grep -q 'example.lan'
resolvectl domain | grep 'Global' | grep -q '~home.arpa'
test "$(resolvectl dns | grep vpn0)" = "$(grep vpn0 /tmp/baseline-dns)"
test "$(resolvectl domain | grep vpn0)" = "$(grep vpn0 /tmp/baseline-domain)"

# Applying again is a no-op.
localname client setup --server 127.0.0.1 --port 5354 --apply --output json > /tmp/again.json
grep -q '"changed":false' /tmp/again.json

# Foreign global DNS servers would also receive the zone: refused, nothing written.
printf '[Resolve]\nDNS=9.9.9.9\n' > /etc/systemd/resolved.conf.d/10-other.conf
expect_exit 5 localname client setup --server 127.0.0.1 --port 5354 --zone dev.test --apply --output json
grep -q '10-other.conf sets global DNS servers' /tmp/out.json
rm /etc/systemd/resolved.conf.d/10-other.conf
test ! -e /etc/systemd/resolved.conf.d/60-localname-dev.test.conf
echo "client split DNS: applied, verified, idempotent, conflicts refused"
