#!/bin/sh
# After a reboot: the configuration persists; then roll it back to the exact baseline.
set -eu
for _ in $(seq 1 50); do
    getent hosts nas.home.arpa >/dev/null 2>&1 && break
    sleep 0.2
done
getent hosts nas.home.arpa | grep -q 192.168.1.20
localname client status --output json | grep -q '"managed":{'
localname client rollback --dry-run --output json | grep -q '"changed":true'
localname client rollback --output json > /tmp/rollback.json
cat /tmp/rollback.json
grep -q '"status":"passed"' /tmp/rollback.json
test ! -e /etc/systemd/resolved.conf.d/60-localname-home.arpa.conf
if getent hosts nas.home.arpa >/dev/null 2>&1; then
    echo "nas.home.arpa still resolves after rollback" >&2
    exit 1
fi
resolvectl dns | diff /var/tmp/baseline-dns -
resolvectl domain | diff /var/tmp/baseline-domain -
localname client rollback --output json | grep -q '"changed":false'
echo "client split DNS: persisted across reboot and rolled back"
