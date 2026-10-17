#!/bin/sh
# Upgrade to the version this tree builds: the running service restarts on the new binary with schema-1 data.
set -eu
. /usr/local/bin/deb-common.sh
apt-get install -y -q /packages/localname_${LOCALNAME_VERSION}_amd64.deb >/dev/null
localname version | grep -q "localname $LOCALNAME_VERSION (config schema 2)"
systemctl is-active --quiet localname
for _ in $(seq 1 50); do
    localname status --output json | grep -q "\"version\":\"$LOCALNAME_VERSION\"" && break
    sleep 0.2
done
localname status --output json | grep -q "\"version\":\"$LOCALNAME_VERSION\""
wait_dns nas.home.arpa 192.168.1.20
wait_dns printer.home.arpa 192.168.1.30
# The next write migrates the file; older revisions stay restorable.
localname add tv 192.168.1.40 --output json | grep -q '"status":"passed"'
grep -q '^schema = 2' "$LOCALNAME_CONFIG"
localname rollback 1 --output json | grep -q '"status":"passed"'
if dig +short @127.0.0.1 printer.home.arpa A | grep -q .; then echo "rollback to schema-1 revision failed" >&2; exit 1; fi
localname backup create --out /root/backup.json >/dev/null
test -z "$(find /var/lib/localname ! -user localname)"
echo "deb: upgraded to $LOCALNAME_VERSION with data migrated"
