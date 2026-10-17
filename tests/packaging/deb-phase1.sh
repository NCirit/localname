#!/bin/sh
# Install 0.1.0 (config schema 1) and create state with its CLI.
set -eu
. /usr/local/bin/deb-common.sh
apt-get install -y -q /packages/localname_0.1.0_amd64.deb >/dev/null
localname version | grep -q "localname 0.1.0 (config schema 1)"
id localname >/dev/null
as_service localname setup --apply --listen 127.0.0.1:53 --advertise 192.168.1.10 >/dev/null
systemctl enable --now localname >/dev/null 2>&1
# 0.1.0 opens its control socket after DNS; wait for the daemon itself to answer.
for _ in $(seq 1 50); do localname status --output json 2>/dev/null | grep -q '"daemon":{' && break; sleep 0.2; done
localname add nas 192.168.1.20 >/dev/null
localname add printer 192.168.1.30 >/dev/null
wait_dns nas.home.arpa 192.168.1.20
grep -q '^schema = 1' "$LOCALNAME_CONFIG"
echo "deb: 0.1.0 installed and serving"
