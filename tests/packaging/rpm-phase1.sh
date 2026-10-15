#!/bin/sh
set -eu
. /usr/local/bin/rpm-common.sh
rpm -i /packages/localname-0.1.0-1.x86_64.rpm
localname version | grep -q "0.1.0"
as_service localname setup --apply --listen 127.0.0.1:53 --advertise 192.168.1.10 >/dev/null
systemctl enable --now localname >/dev/null 2>&1
# 0.1.0 opens its control socket after DNS; wait for the daemon itself to answer.
for _ in $(seq 1 50); do localname status --output json 2>/dev/null | grep -q '"daemon":{' && break; sleep 0.2; done
localname add nas 192.168.1.20 >/dev/null
wait_dns nas.home.arpa 192.168.1.20
rpm -U /packages/localname-1.0.0-1.x86_64.rpm
localname version | grep -q "localname 1.0.0"
for _ in $(seq 1 50); do localname status --output json | grep -q '"version":"1.0.0"' && break; sleep 0.2; done
localname status --output json | grep -q '"version":"1.0.0"'
wait_dns nas.home.arpa 192.168.1.20
echo "rpm: upgraded from 0.1.0 with the service restarted"
