#!/bin/sh
# After a second reboot: the rolled-back state stays rolled back.
set -eu
for _ in $(seq 1 50); do
    resolvectl domain | grep -q 'vpn0.*corp.example' && break
    sleep 0.2
done
resolvectl dns | diff /var/tmp/baseline-dns -
resolvectl domain | diff /var/tmp/baseline-domain -
localname client status --output json | grep -q '"managed":null'
echo "client split DNS: rollback persisted across reboot"
