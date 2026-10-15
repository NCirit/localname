#!/bin/sh
# Runs inside the systemd container: install, start, mutate live, restart, verify.
set -eu
systemd-sysusers
systemd-tmpfiles --create
address=127.0.0.1
LOCALNAME_CONFIG=/var/lib/localname/config.toml
export LOCALNAME_CONFIG
setpriv --reuid=localname --regid=localname --init-groups \
    localname setup --apply --listen "$address:53" --advertise 192.168.1.10 >/dev/null
systemctl start localname
for _ in $(seq 1 50); do
    localname status --check >/dev/null 2>&1 && break
    sleep 0.2
done
test "$(stat -c %U /proc/$(systemctl show -p MainPID --value localname))" = localname
# Root changes go through the control socket while the service runs.
localname add nas 192.168.1.20 --output json | grep -q '"status":"passed"'
dig +short @"$address" nas.lan A | grep -qx 192.168.1.20
dig +tcp +short @"$address" nas.lan A | grep -qx 192.168.1.20
# Offline root changes keep files owned by the service account.
systemctl stop localname
localname add printer 192.168.1.30 >/dev/null
test -z "$(find /var/lib/localname ! -user localname)"
systemctl start localname
for _ in $(seq 1 50); do
    dig +short @"$address" printer.lan A | grep -qx 192.168.1.30 && break
    sleep 0.2
done
dig +short @"$address" printer.lan A | grep -qx 192.168.1.30
systemctl enable localname >/dev/null 2>&1
systemctl is-active localname
echo "systemd unit: all checks passed"
