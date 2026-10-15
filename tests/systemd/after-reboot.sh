#!/bin/sh
# Runs after the container (and so systemd) restarts: the enabled service must come back
# on its own with the last committed revision.
set -eu
for _ in $(seq 1 50); do
    systemctl is-active --quiet localname && break
    sleep 0.2
done
systemctl is-active localname
dig +short @127.0.0.1 nas.home.arpa A | grep -qx 192.168.1.20
dig +short @127.0.0.1 printer.home.arpa A | grep -qx 192.168.1.30
echo "systemd unit: reboot persistence passed"
