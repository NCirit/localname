#!/bin/sh
set -eu
. /usr/local/bin/rpm-common.sh
for _ in $(seq 1 50); do systemctl is-active --quiet localname && break; sleep 0.2; done
wait_dns nas.home.arpa 192.168.1.20
rpm -e localname
test ! -e /usr/bin/localname
test -f /var/lib/localname/config.toml
echo "rpm: survived reboot; erase kept data"
