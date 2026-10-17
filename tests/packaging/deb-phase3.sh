#!/bin/sh
# After a reboot: serving; then remove (data kept), reinstall, and purge.
set -eu
. /usr/local/bin/deb-common.sh
for _ in $(seq 1 50); do systemctl is-active --quiet localname && break; sleep 0.2; done
wait_dns nas.home.arpa 192.168.1.20
if dig +short @127.0.0.1 tv.home.arpa A | grep -q .; then echo "rolled-back record returned" >&2; exit 1; fi
apt-get remove -y -q localname >/dev/null
test ! -e /usr/bin/localname
! systemctl is-active --quiet localname
test -f /var/lib/localname/config.toml
id localname >/dev/null
echo "deb: removal kept data and account"
apt-get install -y -q /packages/localname_1.0.0_amd64.deb >/dev/null
systemctl enable --now localname >/dev/null 2>&1
wait_dns nas.home.arpa 192.168.1.20
apt-get purge -y -q localname >/dev/null
test ! -e /var/lib/localname
! id localname >/dev/null 2>&1
echo "deb: reinstall served old data; purge removed data and account"
