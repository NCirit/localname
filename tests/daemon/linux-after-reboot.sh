#!/bin/sh
# Inside the container after a restart: the service is back; then uninstall.
set -eu
bin=/opt/build/localname
fail() { echo "FAIL: $*" >&2; exit 1; }
json() { "$bin" "$@" --output json; }
for _ in $(seq 1 100); do
    dig +short @127.0.0.1 nas.lan A 2>/dev/null | grep -qx 192.168.1.20 && break
    sleep 0.2
done
dig +short @127.0.0.1 nas.lan A | grep -qx 192.168.1.20 || fail "not serving after reboot"
json daemon status >/tmp/out
grep -q '"enabled":true' /tmp/out && grep -q '"running":true' /tmp/out || fail "status after reboot: $(cat /tmp/out)"

json daemon uninstall --dry-run | grep -q '"changed":true' || fail "dry run"
test -e /etc/systemd/system/localname.service || fail "dry run removed the unit"
json daemon uninstall >/tmp/out || fail "uninstall: $(cat /tmp/out)"
grep -q '"status":"passed"' /tmp/out || fail "uninstall not verified"
for path in /etc/systemd/system/localname.service /etc/sysusers.d/localname.conf \
    /etc/tmpfiles.d/localname.conf /usr/local/lib/localname/localname; do
    test ! -e "$path" || fail "$path left behind"
done
test "$(systemctl is-active localname || true)" != active || fail "still running"
test -f /var/lib/localname/config.toml || fail "uninstall removed the configuration"
"$bin" --config /var/lib/localname/config.toml list | grep -q nas || fail "records lost"
json daemon status | grep -q '"installed":false' || fail "still installed"
json daemon uninstall | grep -q '"changed":false' || fail "second uninstall changed something"
echo "daemon reboot and uninstall: all checks passed"
