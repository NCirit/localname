#!/bin/sh
# Inside the container: with a package's files present, install only enables the packaged
# unit, and uninstall only disables it.
set -eu
fail() { echo "FAIL: $*" >&2; exit 1; }
install -m 0755 /opt/build/localname /usr/bin/localname
install -m 0644 /opt/packaging/localname.service /usr/lib/systemd/system/localname.service
install -m 0644 /opt/packaging/localname.sysusers /usr/lib/sysusers.d/localname.conf
install -m 0644 /opt/packaging/localname.tmpfiles /usr/lib/tmpfiles.d/localname.conf
systemctl daemon-reload
localname daemon install --apply --output json >/tmp/out || fail "packaged install: $(cat /tmp/out)"
grep -q '"status":"passed"' /tmp/out || fail "packaged install not verified"
test ! -e /etc/systemd/system/localname.service || fail "wrote a unit over the package"
test ! -e /usr/local/lib/localname/localname || fail "copied a binary despite the package"
test "$(systemctl show -p ExecMainPID --value localname)" != 0 || fail "not running"
grep -q '/usr/bin/localname' /proc/"$(systemctl show -p MainPID --value localname)"/cmdline || fail "not the packaged binary"
localname daemon uninstall --output json | grep -q '"status":"passed"' || fail "packaged uninstall"
test -f /usr/lib/systemd/system/localname.service || fail "removed the packaged unit"
test "$(systemctl is-enabled localname || true)" = disabled || fail "still enabled"
echo "daemon packaged unit: all checks passed"
