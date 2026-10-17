#!/bin/bash
# `localname daemon` under launchd (CI, passwordless sudo): install, verify, kill and
# relaunch, stop and start, idempotency, uninstall keeping data. Reboots are covered by
# tests/daemon/reboot-check.sh on real hardware.
set -euo pipefail
cd "$(dirname "$0")/../.."
cargo build --locked --release --bin localname
bin=$PWD/target/release/localname
config='/Library/Application Support/localname/config.toml'
label=io.github.ncirit.localname
fail() { echo "FAIL: $*" >&2; sudo tail -50 /Library/Logs/localname.log 2>/dev/null || true; exit 1; }
json() { sudo "$bin" "$@" --output json; }
pid() { sudo launchctl print "system/$label" 2>/dev/null | awk '$1 == "pid" {print $3}'; }
cleanup() { sudo "$bin" daemon uninstall >/dev/null 2>&1 || true; sudo rm -rf '/Library/Application Support/localname'; }
trap cleanup EXIT

set +e; json daemon install >/tmp/out; code=$?; set -e
test "$code" = 3 || fail "install without configuration exited $code"
sudo "$bin" --config "$config" setup --apply --listen 127.0.0.1:5354 --advertise 192.168.1.10 --upstream 192.0.2.1:53 >/dev/null
json daemon install | grep -q '"ok":true' || fail "preview"
test ! -e "/Library/LaunchDaemons/$label.plist" || fail "preview wrote the plist"
json daemon install --apply >/tmp/out || fail "install: $(cat /tmp/out)"
grep -q '"status":"passed"' /tmp/out || fail "install not verified: $(cat /tmp/out)"
grep -q 'Managed by localname' "/Library/LaunchDaemons/$label.plist" || fail "plist lacks marker"
test "$(sudo stat -f %Lp '/Library/Application Support/localname')" = 700 || fail "directory not root-only"
json daemon install --apply | grep -q '"changed":false' || fail "re-install reported a change"

# Root's CLI finds the service configuration without --config.
sudo "$bin" add nas 192.168.1.20 --output json | grep -q '"status":"passed"' || fail "live add"
dig +short -p 5354 @127.0.0.1 nas.lan A | grep -qx 192.168.1.20 || fail "nas.lan not served"

# Killed: launchd relaunches it.
old=$(pid); test -n "$old" || fail "no pid"
sudo kill -9 "$old"
for _ in $(seq 1 100); do
    new=$(pid)
    if [ -n "$new" ] && [ "$new" != "$old" ] && dig +short -p 5354 @127.0.0.1 nas.lan A | grep -qx 192.168.1.20; then break; fi
    sleep 0.3
done
[ -n "$new" ] && [ "$new" != "$old" ] || fail "not relaunched after kill"

json daemon stop | grep -q '"status":"passed"' || fail "stop"
json daemon status | grep -q '"enabled":true' || fail "stop disabled the job"
json daemon start | grep -q '"status":"passed"' || fail "start"

json daemon uninstall >/tmp/out || fail "uninstall: $(cat /tmp/out)"
test ! -e "/Library/LaunchDaemons/$label.plist" || fail "plist left behind"
sudo test ! -e '/Library/Application Support/localname/bin/localname' || fail "binary left behind"
sudo test -f "$config" || fail "uninstall removed the configuration"
json daemon status | grep -q '"installed":false' || fail "still installed"
echo "daemon (launchd): all checks passed"
