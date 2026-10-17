#!/bin/sh
# Inside the container: install from a source build, verify, kill, stop, start.
set -eu
bin=/opt/build/localname
config=/var/lib/localname/config.toml
fail() { echo "FAIL: $*" >&2; exit 1; }
json() { "$bin" "$@" --output json; }
wait_for() {
    for _ in $(seq 1 100); do
        if eval "$1"; then return 0; fi
        sleep 0.2
    done
    fail "timed out waiting for: $1"
}

json daemon status | grep -q '"installed":false' || fail "fresh host reports an installed service"
# Without a configuration, install is refused before changing anything.
set +e; json daemon install >/tmp/out; code=$?; set -e
test "$code" = 3 || fail "install without configuration exited $code"
grep -q 'setup --apply' /tmp/out || fail "no setup remedy: $(cat /tmp/out)"
test ! -e /etc/systemd/system/localname.service || fail "blocked install wrote a unit"

# Setup as root before the service account exists.
"$bin" --config "$config" setup --apply --listen 127.0.0.1:53 --advertise 192.168.1.10 --upstream 192.0.2.1:53 >/dev/null
json daemon install | grep -q '"ok":true' || fail "preview failed"
test ! -e /etc/systemd/system/localname.service || fail "preview wrote a unit"
json daemon install --apply >/tmp/out || fail "install: $(cat /tmp/out)"
grep -q '"status":"passed"' /tmp/out || fail "install not verified: $(cat /tmp/out)"
grep -q '"changed":true' /tmp/out || fail "install reported no change"
head -1 /etc/systemd/system/localname.service | grep -q 'Managed by localname' || fail "unit lacks marker"
grep -qx 'ExecStart=/usr/local/lib/localname/localname serve' /etc/systemd/system/localname.service || fail "unit runs the wrong binary"
cmp -s "$bin" /usr/local/lib/localname/localname || fail "binary not copied"
test "$(systemctl is-enabled localname)" = enabled || fail "not enabled"
pid=$(systemctl show -p MainPID --value localname)
test "$(stat -c %U /proc/$pid)" = localname || fail "service does not run as localname"
test -z "$(find /var/lib/localname ! -user localname)" || fail "root-owned files left in /var/lib/localname"

# Re-running is idempotent.
json daemon install --apply >/tmp/out || fail "re-install: $(cat /tmp/out)"
grep -q '"changed":false' /tmp/out || fail "re-install reported a change: $(cat /tmp/out)"
test "$(systemctl show -p MainPID --value localname)" = "$pid" || fail "re-install restarted the service"

# Root's CLI finds the service configuration without --config.
"$bin" add nas 192.168.1.20 --output json | grep -q '"status":"passed"' || fail "live add without --config"
dig +short @127.0.0.1 nas.lan A | grep -qx 192.168.1.20 || fail "nas.lan not served"
json daemon status | grep -q '"running":true' || fail "status does not report running"

# Killed: systemd restarts it.
kill -9 "$pid"
wait_for '[ "$(systemctl show -p MainPID --value localname)" != 0 ] && [ "$(systemctl show -p MainPID --value localname)" != "$pid" ] && dig +short @127.0.0.1 nas.lan A | grep -qx 192.168.1.20'

# Stop and start.
json daemon stop | grep -q '"status":"passed"' || fail "stop"
test "$(systemctl is-active localname || true)" != active || fail "still active after stop"
test "$(systemctl is-enabled localname)" = enabled || fail "stop disabled the unit"
json daemon start | grep -q '"status":"passed"' || fail "start"
echo "daemon install: all checks passed"
