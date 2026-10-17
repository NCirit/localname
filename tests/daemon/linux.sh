#!/bin/sh
# `localname daemon` under systemd in a disposable container: install from a source build,
# kill and restart, reboot, uninstall, then the packaged unit (M6).
set -eu
cd "$(dirname "$0")/../.."
docker=${DOCKER:-docker}
$docker build -q -f tests/daemon/Dockerfile -t localname-daemon-test . >/dev/null
$docker rm -f localname-daemon >/dev/null 2>&1 || true
trap '$docker rm -f localname-daemon >/dev/null 2>&1 || true' EXIT
boot() {
    $docker start localname-daemon >/dev/null 2>&1 || $docker run -d --name localname-daemon \
        --privileged --cgroupns=host -v /sys/fs/cgroup:/sys/fs/cgroup:rw \
        --tmpfs /run --tmpfs /run/lock localname-daemon-test >/dev/null
    for _ in $(seq 1 100); do
        state=$($docker exec localname-daemon systemctl is-system-running 2>/dev/null || true)
        case "$state" in running|degraded) return ;; esac
        sleep 0.2
    done
}
logs() {
    $docker exec localname-daemon journalctl -u localname --no-pager || true
    exit 1
}
boot
$docker exec localname-daemon check || logs
# Reboot: the enabled service must come back on its own.
$docker stop localname-daemon >/dev/null
boot
$docker exec localname-daemon after-reboot || logs
$docker exec localname-daemon packaged || logs
echo "daemon (systemd): all checks passed"
