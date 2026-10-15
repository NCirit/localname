#!/bin/bash
# Reboot check for client split DNS on a real macOS or Linux machine (M3b). Hosted CI
# cannot reboot, so run this by hand against a running localname server:
#   sudo tests/client/reboot-check.sh before SERVER_IP   # records state, applies
#   (reboot)
#   sudo tests/client/reboot-check.sh after              # verifies, rolls back, compares
set -euo pipefail
state=/var/tmp/localname-reboot-check
name=localname.home.arpa
snapshot() {
    if [ "$(uname)" = Darwin ]; then
        scutil --dns | grep -E 'search domain|domain   :|nameserver' | sort -u
        ls /etc/resolver 2>/dev/null | grep -vx home.arpa || true
    else
        resolvectl dns
        resolvectl domain
    fi
}
lookup() {
    if [ "$(uname)" = Darwin ]; then
        dscacheutil -q host -a name "$name" | awk '/ip_address/ {print $2}'
    else
        getent hosts "$name" | awk '{print $1}'
    fi
}
case "${1:-}" in
    before)
        server=${2:?usage: $0 before SERVER_IP}
        mkdir -p "$state"
        snapshot > "$state/baseline"
        localname client setup --server "$server" --apply
        lookup | grep -q . || { echo "FAIL: $name does not resolve after apply" >&2; exit 1; }
        echo "Applied. Reboot, then run: sudo $0 after"
        ;;
    after)
        lookup | grep -q . || { echo "FAIL: $name no longer resolves after reboot" >&2; exit 1; }
        localname client rollback
        if lookup | grep -q .; then
            echo "FAIL: $name still resolves after rollback (does the router advertise localname?)" >&2
            exit 1
        fi
        snapshot | diff "$state/baseline" - || { echo "FAIL: unrelated DNS state changed" >&2; exit 1; }
        echo "PASS: configuration survived reboot; rollback restored the exact prior DNS state"
        ;;
    *)
        echo "usage: $0 before SERVER_IP | after" >&2
        exit 2
        ;;
esac
