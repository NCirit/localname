#!/bin/sh
# Helpers shared by the package phases (sourced).
export LOCALNAME_CONFIG=/var/lib/localname/config.toml
wait_dns() {
    for _ in $(seq 1 50); do
        dig +short @127.0.0.1 "$1" A | grep -qx "$2" && return
        sleep 0.2
    done
    echo "$1 did not resolve to $2" >&2
    journalctl -u localname --no-pager | tail -20 >&2
    exit 1
}
as_service() { setpriv --reuid=localname --regid=localname --init-groups "$@"; }
