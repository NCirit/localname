#!/bin/sh
# Shared helpers for the HTTPS scenarios.
config=/var/lib/localname/config.toml
L() { localname --config "$config" --output json "$@"; }
expect_exit() {
    expected=$1; shift
    set +e; "$@" > /tmp/out.json 2>/tmp/err.txt; code=$?; set -e
    if [ "$code" != "$expected" ]; then
        echo "expected exit $expected, got $code: $*" >&2; cat /tmp/out.json /tmp/err.txt >&2; exit 1
    fi
}
field() { sed -n "s/.*\"$1\":\"\\([^\"]*\\)\".*/\\1/p" | head -1; }
start_daemon() {
    localname --config "$config" serve 2>>/tmp/daemon.log &
    daemon=$!
    for _ in $(seq 1 100); do
        L status 2>/dev/null | grep -q '"daemon":{' && return
        sleep 0.1
    done
    echo "daemon did not start" >&2; cat /tmp/daemon.log >&2; exit 1
}
stop_daemon() { kill "$daemon"; wait "$daemon" 2>/dev/null || true; }
write_config() {
    mkdir -p /var/lib/localname
    cat > "$config" <<CONFIG
zone = "$1"
listen = ["127.0.0.1:5354"]
upstreams = ["192.0.2.1:53"]
allowed_clients = ["127.0.0.0/8"]
proxy_listen = ["127.0.0.1:8080"]
CONFIG
    mkdir -p /srv/www && echo "hello over https" > /srv/www/index.html
    busybox httpd -p 127.0.0.1:9000 -h /srv/www
}
