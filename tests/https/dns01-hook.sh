#!/bin/sh
# DNS-01 hook for Pebble's challenge test server: dns01-hook set|clear NAME VALUE.
# Names containing "broken" fail, to exercise issuance errors.
set -eu
echo "$1 $2" >> /tmp/dns01.log
case "$2" in *broken*) echo "refusing to publish $2" >&2; exit 1 ;; esac
case "$1" in
    set) curl -fsS -d "{\"host\":\"$2.\",\"value\":\"$3\"}" http://10.57.0.3:8055/set-txt ;;
    clear) curl -fsS -d "{\"host\":\"$2.\"}" http://10.57.0.3:8055/clear-txt ;;
esac
