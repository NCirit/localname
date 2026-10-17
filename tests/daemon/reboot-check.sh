#!/bin/bash
# Real-hardware reboot check for `localname daemon` on Linux and macOS. Run `before` (with
# an installed service), reboot, then run `after`.
set -euo pipefail
bin=${LOCALNAME:-localname}
case "${1:-}" in
before)
    sudo "$bin" daemon status --output json | grep -q '"installed":true' || { echo "install the service first: sudo $bin daemon install --apply"; exit 1; }
    sudo "$bin" daemon status --output json | grep -q '"enabled":true' || { echo "the service does not start at boot"; exit 1; }
    echo "Service installed and enabled. Reboot, then run: $0 after" ;;
after)
    for _ in $(seq 1 60); do
        sudo "$bin" daemon status --output json | grep -q '"healthy":true' && { echo "PASS: localname started at boot and answers DNS"; exit 0; }
        sleep 1
    done
    sudo "$bin" daemon status; echo "FAIL: not answering 60 s after boot"; exit 1 ;;
*) echo "usage: $0 before|after"; exit 2 ;;
esac
