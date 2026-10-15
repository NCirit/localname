#!/bin/bash
# Client split DNS on macOS (CI, passwordless sudo): apply, verify, idempotency,
# conflicts, resolver restart, and rollback, preserving foreign resolver files and
# search domains. Reboots are covered by tests/client/reboot-check.sh on real hardware.
set -euo pipefail
cd "$(dirname "$0")/../.."
cargo build --locked --release --bin localname
bin=$PWD/target/release/localname
work=$(mktemp -d)
config=$work/config.toml
"$bin" --config "$config" setup --apply --listen 127.0.0.1:5354 --advertise 192.168.1.10 --upstream 192.0.2.1:53 >/dev/null
"$bin" --config "$config" add nas 192.168.1.20 >/dev/null
"$bin" --config "$config" serve &
server=$!
service=$(networksetup -listallnetworkservices | sed -n 2p)
previous_search=$(networksetup -getsearchdomains "$service")
cleanup() {
    kill "$server" 2>/dev/null || true
    sudo "$bin" client rollback >/dev/null 2>&1 || true
    sudo rm -f /etc/resolver/corp.example /etc/resolver/dev.test
    if [[ "$previous_search" == *"There aren't any"* ]]; then
        sudo networksetup -setsearchdomains "$service" Empty
    else
        sudo networksetup -setsearchdomains "$service" $previous_search
    fi
}
trap cleanup EXIT
for _ in $(seq 1 50); do
    "$bin" --config "$config" status --check >/dev/null 2>&1 && break
    sleep 0.2
done

# VPN-like state that must survive untouched.
sudo mkdir -p /etc/resolver
printf 'nameserver 10.8.0.1\n' | sudo tee /etc/resolver/corp.example >/dev/null
sudo networksetup -setsearchdomains "$service" example.lan
sleep 1
scutil --dns | grep -E 'search domain|domain   :' | sort -u > "$work/before"

sudo "$bin" client setup --server 127.0.0.1 --port 5354 --apply --output json | tee "$work/apply.json"
grep -q '"status":"passed"' "$work/apply.json"
dscacheutil -q host -a name nas.home.arpa | grep -q 192.168.1.20
sudo "$bin" client setup --server 127.0.0.1 --port 5354 --apply --output json | grep -q '"changed":false'

# A foreign resolver file for the zone is never overwritten.
printf 'nameserver 10.9.9.9\n' | sudo tee /etc/resolver/dev.test >/dev/null
set +e
sudo "$bin" client setup --server 127.0.0.1 --port 5354 --zone dev.test --apply --output json > "$work/conflict.json"
code=$?
set -e
test "$code" = 5
grep -q 'nameserver 10.9.9.9' /etc/resolver/dev.test

# The configuration survives a restart of the system resolver.
sudo launchctl kickstart -k system/com.apple.mDNSResponder
for _ in $(seq 1 50); do
    dscacheutil -q host -a name nas.home.arpa | grep -q 192.168.1.20 && break
    sleep 0.2
done
dscacheutil -q host -a name nas.home.arpa | grep -q 192.168.1.20

sudo "$bin" client rollback --output json | tee "$work/rollback.json"
grep -q '"status":"passed"' "$work/rollback.json"
test ! -e /etc/resolver/home.arpa
grep -q 'nameserver 10.8.0.1' /etc/resolver/corp.example
scutil --dns | grep -E 'search domain|domain   :' | sort -u | diff "$work/before" -
echo "macOS client split DNS: applied, verified, idempotent, conflicts refused, rolled back"
