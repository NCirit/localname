#!/bin/sh
# The localname host: detect the network, apply the plan, publish the router action.
set -eu
config=/var/lib/localname/config.toml
localname --config "$config" setup --apply --upstream 10.55.0.3:5354 --output json > /tmp/plan.json
cat /tmp/plan.json
sed -n 's/.*"router_action":{[^}]*"dns_server":"\([^"]*\)".*/\1/p' /tmp/plan.json > /tmp/dns_server
test -s /tmp/dns_server
localname --config "$config" serve &
daemon=$!
for _ in $(seq 1 50); do
    if localname --config "$config" setup verify --output json > /tmp/verify.json; then
        cp /tmp/plan.json /plan/plan.json
        cp /tmp/dns_server /plan/dns_server
        wait "$daemon"
        exit
    fi
    sleep 0.2
done
cat /tmp/verify.json
exit 1
