#!/bin/sh
set -eu

config_path=/var/lib/localname/config.toml
localname --config "$config_path" setup --check \
    --listen "$LOCALNAME_LISTEN" --advertise "$LOCALNAME_ADVERTISE_ADDRESS" >/dev/null
if [ ! -f "$config_path" ]; then
    localname --config "$config_path" setup --apply \
        --listen "$LOCALNAME_LISTEN" --advertise "$LOCALNAME_ADVERTISE_ADDRESS"
fi
exec localname --config "$config_path" serve
