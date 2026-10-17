#!/bin/sh
# The home router keeps DHCP authority. Its one manual change is the DNS server it hands
# out, copied from the plan's router action.
set -eu
dns_server=$(cat /plan/dns_server)
echo "router action: DHCP DNS server = $dns_server"
exec dnsmasq --no-daemon --port=0 --log-dhcp --interface=eth0 \
    --dhcp-range=10.55.0.100,10.55.0.150,255.255.255.0,1h \
    --dhcp-option=option:router,10.55.0.254 \
    --dhcp-option=option:dns-server,"$dns_server"
