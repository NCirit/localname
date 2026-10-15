#!/bin/sh
# A second device: obtain a DHCP lease, use the DNS server it advertises, and verify.
set -eu
cat > /tmp/lease.sh <<'SCRIPT'
#!/bin/sh
# Keep the static test address; only adopt the advertised DNS servers.
case "$1" in
    bound|renew)
        : > /etc/resolv.conf
        for server in $dns; do echo "nameserver $server" >> /etc/resolv.conf; done
        ;;
esac
SCRIPT
chmod +x /tmp/lease.sh
leased=false
for _ in $(seq 1 30); do
    if busybox udhcpc -i eth0 -n -q -f -t 3 -T 1 -s /tmp/lease.sh; then
        leased=true
        break
    fi
done
$leased
echo "resolv.conf from DHCP:"
cat /etc/resolv.conf
grep -q '^nameserver ' /etc/resolv.conf
# No server argument: verification must find localname through the DHCP-provided DNS.
localname setup verify
localname setup verify --output json > /tmp/verify.json
grep -q '"scope":"second_client"' /tmp/verify.json
grep -q '"discovered_by":"system_resolver"' /tmp/verify.json
# Forwarding still works for names outside the local zone.
getent hosts remote.external.test | grep -q 203.0.113.8
echo "second client: whole-home resolution verified over UDP, TCP, and the system resolver"
