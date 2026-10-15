#!/bin/sh
# Take a DHCP lease and print the DNS servers the router hands out (one per line).
set -eu
cat > /tmp/lease-hook <<'HOOK'
#!/bin/sh
case "$1" in
    bound|renew) : > /etc/resolv.conf; for server in $dns; do echo "nameserver $server" >> /etc/resolv.conf; done ;;
esac
HOOK
chmod +x /tmp/lease-hook
for _ in $(seq 1 20); do
    if busybox udhcpc -i eth0 -n -q -f -t 3 -T 1 -s /tmp/lease-hook >/dev/null 2>&1; then
        awk '/^nameserver/ {print $2}' /etc/resolv.conf
        exit 0
    fi
done
echo "no DHCP lease" >&2
exit 1
