#!/bin/sh
# OpenWrt adapter integration matrix: changed-state failure, clean apply, repeated apply,
# reboot persistence, rollback, rollback persistence, and rollback conflicts (M3c).
set -eu
cd "$(dirname "$0")/../.."
compose="docker compose -p localname-router -f tests/router/compose.yml"
$compose up -d --build >/dev/null
trap '$compose logs openwrt server | tail -40; $compose down --volumes >/dev/null 2>&1' EXIT
admin() { $compose exec -T admin localname --output json router "$@" --host 10.56.0.1; }
on_router() { $compose exec -T openwrt sh -c "$1"; }
lease_dns() { $compose exec -T client lease; }
field() { python3 -c "import json,sys; d=json.load(sys.stdin); print(eval(sys.argv[1], {}, {'d': d}))" "$1"; }
expect_exit() {
    expected=$1; shift
    set +e; "$@" > /tmp/localname-router-out.json; code=$?; set -e
    [ "$code" = "$expected" ] || { echo "expected exit $expected, got $code: $*" >&2; cat /tmp/localname-router-out.json >&2; exit 1; }
}
wait_router() {
    for _ in $(seq 1 60); do
        if $compose exec -T admin ssh -o BatchMode=yes -o StrictHostKeyChecking=accept-new -o ConnectTimeout=2 root@10.56.0.1 'pgrep dnsmasq >/dev/null && uci -q get dhcp.lan' >/dev/null 2>&1; then
            return
        fi
        sleep 1
    done
    echo "router did not come up" >&2
    exit 1
}
reboot_router() {
    $compose restart openwrt >/dev/null
    sleep 2
    wait_router
}
wait_router
test "$(lease_dns)" = 10.56.0.1

admin detect | field "d['data']['detected']['release']" | grep -qx 24.10.3

# Changed-state failure: the router changes between plan and apply.
fingerprint=$(admin plan --dns 10.56.0.20 | field "d['data']['fingerprint']")
on_router "uci add_list dhcp.lan.dhcp_option='42,10.56.0.1' && uci commit dhcp"
expect_exit 5 admin apply --dns 10.56.0.20 --expect-state "$fingerprint"
grep -q '"code":"CONFLICT"' /tmp/localname-router-out.json
test "$(on_router 'uci -q get dhcp.lan.dhcp_option')" = "42,10.56.0.1"
echo "matrix: changed-state failure refused without changes"

# Clean apply. The unrelated option 42 must survive everything that follows.
plan=$(admin plan --dns 10.56.0.20)
echo "$plan" | field "d['data']['changes']"
fingerprint=$(echo "$plan" | field "d['data']['fingerprint']")
admin apply --dns 10.56.0.20 --expect-state "$fingerprint" > /tmp/localname-router-apply.json
field "d['verification']['status']" < /tmp/localname-router-apply.json | grep -qx passed
test "$(on_router 'uci -q get dhcp.lan.dhcp_option')" = "42,10.56.0.1 6,10.56.0.20"
test "$(on_router 'uci -q get dhcp.lan.dns_service')" = 0
test "$(lease_dns)" = 10.56.0.20
$compose exec -T client localname setup verify >/dev/null
echo "matrix: clean apply verified by a DHCP client"

# Repeated apply changes nothing.
plan=$(admin plan --dns 10.56.0.20)
test "$(echo "$plan" | field "d['changed']")" = False
fingerprint=$(echo "$plan" | field "d['data']['fingerprint']")
test "$(admin apply --dns 10.56.0.20 --expect-state "$fingerprint" | field "d['changed']")" = False
echo "matrix: repeated apply is idempotent"

# Reboot persistence.
reboot_router
# dnsmasq's running configuration is regenerated during boot; wait for it.
for _ in $(seq 1 30); do
    [ "$(admin status | field "d['data']['state']")" = applied ] && break
    sleep 1
done
test "$(admin status | field "d['data']['state']")" = applied
test "$(lease_dns)" = 10.56.0.20
echo "matrix: change persisted across router reboot"

# Rollback restores the captured state exactly.
admin rollback --dry-run | field "d['data']['changes']"
admin rollback > /tmp/localname-router-rollback.json
field "d['verification']['status']" < /tmp/localname-router-rollback.json | grep -qx passed
test "$(on_router 'uci -q get dhcp.lan.dhcp_option')" = "42,10.56.0.1"
test -z "$(on_router 'uci -q get dhcp.lan.dns_service || true')"
test "$(lease_dns)" = 10.56.0.1
expect_exit 3 admin rollback
echo "matrix: rollback restored the captured state"

reboot_router
test "$(admin status | field "d['data']['state']")" = not_applied
test "$(lease_dns)" = 10.56.0.1
echo "matrix: rollback persisted across router reboot"

# Rollback refuses when someone changed the managed settings after apply.
fingerprint=$(admin plan --dns 10.56.0.20 | field "d['data']['fingerprint']")
admin apply --dns 10.56.0.20 --expect-state "$fingerprint" >/dev/null
on_router "uci del_list dhcp.lan.dhcp_option='6,10.56.0.20' && uci add_list dhcp.lan.dhcp_option='6,10.56.0.99' && uci commit dhcp"
expect_exit 5 admin rollback
test "$(on_router 'uci -q get dhcp.lan.dhcp_option')" = "42,10.56.0.1 6,10.56.0.99"
echo "matrix: rollback refused after a manual change"
echo "OpenWrt adapter: integration matrix passed"
