---
name: localname
description: Manage LAN device names with the localname DNS CLI — add, remove, alias, roll back, set up, verify, diagnose, and configure its proxy, HTTPS, router, and client modes. Not for public DNS.
---

# Localname

Pass `--output json` on every command and the user's `--config PATH` if given. Success needs exit code 0 and `ok: true`; envelope fields are `ok`, `changed`, `revision`, `data`, `warnings`, `verification`, `rollback`, `error`. Exact flags: `localname skill --output json` (command reference) and `localname schema`. Start with `localname version`.

## Records

1. Read `localname status` (zone, served revision) and `localname list`. Never assume the zone: `lan` is the default, older setups often use `home.arpa`.
2. Preview: `localname add NAME TARGET --dry-run` or `localname remove NAME --dry-run` (`--value VALUE` removes one address).
3. Apply with `--expect-revision N` from step 1. On CONFLICT, re-read and check that the change still applies.
4. If `verification.status` is `passed`, the running daemon serves the change; `not_running` means only the file changed. Exit 7 `VERIFICATION_FAILED` means committed but not observed: report it and offer `rollback`.
5. Report the full name, new revision, verification scope, and the rollback command.

Names follow zone-file rules: `printer.office` → `printer.office.lan.`; an external alias target needs a trailing dot (`tv.example.com.`); a local alias target must exist. Use IP addresses, not URLs. `localname rollback N` restores the whole revision N as a new revision: pick one with `localname revisions`, preview with `--dry-run` (`records_added`/`records_removed`), apply with `--expect-revision`. Before a risky change, offer `localname backup create --out FILE`; restore with `localname backup restore FILE --dry-run` first. If the daemon serves a different revision than the file, a reload was rejected: run `localname diagnose`.

## Setup and diagnosis

- `localname setup` only inspects. Show `data.checks` (`pass|info|warn|fail` plus `remedy`), and show `data.router_action.steps` verbatim; the user makes router changes, so never claim one was made. A `fail` blocks `--apply`. `setup --apply` writes config only; it never installs a service or touches the router. `setup rollback --dry-run`, then `setup rollback`, undoes it.
- Local trial without privileges: `localname setup --local --apply`, then `localname serve` (loopback, port in `data.listen`). Loopback answers prove only local operation.
- Claim whole-network integration only after `localname setup verify` passes on a second device. On the server itself the scope is `this_host`.
- OpenWrt: `localname router plan --host ROUTER`, show `changes`, then after approval `router apply --host ROUTER --expect-state FINGERPRINT`. CONFLICT means re-plan. Never ask for router passwords; pass `--accept-new-host-key` only if the user says the network is trusted.
- Per-device fallback: `localname client setup --server ADDR` previews; `--apply` needs root or admin. The `preserved` check must pass. `client rollback` undoes it, and a foreign zone config is never overwritten.
- On failures, run `localname diagnose` before changing anything.
- Router, DHCP, OS resolver, firewall, and trust-store changes need the user's approval for the exact target. Keep `.local` for mDNS. Keep VPN and enterprise DNS as they are.

## Proxy and HTTPS (opt-in)

- Port-free URLs: stop the service, run `localname proxy enable`, restart, then `localname service add NAME HOST:PORT`. An unreachable-backend warning means routing works but the backend is down; report it, don't retry.
- HTTPS: run `localname https plan --mode local-ca|acme-dns01` and show `data.steps` before `https apply`. ACME needs a domain the user owns, their DNS-01 hook, and `--agree-tos` only after they accept the CA's terms. Run `https trust install|remove --yes` only after the user approves the `--dry-run` output. Never read, copy, or print the `.tls` key directory, and backups never include it. Confirm with `localname https verify`.
