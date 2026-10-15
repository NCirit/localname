---
name: localname
description: Configure or diagnose names served by the localname LAN DNS tool, including adding device addresses and aliases, previewing changes, checking resolution, and restoring configuration revisions. Use for localname operations; public DNS hosting and router administration require their own tools.
---

# Localname

Use the installed CLI and its version-matched help. Run `localname version --output json` before operating an unfamiliar installation. If the binary is absent, build from the trusted project checkout with `cargo build --locked --release`; do not download an unverified installer.

Use the same `--config PATH` on every command when the user selects a configuration. Read `localname skill --output json` for the generated command reference and `localname schema` for the output schema. JSON output carries `ok`, `changed`, `revision`, `data`, `warnings`, `verification`, `rollback`, and `error`. Check both the exit code and `ok`.

## Add or remove a name

1. Inspect `localname status --output json` and `localname list --output json`.
2. Preview the requested change with `localname add NAME ADDRESS --dry-run --output json` or `localname remove NAME --dry-run --output json`. Use `remove NAME --value VALUE` to remove one address of a multi-address name.
3. Apply using `--expect-revision REVISION` from the inspected state. If it reports a stale revision, inspect the new state and determine whether the requested change still applies.
4. When the daemon is running, the command reads the change back itself: `verification.status` is `passed` only when the listener's SOA serial equals the new revision and the record resolves (or no longer resolves). `not_running` means only the configuration changed. Exit code 7 / `VERIFICATION_FAILED` means the change was committed but not observed; report it and offer the returned `rollback` command.
5. Report the fully qualified name, resulting revision, verification scope, and the returned rollback command, preserving the selected configuration path.

Short names expand beneath the configured zone (`home.arpa` by default); read the zone from status rather than assuming it for existing installations. `add NAME TARGET` also supports aliases: a local target must already exist, and an external target needs a trailing dot (`tv.example.com.`). Dotted names without a trailing dot are relative to the zone (`printer.office` → `printer.office.home.arpa.`). Use an IP address rather than a port-bearing URL for device records.

`localname rollback N` restores the contents of revision N as a new revision. It restores the whole configuration rather than one record, so list candidates with `localname revisions --output json`, preview with `localname rollback N --dry-run --output json` (it reports `records_added` and `records_removed`), then apply with `--expect-revision CURRENT`.

`localname status --output json` reports `data.daemon` (served revision and aggregate counters) when the server runs. A warning that the daemon serves a different revision than the file means a reload was rejected; run `localname diagnose`.

## Setup and diagnosis

- `localname setup --output json` only inspects. `data.checks` lists each finding with `status` (`pass`, `info`, `warn`, `fail`) and a `remedy`; `data.router_action` is the single router change, as exact `steps` plus a `restore` instruction; `data.verification` says how to confirm it. A `fail` check blocks `--apply` (exit 5 for port conflicts, 3 otherwise) and its remedy appears in `next_actions`.
- `localname setup --apply` writes localname configuration and records the prior state; `localname setup rollback --dry-run` then `setup rollback` restores it (it refuses with CONFLICT once later revisions exist). For an existing configuration, stop the service and pass `--expect-revision`. Setup never installs a service or changes the router.
- Show `router_action.steps` to the user verbatim. The user makes router changes; never claim one was made.
- Verify from a second device with `localname setup verify --output json`. It finds localname through that device's own DNS settings, which proves the router change took effect, and requires UDP, TCP, and system-resolver success; exit 7 / `VERIFICATION_FAILED` carries per-check remedies. On the server itself the scope is `this_host`, which proves only local operation.
- For an OpenWrt router, `localname router plan --host ROUTER --output json` lists the exact UCI `changes` and a state `fingerprint`; only after the user approves those changes, run `localname router apply --host ROUTER --expect-state FINGERPRINT --output json`. CONFLICT means the router changed since the plan: plan again and show the user. `router rollback` restores the captured values and refuses when the router was changed by hand after apply. SSH authentication is the user's own; never ask for or store router passwords, and do not pass `--accept-new-host-key` unless the user confirms the network is trusted.
- When the router cannot advertise localname, configure individual devices: `localname client setup --server ADDRESS --output json` previews; `--apply` (root or administrator) routes only the zone to localname and verifies through the system resolver. The `preserved` check must pass: it proves VPN DNS, other interfaces, and search domains are unchanged. `localname client rollback` undoes it. A foreign configuration for the zone is reported as CONFLICT and is never overwritten.
- For an unprivileged local trial, use `localname setup --local --apply`, then `localname serve`. This listens on loopback port 5354 and does not provide whole-network naming.
- For failures, run `localname diagnose --output json` before changing configuration. Distinguish configuration validity, listener health, LAN reachability, and client resolver selection.
- A loopback answer proves only local operation. Verify from a second device before claiming a home network is integrated.
- Router DNS, DHCP authority, OS resolver, firewall, and trust-store changes need the user's authorization for the exact affected targets. Setup's guidance does not authorize unrelated changes.
- Public answers pointing at private addresses are filtered (rebinding protection); a router domain that legitimately does this belongs in `rebind_allowed_domains`, which setup fills from the network's search domains.
- Keep `.local` for multicast DNS and use `home.arpa` for ordinary LAN records. Preserve VPN and enterprise resolver settings unless the user explicitly includes them.
- Proxy routing and trusted HTTPS are not available in this release. Do not invent service or certificate commands.
