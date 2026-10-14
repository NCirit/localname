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

Short names expand beneath the configured zone (`home.arpa` by default); read the zone from status rather than assuming it for existing installations. `add NAME TARGET` also supports aliases to another configured local name. Use an IP address rather than a port-bearing URL for device records.

`localname rollback N` restores the contents of revision N as a new revision. It restores the whole configuration rather than one record, so list candidates with `localname revisions --output json`, preview with `localname rollback N --dry-run --output json` (it reports `records_added` and `records_removed`), then apply with `--expect-revision CURRENT`.

`localname status --output json` reports `data.daemon` (served revision and aggregate counters) when the server runs. A warning that the daemon serves a different revision than the file means a reload was rejected; run `localname diagnose`.

## Setup and diagnosis

- `localname setup` inspects the network and displays guidance. `setup --apply` writes localname configuration; it does not install a system service or change router settings.
- For an unprivileged local trial, use `localname setup --local --apply`, then `localname serve`. This listens on loopback port 5354 and does not provide whole-network naming.
- For failures, run `localname diagnose --output json` before changing configuration. Distinguish configuration validity, listener health, LAN reachability, and client resolver selection.
- A loopback answer proves only local operation. Verify from a second device before claiming a home network is integrated.
- Router DNS, DHCP authority, OS resolver, firewall, and trust-store changes need the user's authorization for the exact affected targets. The CLI's current guidance does not authorize unrelated changes.
- Keep `.local` for multicast DNS and use `home.arpa` for ordinary LAN records. Preserve VPN and enterprise resolver settings unless the user explicitly includes them.
- Proxy routing and trusted HTTPS are not available in this release. Do not invent service or certificate commands.
