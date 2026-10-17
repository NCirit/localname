# localname

`localname` gives devices on your home network memorable names such as `nas.lan`. It is a small DNS server for your LAN: it answers for your local names and forwards everything else to your usual resolvers.

**Contents:** [Install](#install) · [Quick start](#quick-start) · [Whole-home setup](#whole-home-setup) · [Run at startup](#run-at-startup) · [Managing names](#managing-names) · [Port-free URLs and HTTPS](#port-free-urls-and-https) · [AI agents](#ai-agents) · [Security](#security) · [Compatibility](#compatibility) · [Development](#development)

## Install

**From a release** (Linux x86-64/ARM64 `.deb`/`.rpm`, archives for Linux, macOS, and Windows, or the image `ghcr.io/ncirit/localname`). Each file ships with an SBOM, a SHA-256 checksum, a Sigstore bundle, and a provenance attestation (replace `VERSION`):

```console
gh attestation verify localname_VERSION_amd64.deb --repo NCirit/localname
sudo apt install ./localname_VERSION_amd64.deb
```

**From source** (Rust 1.88+):

```console
cargo install --locked --path .
```

## Quick start

Try it on your computer without touching network settings. The server listens on loopback only:

```console
localname setup --local --apply
localname add nas 192.168.1.20
localname serve
```

Then, in another terminal:

```console
localname resolve nas
localname status
```

## Whole-home setup

```console
localname setup             # inspect only: prints each check and the one router change
localname setup --apply     # write the configuration
```

`setup` checks the LAN address, port 53, IPv6, VPNs, the firewall, and current resolvers. For any problem it gives the exact fix (for example, which program holds port 53, or the firewall command to run). After `--apply`:

1. **Start the server:** run `localname serve`, or install it as a service so it starts at boot ([Run at startup](#run-at-startup)).
2. **Change the router:** set the DHCP DNS server to the address setup shows and leave the secondary DNS server empty. Setup lists the exact steps.
3. **Verify from another device:** run `localname setup verify` there, or check that `nslookup localname.lan` returns the server's address.

`localname setup rollback` undoes `--apply` and explains how to restore the router. In a container, pass `--listen` (container address) and `--advertise` (host LAN address).

**OpenWrt routers** can be changed for you over SSH, using your own keys; router credentials are never stored:

```console
localname router plan --host 192.168.1.1                            # shows the exact UCI changes
localname router apply --host 192.168.1.1 --expect-state FINGERPRINT
localname router rollback --host 192.168.1.1
```

`apply` refuses if the router changed since the plan. `rollback` restores the saved values exactly.

**No router access?** Point individual devices at localname instead. Only `.lan` queries go to it, so VPN and other DNS settings stay unchanged:

```console
localname client setup --server 192.168.1.10           # preview
sudo localname client setup --server 192.168.1.10 --apply
localname client rollback
```

This uses systemd-resolved on Linux, `/etc/resolver` on macOS, and an NRPT rule on Windows (run it from an administrator PowerShell).

## Run at startup

`localname daemon` makes localname a system service that starts at boot and restarts if it fails: systemd on Linux, launchd on macOS, and a Windows service on Windows. The service runs its own copy of the binary and always uses its platform's configuration:

| Platform | Service configuration | Runs as |
| --- | --- | --- |
| Linux | `/var/lib/localname/config.toml` | the `localname` account, with only the right to bind port 53 |
| macOS | `/Library/Application Support/localname/config.toml` | root (macOS reserves port 53 on LAN addresses for root) |
| Windows | `C:\ProgramData\localname\config.toml` | the `NT SERVICE\localname` virtual account |

```console
sudo localname --config /var/lib/localname/config.toml setup --apply   # once, with the path above
sudo localname daemon install               # preview
sudo localname daemon install --apply       # install, start, and check that it answers
localname daemon status
sudo localname daemon stop                  # also: daemon start
sudo localname daemon uninstall             # keeps the configuration
```

On Windows, run these in an administrator PowerShell without `sudo`. If `sudo` cannot find a binary installed by `cargo install`, use `sudo "$(command -v localname)"`. When you have no configuration of your own, commands such as `sudo localname add` use the service's configuration automatically. After upgrading localname, run `daemon install --apply` again to update the service's copy. The `.deb`/`.rpm` packages already ship the unit; `daemon install --apply` turns it on, upgrades restart it, removing the package keeps the data, and purging deletes it.

**Docker:** `compose.yml` runs a container that restarts automatically, without root or extra capabilities:

```console
export LOCALNAME_LAN_IP=192.168.1.10        # this host's LAN address; host port 53 must be free
docker compose up --build -d
docker compose exec localname localname --config /var/lib/localname/config.toml add nas 192.168.1.20
```

**Without a service manager:** grant the binary the capability (`sudo setcap cap_net_bind_service=+ep "$(command -v localname)"`), or start it as root with `localname serve --user localname`. It drops to that account after binding port 53.

## Managing names

```console
localname add nas 192.168.1.20              # A/AAAA record: nas.lan
localname add storage nas                   # alias to a local name
localname add tv roku.example.com.          # trailing dot = outside the zone
localname remove nas --value fd00::20       # remove one address
localname list
```

Every change creates a revision. Preview any change with `--dry-run`, and guard against concurrent edits with `--expect-revision N`. When the server is running, each change is read back from it to confirm it is served.

```console
localname revisions
localname rollback 3 --dry-run              # restores revision 3 as a new revision
localname backup create --out localname.backup
localname backup restore localname.backup --dry-run
localname config check                      # also: localname config show
localname diagnose
```

**Zones:** names live under `lan` by default. Choose another during first setup: `localname setup --zone home.arpa` (reserved for home networks, RFC 8375) or a domain you own (allows publicly trusted HTTPS). If your router already uses `.lan` for its own DHCP names, localname now answers for the whole zone, so add those devices to localname. `printer.office` means `printer.office.lan`.

## Port-free URLs and HTTPS

DNS maps names to addresses, not ports. The optional proxy lets you open `http://photos.lan/` instead of `http://192.168.1.20:2342/`:

```console
localname proxy enable                      # with the service stopped; then restart it
localname service add photos 192.168.1.20:2342
localname service list
```

The proxy routes HTTP and WebSocket traffic by the `Host` header, only to private backends and only for `allowed_clients`. It is off by default; `localname proxy disable` turns it off again once no services remain.

HTTPS needs a trust mode that you choose explicitly:

- **`local-ca`** for private zones (`lan`, `home.arpa`). It creates a CA restricted to your zone, so it can never vouch for public sites. Its key never leaves this host.
- **`acme-dns01`** for a domain you own. It uses Let's Encrypt with your DNS-provider hook and requires `--agree-tos`.

```console
localname https plan --mode local-ca        # shows every change, changes nothing
localname https apply --mode local-ca       # with the service stopped
localname https verify
sudo localname https trust install --dry-run
localname https ca-cert --out home-ca.crt   # install on phones and other computers
```

Certificates renew automatically 30 days before they expire. `localname https rollback` returns services to plain HTTP.

## AI agents

localname ships an agent skill (`skills/localname/SKILL.md`, also in every release archive) that teaches an agent the safe workflow: preview, apply with a revision guard, verify, and offer rollback. The binary prints the skill that matches its own version, so install it from there:

```console
# Claude Code (personal; use .claude/skills/ in a project for project scope)
mkdir -p ~/.claude/skills/localname && localname skill > ~/.claude/skills/localname/SKILL.md

# OpenAI Codex
mkdir -p ~/.codex/skills/localname && localname skill > ~/.codex/skills/localname/SKILL.md
```

Other agents can load the same file as instructions, or call `localname skill --output json` for the skill, a reference for every command, and the output schema (`localname schema` prints the schema alone). Re-run the install after upgrading localname.

## Security

- Records change only through the daemon's owner-only control socket (Unix) or named pipe (Windows), or by editing the file under a lock while the daemon is stopped.
- Public answers that point at private addresses are dropped (DNS rebinding protection). Exempt a domain with `rebind_allowed_domains`.
- `localhost`, `.local`, `home.arpa`, and private reverse lookups never go to public resolvers.
- No query history is kept; `localname status` shows only aggregate counters.
- Firefox's DoH canary is answered so Firefox keeps using local names (`firefox_doh_canary = false` disables this).
- Backups never contain TLS keys.

## Compatibility

From 1.0, localname follows semantic versioning. Within a major version, JSON output (schema version 1) only gains fields, error and exit codes keep their meaning, and commands and flags keep working, with deprecations warned for at least one minor release. Older configurations and backups are migrated automatically; newer ones are refused. Upgrades from 0.1.x or any 1.x by package, binary, or image are supported.

**Platforms:** Linux (x86-64, ARM64, systemd), macOS 13+, and Windows 10+. Client split DNS on Linux needs systemd-resolved.

## Development

```console
cargo fmt --check
cargo clippy --locked --all-targets -- -D warnings
cargo test --locked --all-targets
cargo build --release && cargo run --release --example benchmark
docker compose -f tests/network/setup.yml up --build --abort-on-container-exit --exit-code-from client
tests/packaging/run.sh && tests/packaging/container-upgrade.sh
```

CI enforces p99 ≤ 5 ms, server memory ≤ 64 MiB, and binary size ≤ 10 MiB on x86-64 and ARM64. DNS behavior is pinned by `tests/fixtures/conformance.toml`. GitHub workflows run only when started manually (Actions → Run workflow). For a release, push a `vX.Y.Z` tag and run **Release** from that tag.
