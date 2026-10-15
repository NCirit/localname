# localname

`localname` gives devices on a home network memorable names such as `nas.home.arpa`.

Build with Rust 1.88 or newer:

```console
cargo build --release
cargo install --locked --path .
```

Try an instance on your computer without changing network settings:

```console
localname setup --local --apply
localname add nas 192.168.1.20
localname serve
```

In another terminal:

```console
localname resolve nas
localname status
localname diagnose --output json
```

For home-network setup, run `localname setup`. It inspects this host — LAN address, port 53, IPv6, VPNs, firewall, and the current resolvers — and prints each check, the one router change to make, and how to verify it. When port 53 is taken it names the program holding it; when a firewall is active it prints the exact command that allows DNS from your LAN. `localname setup --apply` writes the configuration and adds `localname.home.arpa` for this host. Then:

1. Start the server (`localname serve` or the service below).
2. On the router's LAN/DHCP page, set the DNS server handed to devices to the address setup shows, and leave the secondary DNS server empty. Setup lists the exact steps, including reserving the address and the IPv6 DNS setting when your network needs them.
3. Reconnect a second device and run `localname setup verify` on it. It finds localname through that device's DNS settings and checks UDP, TCP, and the system resolver. Without localname on that device, `nslookup localname.home.arpa` must return the server's address.

`localname setup rollback` restores what existed before `--apply` and tells you how to set the router back. `localname setup` never changes the router itself; see `localname router` below for OpenWrt. In a container, pass `--listen` with the container address and `--advertise` with the host's LAN address; `--upstream` selects resolvers when the detected ones are unsuitable.

On an OpenWrt router, localname can make the router change itself over SSH, using your own SSH keys or agent; it never stores router credentials:

```console
localname router plan --host 192.168.1.1
localname router apply --host 192.168.1.1 --expect-state FINGERPRINT
localname router status --host 192.168.1.1
localname router rollback --host 192.168.1.1
```

`plan` shows the exact UCI changes: DHCP option 6 on the LAN set to this host, every other DHCP option kept, and IPv6 DNS announcements pointed at localname's unique-local address or turned off. `apply` refuses if the router's DHCP configuration changed since the plan, commits the change so it survives reboots, and checks that dnsmasq serves it. The values it replaced are saved beside the configuration, and `rollback` restores them exactly — unless someone changed the router since, in which case it refuses. Connect once with `ssh root@192.168.1.1` to verify the host key, or pass `--accept-new-host-key` on a network you trust.

If the router cannot hand out a DNS server, point individual devices at localname instead. `localname client setup --server 192.168.1.10` shows the change; add `--apply` (with `sudo`, or in an administrator PowerShell on Windows) to make it. Only `home.arpa` queries go to localname, through each system's split-DNS mechanism: a systemd-resolved drop-in on Linux, `/etc/resolver/home.arpa` on macOS, and a Name Resolution Policy Table rule on Windows. VPN DNS, other interfaces, and search domains stay as they were; the command compares them before and after and fails if anything else changed. `localname client rollback` removes the change, and `localname client status` shows the current state. On Linux this requires systemd-resolved.

Answers forwarded from the Internet that point a public name at a private, loopback, or link-local address are dropped (DNS rebinding protection). Setup exempts the router's own domain, such as `lan`; list others in `rebind_allowed_domains`. localname also answers Firefox's DNS-over-HTTPS canary domain so Firefox keeps using network DNS and local names; set `firefox_doh_canary = false` to turn that off.

On Linux with systemd, install the hardened service unit from `packaging/systemd`. It runs as a dedicated `localname` account that keeps only the capability to bind port 53, and stores configuration and revisions in `/var/lib/localname`:

```console
sudo install -m 0755 target/release/localname /usr/bin/localname
sudo install -m 0644 packaging/systemd/localname.service /usr/lib/systemd/system/
sudo install -m 0644 packaging/systemd/localname.sysusers /usr/lib/sysusers.d/localname.conf
sudo install -m 0644 packaging/systemd/localname.tmpfiles /usr/lib/tmpfiles.d/localname.conf
sudo systemd-sysusers && sudo systemd-tmpfiles --create
export LOCALNAME_CONFIG=/var/lib/localname/config.toml
sudo -E -u localname localname setup --apply
sudo systemctl enable --now localname
sudo -E localname add nas 192.168.1.20
```

Administrators (root) can change records while the service runs; changes made while it is stopped keep the files owned by the service account.

Alternatively, run a persistent container service. Replace the address below with this host's private LAN address:

```console
export LOCALNAME_LAN_IP=192.168.1.10
docker compose up --build -d
docker compose exec localname localname --config /var/lib/localname/config.toml add nas 192.168.1.20
```

Set your router's LAN/DHCP DNS server to `LOCALNAME_LAN_IP`, then reconnect a second device and check `nslookup nas.home.arpa`. The container publishes both DNS transports on the selected LAN address, runs without root or extra capabilities, and keeps configuration in a named volume. Host port 53 must be free. If the Docker subnet `172.30.55.0/24` overlaps an existing network, change the subnet and container address together in `compose.yml` and update the persisted listener address with the service stopped.

### Optional service proxy

DNS maps names to addresses, not ports. To reach `http://photos.home.arpa/` instead of `http://192.168.1.20:2342/`, turn on the HTTP/WebSocket proxy while the service is stopped, then add services:

```console
localname proxy enable                      # port 80 on the DNS listener address
localname serve                             # or restart the installed service
localname service add photos 192.168.1.20:2342
localname service list
localname service remove photos
```

A service name resolves to the proxy, which routes requests by their `Host` header and passes WebSocket upgrades through. Backends must be on private addresses; only clients in `allowed_clients` may use the proxy. The proxy is off by default: without `proxy_listen`, localname opens no HTTP port and starts no proxy task, and `cargo build --no-default-features` leaves the proxy out entirely. `localname proxy disable` returns to DNS-only mode once no services remain. For HTTPS, see below.

When a backend fails, the proxy answers with a short plain-text error naming the service and backend:

| Situation | Response |
| --- | --- |
| No service has the requested name | 404 Not Found |
| Request without a `Host` header | 400 Bad Request |
| Client outside `allowed_clients` | 403 Forbidden |
| Backend refuses or resets the connection | 502 Bad Gateway |
| Backend does not accept within 5 s, or sends no response headers within 60 s | 504 Gateway Timeout |
| Backend fails while sending a response | The client connection is closed |

`localname service add` checks that the name resolves to the proxy and that the proxy routes it; an unreachable backend is reported as a warning. `localname status` shows aggregate proxy counters.

### HTTPS for services

HTTPS needs someone to vouch for the certificate, and localname never decides that silently. Pick one trust mode:

- **Local CA** (`--mode local-ca`) — for `home.arpa` and other private zones. localname creates a CA on this host that can only sign names under your zone (an X.509 name constraint), so trusting it cannot vouch for any public site. Its private key stays in an owner-only directory beside the configuration and is never printed, exported, or copied; `localname https ca-cert` gives you only the public certificate to install on phones and other computers.
- **ACME DNS-01** (`--mode acme-dns01`) — for a domain you own, such as `home.example.com` used as the zone. Certificates come from Let's Encrypt (or `--acme-directory`) and are trusted everywhere. You supply a hook program that localname runs as `HOOK set|clear _acme-challenge.NAME VALUE` to publish TXT records with your DNS provider; provider credentials stay with the hook. You must pass `--agree-tos` to accept the CA's terms.

```console
localname https plan --mode local-ca            # shows every change; changes nothing
sudo systemctl stop localname
localname https apply --mode local-ca
sudo systemctl start localname
localname https verify                          # TLS handshake per service against the CA
sudo localname https trust install --dry-run    # shows the exact trust-store command
sudo localname https trust install              # asks you to type "yes" (or pass --yes)
localname https ca-cert --out home-ca.crt       # public certificate for other devices
```

Services listed with `--service` (default: all) are served on port 443 of the proxy address; plain HTTP requests for them redirect to HTTPS. Certificates last 90 days (local CA) or the ACME CA's lifetime, renew 30 days before expiry, and survive restarts; `localname https renew` renews immediately and `localname https status` shows expiry and the last error. Trust-store changes happen only through `https trust install` and `https trust remove` — on Linux the system store (`update-ca-certificates` or `update-ca-trust`), on macOS the login keychain, on Windows the current user's root store, which shows its own confirmation dialog. Firefox keeps a separate store. `localname https rollback` restores the configuration from before `https apply` and deletes the keys and certificates it created; it refuses while the CA is still trusted on this host.

The CLI supports IPv4/IPv6 address records, local aliases, reverse lookup, upstream forwarding, bounded caching, live record reload, previews, and revision rollback. Use `--config PATH` to select a configuration file and `--output json` for automation.

Names follow zone-file rules: `printer.office` means `printer.office.home.arpa`, and a trailing dot marks a name outside the zone, so an alias to an external host is written `localname add tv roku.example.com.`. Aliases to local names must point at a name that exists.

localname answers `localhost`, `invalid`, and private reverse lookups (`192.168.x.x`, `10.x.x.x`, ULA and link-local IPv6) itself and never sends them, `home.arpa`, or `.local` names to public resolvers; when an upstream is on your LAN (such as the router), those queries go only to it.

To choose a different namespace during first setup, use `localname setup --zone dev.test --local --apply` for a development instance, or provide a domain you control for home-network setup. Short names are expanded under the configured zone.

```console
localname add storage nas --dry-run --output json
localname add storage nas --expect-revision 1 --output json
localname remove nas --value fd00::20
localname list
localname revisions
localname rollback 0 --dry-run
localname rollback 0
```

Configuration backups are stored beside the configuration file. `rollback N` restores the contents of revision N as a new revision; `--dry-run` shows which records it would add and remove. With a running server, each change is read back from the listener: the zone's SOA serial must equal the new revision and the record must (or must no longer) resolve. Listener changes require restarting the server.

While the server runs, record changes go through its local control endpoint: an owner-only Unix socket on Linux and macOS, or a local named pipe on Windows. Only the daemon's own account (or an administrator) can use it. When the server is stopped, the CLI edits the configuration directly under a lock. `localname status` reports the served revision and aggregate query counters; localname does not keep query history.

Agents can use the bundled `skills/localname` skill. `localname skill --output json` returns the version-matched instructions, a generated reference for every command, and the output schema. `localname schema` prints the schema separately.

To serve port 53 without running as root, either grant the binary the bind capability (`sudo setcap cap_net_bind_service=+ep "$(command -v localname)"`), or start it as root with `localname serve --user localname`: it binds its listeners, then permanently switches to that account before reading any query. The configuration directory must be writable by that account.

Development checks:

```console
cargo fmt --check
cargo clippy --locked --all-targets -- -D warnings
cargo test --locked --all-targets
cargo build --release && cargo run --release --example benchmark
docker compose -f tests/network/compose.yml up --build --abort-on-container-exit --exit-code-from client
docker compose -f tests/network/setup.yml up --build --abort-on-container-exit --exit-code-from client
```

`tests/network/setup.yml` runs whole-home setup on an isolated network: a dnsmasq router applies only the plan's router action, and a second device takes a DHCP lease and runs `localname setup verify`.

The benchmark starts the release binary as a separate server with 10,000 records and sends 20,000 UDP queries paced at 10,000 queries/second. Set `LOCALNAME_BENCH_RATE=0` for a throughput run. CI enforces these budgets on x86-64 and ARM64: p99 at most 5 ms, server memory at most 64 MiB, release binary at most 10 MiB. Results describe the machine where the test runs; they are not a guarantee for every router or host.

DNS behavior is pinned by `tests/fixtures/conformance.toml`, which runs every case over UDP and TCP.

This is an early development release.

