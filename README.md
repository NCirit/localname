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

For home-network setup, run `localname setup` to inspect the network and show the proposed server address. `localname setup --apply` writes the configuration. Start the server, reserve its address in your router, then set the router's LAN/DHCP DNS server to that address. Port 53 must be available and the host firewall must permit DNS over UDP and TCP from your LAN. The setup command currently provides guidance; it does not install a service or change your router.

Alternatively, run a persistent container service. Replace the address below with this host's private LAN address:

```console
export LOCALNAME_LAN_IP=192.168.1.10
docker compose up --build -d
docker compose exec localname localname --config /var/lib/localname/config.toml add nas 192.168.1.20
```

Set your router's LAN/DHCP DNS server to `LOCALNAME_LAN_IP`, then reconnect a second device and check `nslookup nas.home.arpa`. The container publishes both DNS transports on the selected LAN address, runs without root or extra capabilities, and keeps configuration in a named volume. Host port 53 must be free. If the Docker subnet `172.30.55.0/24` overlaps an existing network, change the subnet and container address together in `compose.yml` and update the persisted listener address with the service stopped.

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
```

The benchmark starts the release binary as a separate server with 10,000 records and sends 20,000 UDP queries paced at 10,000 queries/second. Set `LOCALNAME_BENCH_RATE=0` for a throughput run. CI enforces these budgets on x86-64 and ARM64: p99 at most 5 ms, server memory at most 64 MiB, release binary at most 10 MiB. Results describe the machine where the test runs; they are not a guarantee for every router or host.

DNS behavior is pinned by `tests/fixtures/conformance.toml`, which runs every case over UDP and TCP.

This is an early development release. Automated router configuration, operating-system DNS integration, service proxying, and trusted HTTPS are still being implemented.

