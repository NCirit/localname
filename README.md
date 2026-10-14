# localname

`localname` gives devices on a home network memorable names such as `nas.home.arpa`.

Build with Rust 1.88 or newer:

```console
cargo build --release
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

The CLI supports IPv4/IPv6 address records, local aliases, reverse lookup, upstream forwarding, bounded caching, live record reload, previews, and revision rollback. Use `--config PATH` to select a configuration file and `--output json` for automation.

```console
localname add storage nas --dry-run --output json
localname add storage nas --expect-revision 1 --output json
localname list
localname rollback 0
```

Configuration backups are stored beside the configuration file. `rollback N` restores the contents of revision N as a new revision. Listener changes require restarting the server.

Agents can use the bundled `skills/localname` skill. `localname skill --output json` returns the version-matched instructions, a generated reference for every command, and the output schema. `localname schema` prints the schema separately.

Development checks:

```console
cargo fmt --check
cargo clippy --locked --all-targets -- -D warnings
cargo test --locked --all-targets
cargo run --release --example benchmark
```

The benchmark uses 10,000 records and 20,000 UDP queries, paced at 10,000 queries/second by default. Set `LOCALNAME_BENCH_RATE=0` for a throughput run. Results describe the machine where the test runs; they are not a guarantee for every router or host.

This is an early development release. Automated router configuration, operating-system DNS integration, service proxying, and trusted HTTPS are still being implemented.

