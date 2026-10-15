//! DNS data plane: immutable zone snapshots, the server, forwarding, and a stub client.

mod client;
mod forward;
mod pool;
mod server;
pub mod special;

use std::{
    collections::HashMap,
    net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr},
    str::FromStr,
    sync::atomic::{AtomicU64, Ordering},
    time::Duration,
};

use anyhow::{Context, Result};
use hickory_proto::{
    op::{Edns, Message, ResponseCode},
    rr::{
        Name, RData, Record, RecordType,
        rdata::{A, AAAA, CNAME, PTR, SOA},
    },
};
use serde::{Deserialize, Serialize};

pub use client::{Answer, QueryResult, Transport, query_server, query_with};
pub use server::{DnsServer, Listeners};

use crate::config::{Config, RecordConfig, is_private_address, name_in_zone};

pub(crate) const MAX_UDP_PACKET: usize = 4096;
pub(crate) const MAX_TCP_PACKET: usize = u16::MAX as usize;
const MAX_CNAME_CHAIN: usize = 16;

/// Data for one owner name. Kept compact; wire records are built per answer.
#[derive(Clone, Debug, Default)]
struct NameEntry {
    v4: Vec<(Ipv4Addr, u32)>,
    v6: Vec<(Ipv6Addr, u32)>,
    alias: Option<(Box<str>, u32)>,
    pointers: Vec<(Box<str>, u32)>,
}

impl NameEntry {
    fn records(&self, owner: &Name, kind: RecordType) -> Result<Vec<Record>> {
        let mut records = Vec::new();
        if matches!(kind, RecordType::A | RecordType::ANY) {
            records.extend(self.v4.iter().map(|(address, ttl)| {
                Record::from_rdata(owner.clone(), *ttl, RData::A(A(*address)))
            }));
        }
        if matches!(kind, RecordType::AAAA | RecordType::ANY) {
            records.extend(self.v6.iter().map(|(address, ttl)| {
                Record::from_rdata(owner.clone(), *ttl, RData::AAAA(AAAA(*address)))
            }));
        }
        if matches!(kind, RecordType::CNAME | RecordType::ANY)
            && let Some((target, ttl)) = &self.alias
        {
            records.push(Record::from_rdata(
                owner.clone(),
                *ttl,
                RData::CNAME(CNAME(Name::from_str(target)?)),
            ));
        }
        if matches!(kind, RecordType::PTR | RecordType::ANY) {
            for (target, ttl) in &self.pointers {
                records.push(Record::from_rdata(
                    owner.clone(),
                    *ttl,
                    RData::PTR(PTR(Name::from_str(target)?)),
                ));
            }
        }
        Ok(records)
    }
}

/// Everything the query path needs, built once per configuration revision and swapped
/// atomically, so queries never observe a partially applied change.
#[derive(Clone)]
pub struct DnsSnapshot {
    revision: u64,
    zone_text: String,
    /// Configured names, their reverse names, and empty non-terminals (empty entries).
    names: HashMap<Box<str>, NameEntry>,
    soa: Record,
    allowed_clients: Vec<ipnet::IpNet>,
    upstreams: Vec<SocketAddr>,
    upstream_timeout: Duration,
    cache_entries: usize,
    rebind_protection: bool,
    rebind_allowed_domains: Vec<String>,
    firefox_doh_canary: bool,
}

impl DnsSnapshot {
    pub fn from_config(config: &Config) -> Result<Self> {
        let zone = Name::from_str(&config.zone).context("invalid zone")?;
        let mut names: HashMap<Box<str>, NameEntry> =
            HashMap::with_capacity(config.records.len() * 2);
        let mut owners: Vec<&str> = Vec::with_capacity(config.records.len());
        for entry in &config.records {
            insert_record(&mut names, entry);
            owners.push(&entry.name);
        }
        // Service names resolve to the proxy, which routes them by Host header.
        for service in &config.services {
            let entry = names.entry(service.name.as_str().into()).or_default();
            for listen in &config.proxy_listen {
                match listen.ip() {
                    IpAddr::V4(v4) if !entry.v4.iter().any(|(ip, _)| *ip == v4) => {
                        entry.v4.push((v4, 60));
                    }
                    IpAddr::V6(v6) if !entry.v6.iter().any(|(ip, _)| *ip == v6) => {
                        entry.v6.push((v6, 60));
                    }
                    _ => {}
                }
            }
            owners.push(&service.name);
        }
        for owner in owners {
            // Empty non-terminals exist (NODATA, not NXDOMAIN) per RFC 8020.
            let mut parent = owner;
            while let Some((_, next)) = parent.split_once('.') {
                if !name_in_zone(next, &config.zone) {
                    break;
                }
                names.entry(next.into()).or_default();
                parent = next;
            }
        }
        names.shrink_to_fit();
        let soa = soa_record(
            zone,
            &format!("ns1.{}", config.zone),
            &format!("hostmaster.{}", config.zone),
            u32::try_from(config.revision).unwrap_or(u32::MAX),
        )?;
        Ok(Self {
            revision: config.revision,
            zone_text: config.zone.clone(),
            names,
            soa,
            allowed_clients: config.allowed_clients.clone(),
            upstreams: config.upstreams.clone(),
            upstream_timeout: Duration::from_millis(config.upstream_timeout_ms),
            cache_entries: config.cache_entries,
            rebind_protection: config.rebind_protection,
            rebind_allowed_domains: config.rebind_allowed_domains.clone(),
            firefox_doh_canary: config.firefox_doh_canary,
        })
    }

    pub fn revision(&self) -> u64 {
        self.revision
    }

    fn is_local_name(&self, name: &str) -> bool {
        name_in_zone(name, &self.zone_text) || self.names.contains_key(name)
    }

    fn client_allowed(&self, address: IpAddr) -> bool {
        let address = canonical_ip(address);
        self.allowed_clients
            .iter()
            .any(|network| network.contains(&address))
    }

    /// Whether private addresses must be removed from forwarded answers for `name`.
    fn rebind_protected(&self, name: &str) -> bool {
        self.rebind_protection
            && !self
                .rebind_allowed_domains
                .iter()
                .any(|domain| name_in_zone(name, domain))
    }

    /// Upstreams on this host or LAN, which may receive locally served zones.
    fn private_upstreams(&self) -> Vec<SocketAddr> {
        self.upstreams
            .iter()
            .copied()
            .filter(|upstream| is_private_address(upstream.ip()))
            .collect()
    }
}

/// Dual-stack sockets report IPv4 peers as `::ffff:a.b.c.d`; compare them as IPv4.
fn canonical_ip(address: IpAddr) -> IpAddr {
    match address {
        IpAddr::V6(v6) => v6.to_ipv4_mapped().map_or(address, IpAddr::V4),
        IpAddr::V4(_) => address,
    }
}

fn soa_record(apex: Name, mname: &str, rname: &str, serial: u32) -> Result<Record> {
    Ok(Record::from_rdata(
        apex,
        60,
        RData::SOA(SOA::new(
            Name::from_str(mname)?,
            Name::from_str(rname)?,
            serial,
            3600,
            600,
            86_400,
            60,
        )),
    ))
}

/// Add one validated record. Values are canonical: addresses or absolute names.
fn insert_record(names: &mut HashMap<Box<str>, NameEntry>, entry: &RecordConfig) {
    let owner: Box<str> = entry.name.to_ascii_lowercase().into();
    let ttl = entry.ttl;
    match entry.value.parse::<IpAddr>() {
        Ok(address) => {
            let record = names.entry(owner.clone()).or_default();
            match address {
                IpAddr::V4(v4) => record.v4.push((v4, ttl)),
                IpAddr::V6(v6) => record.v6.push((v6, ttl)),
            }
            let reverse = names.entry(reverse_name(address).into()).or_default();
            if !reverse.pointers.iter().any(|(target, _)| *target == owner) {
                reverse.pointers.push((owner, ttl));
            }
        }
        Err(_) => {
            names.entry(owner).or_default().alias =
                Some((entry.value.to_ascii_lowercase().into(), ttl));
        }
    }
}

pub(crate) fn reverse_name(address: IpAddr) -> String {
    match address {
        IpAddr::V4(address) => {
            let octets = address.octets();
            format!(
                "{}.{}.{}.{}.in-addr.arpa.",
                octets[3], octets[2], octets[1], octets[0]
            )
        }
        IpAddr::V6(address) => {
            let nibbles = address
                .octets()
                .iter()
                .rev()
                .flat_map(|byte| [format!("{:x}", byte & 0x0f), format!("{:x}", byte >> 4)])
                .collect::<Vec<_>>()
                .join(".");
            format!("{nibbles}.ip6.arpa.")
        }
    }
}

/// Addresses a public name must not resolve to: reaching them lets a web page attack
/// devices on the LAN or this host (DNS rebinding).
fn is_rebinding_target(address: IpAddr) -> bool {
    let address = canonical_ip(address);
    is_private_address(address) || address.is_unspecified()
}

/// Remove rebinding targets from a forwarded answer. Returns `None` when nothing changed.
fn strip_private_answers(bytes: &[u8]) -> Result<Option<Vec<u8>>> {
    let mut message = Message::from_vec(bytes)?;
    let before = message.answers.len();
    message.answers.retain(|record| match &record.data {
        RData::A(A(address)) => !is_rebinding_target(IpAddr::V4(*address)),
        RData::AAAA(AAAA(address)) => !is_rebinding_target(IpAddr::V6(*address)),
        _ => true,
    });
    if message.answers.len() == before {
        return Ok(None);
    }
    Ok(Some(message.to_vec()?))
}

/// Aggregate health counters. Decision 11: no per-query history is retained.
#[derive(Default)]
pub(crate) struct Metrics {
    queries: AtomicU64,
    local: AtomicU64,
    forwarded: AtomicU64,
    cache_hits: AtomicU64,
    refused: AtomicU64,
    errors: AtomicU64,
    dropped: AtomicU64,
    loops: AtomicU64,
    rebind_blocked: AtomicU64,
}

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct MetricsSnapshot {
    pub queries: u64,
    pub local: u64,
    pub forwarded: u64,
    pub cache_hits: u64,
    pub refused: u64,
    pub errors: u64,
    #[serde(default)]
    pub dropped: u64,
    #[serde(default)]
    pub loops: u64,
    /// Forwarded answers from which private addresses were removed.
    #[serde(default)]
    pub rebind_blocked: u64,
}

impl Metrics {
    fn add(counter: &AtomicU64) {
        counter.fetch_add(1, Ordering::Relaxed);
    }

    pub(crate) fn cache_hit(&self) {
        Self::add(&self.cache_hits);
    }

    fn snapshot(&self) -> MetricsSnapshot {
        let load = |counter: &AtomicU64| counter.load(Ordering::Relaxed);
        MetricsSnapshot {
            queries: load(&self.queries),
            local: load(&self.local),
            forwarded: load(&self.forwarded),
            cache_hits: load(&self.cache_hits),
            refused: load(&self.refused),
            errors: load(&self.errors),
            dropped: load(&self.dropped),
            loops: load(&self.loops),
            rebind_blocked: load(&self.rebind_blocked),
        }
    }
}

fn response_to(request: &Message) -> Message {
    let mut response = Message::response(request.id, request.op_code);
    response.metadata.recursion_desired = request.recursion_desired;
    response.metadata.checking_disabled = request.checking_disabled;
    response.metadata.recursion_available = true;
    response.add_queries(request.queries.iter().cloned());
    if request.edns.is_some() {
        let mut edns = Edns::new();
        edns.set_max_payload(request.max_payload().clamp(512, 4096));
        response.set_edns(edns);
    }
    response
}

/// Authoritative answer for a name inside the configured zone or a configured reverse name.
fn local_response(request: &Message, snapshot: &DnsSnapshot) -> Result<Vec<u8>> {
    let query = &request.queries[0];
    let name = query.name().to_ascii().to_ascii_lowercase();
    let mut response = response_to(request);
    response.metadata.authoritative = true;
    if request.edns.is_some() && request.version() != 0 {
        response.metadata.response_code = ResponseCode::BADVERS;
        return Ok(response.to_vec()?);
    }

    let entry = snapshot.names.get(name.as_str());
    let exists = entry.is_some() || name == snapshot.zone_text;
    let owner = query.name();
    let requested = query.query_type();
    let mut answers =
        entry.map_or_else(|| Ok(Vec::new()), |entry| entry.records(owner, requested))?;
    if name == snapshot.zone_text && matches!(requested, RecordType::SOA | RecordType::ANY) {
        answers.push(snapshot.soa.clone());
    }
    if answers.is_empty() && !matches!(requested, RecordType::CNAME | RecordType::ANY) {
        // Follow local aliases so stub resolvers get the final address in one answer.
        let mut current = entry;
        let mut current_owner = owner.clone();
        for _ in 0..MAX_CNAME_CHAIN {
            let Some((target, ttl)) = current.and_then(|entry| entry.alias.as_ref()) else {
                break;
            };
            let target_name = Name::from_str(target)?;
            answers.push(Record::from_rdata(
                current_owner,
                *ttl,
                RData::CNAME(CNAME(target_name.clone())),
            ));
            current = snapshot.names.get(&**target);
            if let Some(next) = current {
                let found = next.records(&target_name, requested)?;
                if !found.is_empty() {
                    answers.extend(found);
                    break;
                }
            }
            current_owner = target_name;
        }
    }

    if answers.is_empty() {
        if !exists {
            response.metadata.response_code = ResponseCode::NXDomain;
        }
        response.add_authority(snapshot.soa.clone());
    } else {
        response.add_answers(answers);
    }
    response.to_vec().map_err(Into::into)
}

/// Loopback answers for `localhost.` (RFC 6761 §6.3).
fn localhost_response(request: &Message) -> Result<Vec<u8>> {
    let query = &request.queries[0];
    let mut response = response_to(request);
    response.metadata.authoritative = true;
    let name = query.name().clone();
    let data = match query.query_type() {
        RecordType::A => Some(RData::A(A(special::LOCALHOST_V4))),
        RecordType::AAAA => Some(RData::AAAA(AAAA(special::LOCALHOST_V6))),
        _ => None,
    };
    if let Some(data) = data {
        response.add_answer(Record::from_rdata(name, 3600, data));
    }
    response.to_vec().map_err(Into::into)
}

/// NXDOMAIN for a name in a locally served zone, with that zone's synthesized SOA.
fn nonexistent_response(request: &Message, apex: &str) -> Result<Vec<u8>> {
    let mut response = response_to(request);
    response.metadata.authoritative = true;
    response.metadata.response_code = ResponseCode::NXDomain;
    response.add_authority(soa_record(
        Name::from_str(apex)?,
        "localhost.",
        "nobody.invalid.",
        1,
    )?);
    response.to_vec().map_err(Into::into)
}

fn encode_error(request: &Message, code: ResponseCode) -> Result<Vec<u8>> {
    let mut response = response_to(request);
    response.metadata.recursion_available = false;
    response.metadata.response_code = code;
    response.to_vec().map_err(Into::into)
}

fn truncate_response(bytes: &[u8]) -> Result<Vec<u8>> {
    let response = Message::from_vec(bytes)?;
    response.truncate().to_vec().map_err(Into::into)
}

#[cfg(test)]
mod tests {
    use super::*;
    use hickory_proto::op::Query;

    pub(crate) fn config_with_record() -> Config {
        let mut config = Config::default();
        config.records.push(RecordConfig {
            name: "nas".into(),
            value: "192.168.1.20".into(),
            ttl: 60,
        });
        config.validate().unwrap();
        config
    }

    #[test]
    fn answers_local_a_and_ptr() {
        let snapshot = DnsSnapshot::from_config(&config_with_record()).unwrap();
        for (name, kind) in [
            ("nas.lan.", RecordType::A),
            ("20.1.168.192.in-addr.arpa.", RecordType::PTR),
        ] {
            let mut request = Message::query();
            request.add_query(Query::query(Name::from_str(name).unwrap(), kind));
            let bytes = local_response(&request, &snapshot).unwrap();
            let response = Message::from_vec(&bytes).unwrap();
            assert_eq!(response.response_code, ResponseCode::NoError);
            assert_eq!(response.answers.len(), 1);
            assert!(response.authoritative);
        }
    }

    #[test]
    fn duplicate_address_produces_one_ptr_per_name() {
        let mut config = config_with_record();
        config.records.push(RecordConfig {
            name: "nas".into(),
            value: "192.168.1.20".into(),
            ttl: 120,
        });
        config.validate().unwrap();
        let snapshot = DnsSnapshot::from_config(&config).unwrap();
        assert_eq!(
            snapshot.names["20.1.168.192.in-addr.arpa."].pointers.len(),
            1
        );
    }

    #[test]
    fn local_unknown_is_nxdomain() {
        let snapshot = DnsSnapshot::from_config(&config_with_record()).unwrap();
        let mut request = Message::query();
        request.add_query(Query::query(
            Name::from_str("missing.lan.").unwrap(),
            RecordType::A,
        ));
        let response = Message::from_vec(&local_response(&request, &snapshot).unwrap()).unwrap();
        assert_eq!(response.response_code, ResponseCode::NXDomain);
        assert_eq!(response.authorities.len(), 1);
    }

    #[test]
    fn local_cname_chain_includes_target_address() {
        let mut config = config_with_record();
        config.records.push(RecordConfig {
            name: "storage".into(),
            value: "nas".into(),
            ttl: 60,
        });
        config.validate().unwrap();
        let snapshot = DnsSnapshot::from_config(&config).unwrap();
        let mut request = Message::query();
        request.add_query(Query::query(
            Name::from_str("storage.lan.").unwrap(),
            RecordType::A,
        ));
        let response = Message::from_vec(&local_response(&request, &snapshot).unwrap()).unwrap();
        assert_eq!(response.answers.len(), 2);
        assert_eq!(response.answers[0].record_type(), RecordType::CNAME);
        assert_eq!(response.answers[1].record_type(), RecordType::A);
    }

    #[cfg(feature = "proxy")]
    #[test]
    fn service_names_resolve_to_the_proxy() {
        let mut config = config_with_record();
        config.proxy_listen = vec![
            "127.0.0.1:8080".parse().unwrap(),
            "127.0.0.1:8081".parse().unwrap(),
        ];
        config.services.push(crate::config::ServiceConfig {
            name: "photos.media".into(),
            target: "192.168.1.20:2342".parse().unwrap(),
            https: false,
        });
        config.validate().unwrap();
        let snapshot = DnsSnapshot::from_config(&config).unwrap();
        let entry = &snapshot.names["photos.media.lan."];
        assert_eq!(entry.v4, vec![("127.0.0.1".parse().unwrap(), 60)]);
        assert!(snapshot.names.contains_key("media.lan."));
    }

    #[test]
    fn ipv6_reverse_name_is_correct_length() {
        let name = reverse_name("2001:db8::1".parse().unwrap());
        assert!(name.ends_with(".ip6.arpa."));
        assert_eq!(name.matches('.').count(), 34);
    }

    #[test]
    fn rebinding_targets_are_removed_from_forwarded_answers() {
        let mut response = Message::response(7, hickory_proto::op::OpCode::Query);
        let owner = Name::from_str("evil.example.").unwrap();
        response.add_query(Query::query(owner.clone(), RecordType::A));
        for address in ["192.168.1.1", "93.184.216.34", "127.0.0.1", "0.0.0.0"] {
            response.add_answer(Record::from_rdata(
                owner.clone(),
                60,
                RData::A(A(address.parse().unwrap())),
            ));
        }
        response.add_answer(Record::from_rdata(
            owner.clone(),
            60,
            RData::AAAA(AAAA("::ffff:10.0.0.1".parse().unwrap())),
        ));
        let stripped = strip_private_answers(&response.to_vec().unwrap())
            .unwrap()
            .unwrap();
        let stripped = Message::from_vec(&stripped).unwrap();
        assert_eq!(stripped.answers.len(), 1);
        assert_eq!(
            stripped.answers[0].data,
            RData::A(A("93.184.216.34".parse().unwrap()))
        );
        let public = Message::from_vec(&stripped.to_vec().unwrap()).unwrap();
        assert!(
            strip_private_answers(&public.to_vec().unwrap())
                .unwrap()
                .is_none()
        );
    }

    #[test]
    fn rebinding_allowlist_uses_label_boundaries() {
        let mut config = config_with_record();
        config.rebind_allowed_domains = vec!["lan".into()];
        config.validate().unwrap();
        let snapshot = DnsSnapshot::from_config(&config).unwrap();
        assert!(!snapshot.rebind_protected("printer.lan."));
        assert!(snapshot.rebind_protected("printer.evillan."));
        config.rebind_protection = false;
        assert!(
            !DnsSnapshot::from_config(&config)
                .unwrap()
                .rebind_protected("x.example.")
        );
    }

    #[test]
    fn mapped_ipv4_clients_match_ipv4_networks() {
        let snapshot = DnsSnapshot::from_config(&config_with_record()).unwrap();
        assert!(snapshot.client_allowed("::ffff:127.0.0.1".parse().unwrap()));
        assert!(!snapshot.client_allowed("::ffff:8.8.8.8".parse().unwrap()));
    }
}
