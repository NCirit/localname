pub mod cli;
pub mod client;
pub mod config;
pub mod control;
pub mod dns;
pub mod error;
pub mod integration;
pub mod output;
pub mod privilege;
#[cfg(feature = "proxy")]
pub mod proxy;
pub mod router;

pub use config::{Config, ConfigStore, RecordConfig, ServiceConfig};
pub use dns::{
    DnsServer, DnsSnapshot, Listeners, QueryResult, Transport, query_server, query_with,
};
