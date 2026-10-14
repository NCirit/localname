pub mod config;
pub mod control;
pub mod dns;
pub mod integration;
pub mod output;

pub use config::{Config, ConfigStore, RecordConfig, ServiceConfig};
pub use dns::{DnsServer, DnsSnapshot, QueryResult, query_server};
