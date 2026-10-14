use serde::Serialize;
use serde_json::Value;

#[derive(Clone, Copy, Debug, clap::ValueEnum)]
pub enum OutputFormat {
    Human,
    Json,
}

#[derive(Debug, Serialize)]
pub struct Envelope<T: Serialize> {
    pub schema_version: &'static str,
    pub command: &'static str,
    pub ok: bool,
    pub changed: bool,
    pub revision: Option<u64>,
    pub data: T,
    pub warnings: Vec<String>,
    pub verification: Option<Value>,
    pub rollback: Option<String>,
    pub next_actions: Vec<String>,
    pub error: Option<ErrorBody>,
}

#[derive(Debug, Serialize)]
pub struct ErrorBody {
    pub code: &'static str,
    pub message: String,
}

impl<T: Serialize> Envelope<T> {
    pub fn success(command: &'static str, changed: bool, revision: Option<u64>, data: T) -> Self {
        Self {
            schema_version: "1",
            command,
            ok: true,
            changed,
            revision,
            data,
            warnings: Vec::new(),
            verification: None,
            rollback: None,
            next_actions: Vec::new(),
            error: None,
        }
    }
}
