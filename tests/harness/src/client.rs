//! HTTP client for an agent. The same client type drives both the Linux and
//! Windows agents; the harness treats them interchangeably (CONTRACTS.md).
//!
//! CONTRACTS.md specifies GET (with a JSON body) for read endpoints. ureq's
//! typed builder forbids bodies on GET, so reads go through `Agent::run` with a
//! hand-built `http::Request`, which sends the body faithfully. The agent is
//! configured to surface non-2xx responses as normal envelopes rather than
//! transport errors, so logical failures (`ok: false`) are always readable.

use http::Request;
use serde::Deserialize;
use serde_json::{json, Value};

pub struct Client {
    agent: ureq::Agent,
    base: String,
    pub name: String,
}

/// The standard response envelope from CONTRACTS.md.
#[derive(Debug, Clone, Deserialize)]
pub struct Envelope {
    pub ok: bool,
    #[serde(default)]
    pub error: Option<String>,
    #[serde(default)]
    pub code: Option<String>,
    #[serde(default)]
    pub data: Value,
}

#[derive(Debug, Clone, Deserialize)]
pub struct Handshake {
    pub agent: String,
    pub protocol: String,
    pub backend: String,
}

impl Client {
    pub fn new(name: impl Into<String>, host: &str, port: u16) -> Self {
        let config = ureq::Agent::config_builder()
            .http_status_as_error(false)
            .build();
        Client {
            agent: config.into(),
            base: format!("http://{host}:{port}"),
            name: name.into(),
        }
    }

    /// Send a request and parse the envelope. `method` is the contract method
    /// (GET or POST). Transport failures (connection refused, malformed
    /// envelope) are returned as `Err`; logical failures arrive as an
    /// `Envelope` with `ok: false`.
    pub fn call(&self, method: &str, path: &str, body: &Value) -> Result<Envelope, String> {
        let url = format!("{}{}", self.base, path);
        let payload = serde_json::to_string(body).map_err(|e| e.to_string())?;
        let req = Request::builder()
            .method(method)
            .uri(&url)
            .header("content-type", "application/json")
            .body(payload)
            .map_err(|e| format!("building request: {e}"))?;
        let mut resp = self
            .agent
            .run(req)
            .map_err(|e| format!("transport error to {} ({}): {e}", self.name, url))?;
        let text = resp
            .body_mut()
            .read_to_string()
            .map_err(|e| format!("reading response from {}: {e}", self.name))?;
        serde_json::from_str(&text)
            .map_err(|e| format!("bad envelope from {} for {path}: {e}; body was: {text}", self.name))
    }

    pub fn version(&self) -> Result<Handshake, String> {
        let env = self.call("GET", "/version", &json!({}))?;
        if !env.ok {
            return Err(format!("{} /version returned error: {:?}", self.name, env.error));
        }
        serde_json::from_value(env.data)
            .map_err(|e| format!("{} /version data malformed: {e}", self.name))
    }
}
