//! winreg-agent: HTTP server wrapping offreg.dll.
//!
//! The ground-truth oracle for libreg differential testing. Cross-compiled from
//! Linux for x86_64-pc-windows-gnu and run on the Windows VM as administrator.
//! See agents/windows/CLAUDE.md and the top-level CONTRACTS.md.

mod audit;
mod canonical;
mod error;
mod handlers;
mod offreg;
mod response;
mod sddl;
mod state;
mod time;
mod util;
mod valuec;
mod winapi;

use std::sync::Arc;

use serde_json::Value;
use tiny_http::{Header, Response, Server};

use crate::state::AppState;

struct Config {
    port: u16,
    bind: String,
    audit_path: String,
    backend: String,
    hive_os_major: u32,
    hive_os_minor: u32,
}

fn parse_args() -> Config {
    // Default 6.3 = Windows 8.1, which makes offreg write v1.5 hives (the
    // format the harness expects by default).
    let mut cfg = Config {
        port: 7879,
        bind: "0.0.0.0".to_string(),
        audit_path: "audit.log".to_string(),
        backend: "offreg-unknown".to_string(),
        hive_os_major: 6,
        hive_os_minor: 3,
    };
    let mut args = std::env::args().skip(1);
    while let Some(arg) = args.next() {
        match arg.as_str() {
            "--port" => {
                if let Some(v) = args.next() {
                    cfg.port = v.parse().unwrap_or(cfg.port);
                }
            }
            "--bind" => {
                if let Some(v) = args.next() {
                    cfg.bind = v;
                }
            }
            "--audit" => {
                if let Some(v) = args.next() {
                    cfg.audit_path = v;
                }
            }
            "--backend" => {
                if let Some(v) = args.next() {
                    cfg.backend = v;
                }
            }
            "--hive-os-major" => {
                if let Some(v) = args.next() {
                    cfg.hive_os_major = v.parse().unwrap_or(cfg.hive_os_major);
                }
            }
            "--hive-os-minor" => {
                if let Some(v) = args.next() {
                    cfg.hive_os_minor = v.parse().unwrap_or(cfg.hive_os_minor);
                }
            }
            other => eprintln!("ignoring unknown argument: {other}"),
        }
    }
    cfg
}

fn main() {
    let cfg = parse_args();

    if let Err(e) = offreg::init() {
        eprintln!("fatal: {e}");
        eprintln!("the agent cannot run without offreg.dll; install the Windows ADK Deployment Tools");
        std::process::exit(1);
    }
    audit::init(cfg.audit_path.clone());

    let state = Arc::new(AppState::new(
        cfg.backend.clone(),
        cfg.hive_os_major,
        cfg.hive_os_minor,
    ));
    let addr = format!("{}:{}", cfg.bind, cfg.port);
    let server = match Server::http(&addr) {
        Ok(s) => s,
        Err(e) => {
            eprintln!("fatal: could not bind {addr}: {e}");
            std::process::exit(1);
        }
    };
    println!("winreg-agent listening on {addr} (backend {})", cfg.backend);

    for mut request in server.incoming_requests() {
        let state = Arc::clone(&state);
        // One thread per request. offreg calls are serialized per hive handle
        // by the registry, so different handles can be served concurrently.
        std::thread::spawn(move || {
            let path = request.url().split('?').next().unwrap_or("/").to_string();

            let mut raw = String::new();
            let _ = request.as_reader().read_to_string(&mut raw);
            let body: Value = if raw.trim().is_empty() {
                Value::Object(Default::default())
            } else {
                match serde_json::from_str(&raw) {
                    Ok(v) => v,
                    Err(e) => {
                        let resp = response::fail(&error::AgentError::new(
                            "INTERNAL",
                            format!("invalid JSON body: {e}"),
                        ));
                        respond(request, &resp);
                        return;
                    }
                }
            };

            let resp = handlers::dispatch(&state, &path, &body);
            respond(request, &resp);
        });
    }
}

fn respond(request: tiny_http::Request, body: &Value) {
    let text = serde_json::to_string(body).unwrap_or_else(|_| "{\"ok\":false}".to_string());
    let header = Header::from_bytes(&b"Content-Type"[..], &b"application/json"[..])
        .expect("static header is valid");
    let response = Response::from_string(text).with_header(header);
    let _ = request.respond(response);
}
