//! Linux agent: HTTP server wrapping a registry backend, mirror of the Windows
//! agent. Implements the Agent HTTP Protocol from CONTRACTS.md.
//!
//! Usage:
//!   libreg-agent-linux [--port 7878] [--backend-id libreg-0.1.0]
//!
//! Every response is the contract envelope:
//!   { "ok": bool, "error": null | string, "data": ..., "code": <on error> }

mod backend;
mod canonical;
mod error;
mod handlers;
mod model;

use backend::{Backend, MemBackend};
use serde_json::{json, Value as J};
use std::sync::Arc;

struct Config {
    port: u16,
    backend_id: String,
}

fn parse_args() -> Config {
    let mut port = 7878u16;
    let mut backend_id = "libreg-0.1.0".to_string();
    let mut args = std::env::args().skip(1);
    while let Some(arg) = args.next() {
        match arg.as_str() {
            "--port" => {
                port = args
                    .next()
                    .and_then(|s| s.parse().ok())
                    .unwrap_or_else(|| fatal("--port needs a number"));
            }
            "--backend-id" => {
                backend_id = args.next().unwrap_or_else(|| fatal("--backend-id needs a value"));
            }
            "-h" | "--help" => {
                eprintln!("libreg-agent-linux [--port N] [--backend-id ID]");
                std::process::exit(0);
            }
            other => fatal(&format!("unknown argument: {other}")),
        }
    }
    Config { port, backend_id }
}

fn fatal(msg: &str) -> ! {
    eprintln!("error: {msg}");
    std::process::exit(2);
}

fn main() {
    let cfg = parse_args();
    let addr = format!("0.0.0.0:{}", cfg.port);
    let server = match tiny_http::Server::http(&addr) {
        Ok(s) => Arc::new(s),
        Err(e) => fatal(&format!("cannot bind {addr}: {e}")),
    };
    let backend: Arc<dyn Backend> = Arc::new(MemBackend::new(cfg.backend_id.clone()));
    eprintln!(
        "libreg-agent-linux listening on {addr} (agent=linux, protocol={}, backend={})",
        canonical::FORMAT_VERSION,
        cfg.backend_id
    );

    let worker_count = 4;
    let mut workers = Vec::with_capacity(worker_count);
    for _ in 0..worker_count {
        let server = server.clone();
        let backend = backend.clone();
        workers.push(std::thread::spawn(move || worker_loop(server, backend)));
    }
    for w in workers {
        let _ = w.join();
    }
}

fn worker_loop(server: Arc<tiny_http::Server>, backend: Arc<dyn Backend>) {
    loop {
        let mut req = match server.recv() {
            Ok(r) => r,
            Err(_) => break,
        };
        // Path without query string.
        let url = req.url().to_string();
        let path = url.split('?').next().unwrap_or("").to_string();

        let mut raw = String::new();
        let _ = req.as_reader().read_to_string(&mut raw);

        let (status, payload) = handle_request(backend.as_ref(), &path, &raw);
        let data = serde_json::to_string(&payload).unwrap_or_else(|_| "{}".to_string());
        let header =
            tiny_http::Header::from_bytes(&b"Content-Type"[..], &b"application/json"[..]).unwrap();
        let response = tiny_http::Response::from_string(data)
            .with_status_code(status)
            .with_header(header);
        let _ = req.respond(response);
    }
}

/// Returns (http_status, envelope_json).
fn handle_request(backend: &dyn Backend, path: &str, raw_body: &str) -> (u16, J) {
    // Empty body is treated as an empty object so endpoints with no params work.
    let body: J = if raw_body.trim().is_empty() {
        json!({})
    } else {
        match serde_json::from_str(raw_body) {
            Ok(v) => v,
            Err(e) => {
                return (
                    400,
                    json!({
                        "ok": false,
                        "error": format!("invalid JSON body: {e}"),
                        "code": "INTERNAL",
                        "data": J::Null,
                    }),
                );
            }
        }
    };

    match handlers::dispatch(backend, path, &body) {
        Ok(data) => (200, json!({ "ok": true, "error": J::Null, "data": data })),
        Err(err) => {
            // Unknown endpoint is the one case we map to HTTP 404; everything
            // else is a logical error carried in the 200 envelope so the
            // harness reads `code` uniformly.
            let status = if path_is_known(path) { 200 } else { 404 };
            (
                status,
                json!({
                    "ok": false,
                    "error": err.message,
                    "code": err.code.as_str(),
                    "data": J::Null,
                }),
            )
        }
    }
}

fn path_is_known(path: &str) -> bool {
    matches!(
        path,
        "/version"
            | "/hive/create"
            | "/hive/load"
            | "/hive/save"
            | "/hive/close"
            | "/key/create"
            | "/key/delete"
            | "/key/rename"
            | "/key/list"
            | "/key/info"
            | "/value/set"
            | "/value/delete"
            | "/value/get"
            | "/key/security"
            | "/hive/dump"
            | "/hive/checksum"
            | "/hive/validate"
    )
}
