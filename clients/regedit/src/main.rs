//! `regedit`: a web-based registry editor for offline hives.
//!
//! Unlike `reg` and `sc`, this is syntax equivalent rather than identical: it
//! is a browser UI that offers the same browsing and editing as Windows
//! regedit, plus features the core library exposes that Windows regedit does
//! not (raw security descriptors, hive structural validation, per-key data, and
//! `.reg` export of any subtree).
//!
//! It is a standalone server that links libreg through `cli-core`. Hives are
//! taken from the mount map, or a single `--hive FILE` can be mounted under a
//! chosen root. Each request opens the hive file, performs its operation, and
//! saves on mutation, so edits persist immediately.

mod http;
mod json;

use cli_core::error::CliResult;
use cli_core::mount::MountMap;
use cli_core::regfile;
use cli_core::session::Session;
use cli_core::value;
use http::{Request, Response};
use std::collections::HashMap;
use std::path::PathBuf;
use std::process::Command;
use std::sync::Arc;

const INDEX_HTML: &str = include_str!("../static/index.html");

/// One browsable root: a label shown in the UI and the hive file behind it.
#[derive(Clone)]
struct RootEntry {
    label: String,
    file: PathBuf,
}

struct AppState {
    roots: Vec<RootEntry>,
}

fn main() {
    let mut port = 7890u16;
    let mut bind_addr = "127.0.0.1".to_string();
    let mut hive_override: Option<PathBuf> = None;
    let mut override_label = "HKEY_LOCAL_MACHINE".to_string();
    // regedit is a desktop-style local tool, not a service: by default it opens
    // the UI in a browser once the server is listening. --no-browser suppresses
    // that (and we just print the URL to open by hand).
    let mut open_browser = true;

    let args: Vec<String> = std::env::args().skip(1).collect();
    let mut i = 0;
    while i < args.len() {
        match args[i].as_str() {
            "--port" => {
                i += 1;
                port = args.get(i).and_then(|s| s.parse().ok()).unwrap_or(7890);
            }
            "--bind" => {
                i += 1;
                bind_addr = args.get(i).cloned().unwrap_or(bind_addr);
            }
            "--hive" => {
                i += 1;
                hive_override = args.get(i).map(PathBuf::from);
            }
            "--root" => {
                i += 1;
                override_label = args.get(i).cloned().unwrap_or(override_label);
            }
            "--no-browser" => open_browser = false,
            "-h" | "--help" => {
                eprintln!(
                    "regedit (libreg) [--port N] [--bind ADDR] [--no-browser] \
                     [--hive FILE --root LABEL]"
                );
                return;
            }
            other => eprintln!("ignoring unknown argument: {other}"),
        }
        i += 1;
    }

    let roots = match build_roots(hive_override, override_label) {
        Ok(r) => r,
        Err(e) => {
            eprintln!("startup error: {e}");
            std::process::exit(1);
        }
    };
    if roots.is_empty() {
        eprintln!(
            "no hives to browse: add entries to the mount map ($LIBREG_HIVES or\n\
             ~/.config/libreg/hives.conf) or pass --hive FILE."
        );
    }
    let state = Arc::new(AppState { roots });

    let bind = format!("{bind_addr}:{port}");
    // Bind first so we know the port is ours before announcing a URL or opening
    // a browser at it. A bound socket queues connections, so a browser launched
    // now is served as soon as the accept loop below starts.
    let listener = match http::bind(&bind) {
        Ok(l) => l,
        Err(e) => {
            eprintln!("could not bind {bind}: {e}");
            std::process::exit(1);
        }
    };

    // The URL to visit. When bound to all interfaces, point the browser at
    // loopback rather than 0.0.0.0, which browsers will not open.
    let host = if bind_addr == "0.0.0.0" || bind_addr == "::" {
        "127.0.0.1"
    } else {
        bind_addr.as_str()
    };
    let url = format!("http://{host}:{port}");
    println!("regedit serving on {url}  ({} root(s))", state.roots.len());

    if open_browser {
        launch_browser(&url);
    } else {
        println!("open {url} in your browser");
    }

    let st = state.clone();
    if let Err(e) = http::serve(listener, move |req| dispatch(&st, req)) {
        eprintln!("server error: {e}");
        std::process::exit(1);
    }
}

/// Best-effort: open `url` in the user's default browser. If no opener is
/// available (for example a headless box with no `xdg-open`), fall back to
/// telling the user which URL to open by hand.
fn launch_browser(url: &str) {
    // xdg-open is the freedesktop standard; the others cover minimal installs.
    let openers: [&[&str]; 5] = [
        &["xdg-open"],
        &["gio", "open"],
        &["sensible-browser"],
        &["x-www-browser"],
        &["www-browser"],
    ];
    for opener in openers {
        let (cmd, pre) = opener.split_first().expect("opener is non-empty");
        if Command::new(cmd).args(pre).arg(url).spawn().is_ok() {
            println!("opening {url} in your browser (pass --no-browser to skip)");
            return;
        }
    }
    println!("could not launch a browser automatically; open {url} in your browser");
}

fn build_roots(hive_override: Option<PathBuf>, label: String) -> CliResult<Vec<RootEntry>> {
    if let Some(file) = hive_override {
        return Ok(vec![RootEntry { label, file }]);
    }
    let map = MountMap::load_default()?;
    Ok(map
        .mounts
        .iter()
        .map(|m| RootEntry {
            label: m.point.display_long(),
            file: m.file.clone(),
        })
        .collect())
}

fn dispatch(state: &AppState, req: &Request) -> Response {
    let result = match (req.method.as_str(), req.path.as_str()) {
        ("GET", "/") | ("GET", "/index.html") => return Response::html(INDEX_HTML),
        ("GET", "/api/roots") => api_roots(state),
        ("GET", "/api/key") => api_key(state, &req.query),
        ("GET", "/api/validate") => api_validate(state, &req.query),
        ("GET", "/api/structure") => api_structure(state, &req.query),
        ("GET", "/api/tree") => api_tree(state, &req.query),
        ("GET", "/api/diff") => api_diff(state, &req.query),
        ("GET", "/api/security") => api_security(state, &req.query),
        ("POST", "/api/setsecurity") => api_setsecurity(state, &req.form),
        ("GET", "/api/export") => return api_export(state, &req.query),
        ("POST", "/api/setvalue") => api_setvalue(state, &req.form),
        ("POST", "/api/deletevalue") => api_deletevalue(state, &req.form),
        ("POST", "/api/createkey") => api_createkey(state, &req.form),
        ("POST", "/api/deletekey") => api_deletekey(state, &req.form),
        _ => return Response::text(404, "not found"),
    };
    match result {
        Ok(body) => Response::json(body),
        Err(e) => Response::json(json::object(&[("error", json::string(&e.to_string()))])),
    }
}

/// Find the hive file for a root label.
fn file_for<'a>(state: &'a AppState, label: &str) -> CliResult<&'a PathBuf> {
    state
        .roots
        .iter()
        .find(|r| r.label.eq_ignore_ascii_case(label))
        .map(|r| &r.file)
        .ok_or_else(|| cli_core::error::CliError::not_found(format!("unknown root: {label}")))
}

fn param<'a>(q: &'a HashMap<String, String>, key: &str) -> &'a str {
    q.get(key).map(|s| s.as_str()).unwrap_or("")
}

// ---- API handlers ----------------------------------------------------------

fn api_roots(state: &AppState) -> CliResult<String> {
    let labels: Vec<String> = state.roots.iter().map(|r| r.label.clone()).collect();
    Ok(json::object(&[("roots", json::string_array(&labels))]))
}

fn api_key(state: &AppState, q: &HashMap<String, String>) -> CliResult<String> {
    let file = file_for(state, param(q, "root"))?;
    let path = param(q, "path");
    let session = Session::open(file)?;
    let dump = session.dump_key(path)?;

    let values: Vec<String> = dump
        .values
        .iter()
        .map(|v| {
            json::object(&[
                ("name", json::string(&v.name)),
                ("type", json::string(value::type_name(v.ty))),
                ("display", json::string(&v.display())),
                ("hex", json::string(&value::to_hex_upper(&v.data))),
            ])
        })
        .collect();

    Ok(json::object(&[
        ("path", json::string(path)),
        ("subkeys", json::string_array(&dump.subkeys)),
        ("values", format!("[{}]", values.join(","))),
    ]))
}

fn api_validate(state: &AppState, q: &HashMap<String, String>) -> CliResult<String> {
    let file = file_for(state, param(q, "root"))?;
    let session = Session::open(file)?;
    let problems = session.hive().validate();
    let valid = problems.is_empty();
    Ok(json::object(&[
        ("valid", valid.to_string()),
        ("problems", json::string_array(&problems)),
    ]))
}

fn api_structure(state: &AppState, q: &HashMap<String, String>) -> CliResult<String> {
    let file = file_for(state, param(q, "root"))?;
    let st = cli_core::structure::inspect(file)?;
    let b = &st.base;
    let base = json::object(&[
        ("magic_ok", b.magic_ok.to_string()),
        ("primary_seq", b.primary_seq.to_string()),
        ("secondary_seq", b.secondary_seq.to_string()),
        ("clean", b.clean.to_string()),
        ("major_version", b.major_version.to_string()),
        ("minor_version", b.minor_version.to_string()),
        ("root_offset", b.root_offset.to_string()),
        ("hbins_size", b.hbins_size.to_string()),
        ("checksum_valid", b.checksum_valid.to_string()),
        ("file_size", b.file_size.to_string()),
    ]);
    let stats = json::object(&[
        ("hbins", st.stats.hbins.to_string()),
        ("allocated", st.stats.allocated.to_string()),
        ("free", st.stats.free.to_string()),
        ("total_cell_bytes", st.stats.total_cell_bytes.to_string()),
    ]);
    let cells: Vec<String> = st
        .cells
        .iter()
        .map(|c| {
            json::object(&[
                ("offset", c.offset.to_string()),
                ("size", c.size.to_string()),
                ("allocated", c.allocated.to_string()),
                ("sig", c.signature.as_ref().map(|s| json::string(s)).unwrap_or_else(|| "null".into())),
            ])
        })
        .collect();
    Ok(json::object(&[
        ("base", base),
        ("stats", stats),
        ("cells", format!("[{}]", cells.join(","))),
        ("cells_truncated", st.cells_truncated.to_string()),
        ("walk_error", st.walk_error.as_ref().map(|e| json::string(e)).unwrap_or_else(|| "null".into())),
    ]))
}

fn api_tree(state: &AppState, q: &HashMap<String, String>) -> CliResult<String> {
    let file = file_for(state, param(q, "root"))?;
    let path = param(q, "path");
    let session = Session::open(file)?;
    build_tree(&session, path)
}

/// Build a recursive JSON dump of the subtree at `path` (name, values, subkeys).
fn build_tree(session: &Session, path: &str) -> CliResult<String> {
    let dump = session.dump_key(path)?;
    let name = path.rsplit('\\').next().unwrap_or("").to_string();
    let values: Vec<String> = dump
        .values
        .iter()
        .map(|v| {
            json::object(&[
                ("name", json::string(&v.name)),
                ("type", json::string(value::type_name(v.ty))),
                ("display", json::string(&v.display())),
            ])
        })
        .collect();
    let mut subtrees = Vec::new();
    for sub in &dump.subkeys {
        let child = if path.is_empty() { sub.clone() } else { format!("{path}\\{sub}") };
        subtrees.push(build_tree(session, &child)?);
    }
    Ok(json::object(&[
        ("name", json::string(&name)),
        ("path", json::string(path)),
        ("values", format!("[{}]", values.join(","))),
        ("subkeys", format!("[{}]", subtrees.join(","))),
    ]))
}

fn api_diff(state: &AppState, q: &HashMap<String, String>) -> CliResult<String> {
    let fa = file_for(state, param(q, "root_a"))?.clone();
    let fb = file_for(state, param(q, "root_b"))?.clone();
    let pa = param(q, "path_a");
    let pb = param(q, "path_b");
    let sa = Session::open(&fa)?;
    let sb = Session::open(&fb)?;

    use std::collections::BTreeMap;
    type Vals = Vec<(String, u32, Vec<u8>)>;
    let rel = |base: &str, p: &str| p.strip_prefix(base).unwrap_or(p).trim_start_matches('\\').to_string();
    let collect = |s: &Session, base: &str| -> CliResult<BTreeMap<String, Vals>> {
        let mut m = BTreeMap::new();
        for d in s.dump_recursive(base)? {
            m.insert(
                rel(base, &d.path),
                d.values.iter().map(|v| (v.name.to_uppercase(), v.ty, v.data.clone())).collect(),
            );
        }
        Ok(m)
    };
    let left = collect(&sa, pa)?;
    let right = collect(&sb, pb)?;

    let mut diffs: Vec<String> = Vec::new();
    for (k, lv) in &left {
        match right.get(k) {
            None => diffs.push(format!("only in A: {}", if k.is_empty() { "(root)" } else { k })),
            Some(rv) if rv != lv => diffs.push(format!("values differ: {}", if k.is_empty() { "(root)" } else { k })),
            _ => {}
        }
    }
    for k in right.keys() {
        if !left.contains_key(k) {
            diffs.push(format!("only in B: {}", if k.is_empty() { "(root)" } else { k }));
        }
    }
    Ok(json::object(&[
        ("identical", diffs.is_empty().to_string()),
        ("differences", json::string_array(&diffs)),
    ]))
}

fn api_security(state: &AppState, q: &HashMap<String, String>) -> CliResult<String> {
    let file = file_for(state, param(q, "root"))?;
    let path = param(q, "path");
    let session = Session::open(file)?;
    // libreg exposes the raw self-relative descriptor bytes; cli-core decodes
    // them to SDDL (the readable, editable form). We return both: the SDDL for
    // editing and the raw hex, which Windows regedit never surfaces.
    let desc = session.hive().key_security(path)?;
    let sddl = cli_core::sddl::to_sddl(&desc)?;
    Ok(json::object(&[
        ("path", json::string(path)),
        ("sddl", json::string(&sddl)),
        ("descriptor_hex", json::string(&value::to_hex_upper(&desc))),
        ("descriptor_len", desc.len().to_string()),
    ]))
}

fn api_setsecurity(state: &AppState, f: &HashMap<String, String>) -> CliResult<String> {
    let file = file_for(state, param(f, "root"))?;
    let path = param(f, "key");
    // Convert the edited SDDL back to a binary descriptor before storing it.
    let descriptor = cli_core::sddl::from_sddl(param(f, "sddl"))?;
    let mut session = Session::open(file)?;
    session.hive_mut().set_key_security(path, descriptor)?;
    session.save()?;
    Ok(ok())
}

fn api_export(state: &AppState, q: &HashMap<String, String>) -> Response {
    let file = match file_for(state, param(q, "root")) {
        Ok(f) => f,
        Err(e) => return Response::text(400, &e.to_string()),
    };
    let path = param(q, "path");
    let session = match Session::open(file) {
        Ok(s) => s,
        Err(e) => return Response::text(500, &e.to_string()),
    };
    let dumps = match session.dump_recursive(path) {
        Ok(d) => d,
        Err(e) => return Response::text(500, &e.to_string()),
    };
    let root_label = param(q, "root");
    let mut doc = regfile::export_header();
    for d in &dumps {
        let display = if d.path.is_empty() {
            root_label.to_string()
        } else {
            format!("{root_label}\\{}", d.path)
        };
        doc.push_str(&regfile::export_key(&display, &d.values));
    }
    Response::download("export.reg", regfile::to_utf16le_bom(&doc))
}

fn api_setvalue(state: &AppState, f: &HashMap<String, String>) -> CliResult<String> {
    let file = file_for(state, param(f, "root"))?;
    let key = param(f, "key");
    let name = param(f, "name");
    let ty = value::type_from_name(param(f, "type"))
        .ok_or_else(|| cli_core::error::CliError::usage(format!("unknown type {}", param(f, "type"))))?;
    let sep = if param(f, "sep").is_empty() { "\\0" } else { param(f, "sep") };
    let data = value::encode_cli(ty, param(f, "data"), sep)?;
    let mut session = Session::open(file)?;
    session.hive_mut().create_key(key)?;
    session.hive_mut().set_value(key, name, ty, &data)?;
    session.save()?;
    Ok(ok())
}

fn api_deletevalue(state: &AppState, f: &HashMap<String, String>) -> CliResult<String> {
    let file = file_for(state, param(f, "root"))?;
    let mut session = Session::open(file)?;
    session.hive_mut().delete_value(param(f, "key"), param(f, "name"))?;
    session.save()?;
    Ok(ok())
}

fn api_createkey(state: &AppState, f: &HashMap<String, String>) -> CliResult<String> {
    let file = file_for(state, param(f, "root"))?;
    let mut session = Session::open(file)?;
    session.hive_mut().create_key(param(f, "key"))?;
    session.save()?;
    Ok(ok())
}

fn api_deletekey(state: &AppState, f: &HashMap<String, String>) -> CliResult<String> {
    let file = file_for(state, param(f, "root"))?;
    let key = param(f, "key");
    if key.is_empty() {
        return Err(cli_core::error::CliError::usage("refusing to delete the hive root"));
    }
    let mut session = Session::open(file)?;
    session.hive_mut().delete_key(key, true)?;
    session.save()?;
    Ok(ok())
}

fn ok() -> String {
    json::object(&[("ok", "true".to_string())])
}
