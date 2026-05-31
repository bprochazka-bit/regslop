//! Operation sequence executor. Reads a `TestDef` (parsed from the YAML format
//! in the harness CLAUDE.md), runs it against the Linux agent and, when
//! present, the Windows agent, and compares the results across the axes in
//! CONTRACTS.md.
//!
//! Handles are agent specific (CONTRACTS.md: handles are opaque, each agent
//! emits its own), so capture variables resolve to a different concrete handle
//! per agent. The runner keeps a separate variable map per agent and
//! substitutes `$var` references when building each request body.
//!
//! The fuzzer agent integrates here: build a `TestDef` and call
//! `run_operations`.

use crate::client::Client;
use crate::differ::{bytewise, semantic, structural};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use std::collections::{HashMap, HashSet};

#[derive(Debug, Deserialize, Serialize)]
pub struct TestDef {
    pub name: String,
    #[serde(default)]
    pub tags: Vec<String>,
    #[serde(default)]
    pub operations: Vec<serde_yaml::Mapping>,
    #[serde(default)]
    pub expect: Expect,
}

#[derive(Debug, Default, Deserialize, Serialize)]
pub struct Expect {
    #[serde(default)]
    pub semantic_equal: Option<bool>,
    #[serde(default)]
    pub structural_valid: Option<Vec<String>>,
}

pub struct Agents<'a> {
    pub linux: &'a Client,
    pub windows: Option<&'a Client>,
}

#[derive(Debug, Clone)]
pub enum AspectOutcome {
    Pass,
    Fail(String),
    Warn(String),
    Na,
}

#[derive(Debug, Clone)]
pub struct Snapshot {
    pub dump: Value,
    pub sha_file: String,
    /// Hash of the canonical form. Currently unused (semantic equality is done
    /// structurally), kept for a future fast-path equality check and JSON
    /// reporting.
    #[allow(dead_code)]
    pub sha_canon: String,
    pub validate: Value,
}

#[derive(Debug, Clone)]
pub struct OpResult {
    pub op: String,
    pub expect_error: Option<String>,
    pub ok: bool,
    pub code: Option<String>,
    pub transport_error: Option<String>,
    /// Response `data` for a successful read op (key_list, key_info, value_get,
    /// key_security_get), captured so the harness can compare what each agent
    /// returns for the same read. `None` for writes, failures, and non-reads.
    pub data: Option<Value>,
}

/// Read endpoints whose response payload is compared across agents. A read op
/// returning divergent data even when the stored hive matches (e.g. a wrong
/// `/key/list` order or a buggy `/key/info` count) would otherwise slip past
/// the dump-based semantic comparison.
fn is_read_op(op: &str) -> bool {
    matches!(op, "key_list" | "key_info" | "value_get" | "key_security_get")
}

pub struct SeqResult {
    pub op_results: Vec<OpResult>,
    pub snapshots: HashMap<String, Snapshot>,
    pub roundtrip_dumps: HashMap<String, Value>,
    /// Byte-level structural invariant results per saved hive, from pulling the
    /// agent's on-disk hive over SMB and running `structural::check_bytes`. Only
    /// populated for the Windows agent when `--windows-smb` is on; empty
    /// otherwise (the in-memory Linux backend emits no `regf` bytes).
    pub byte_invariants: HashMap<String, Vec<structural::InvariantResult>>,
}

pub struct TestResult {
    pub name: String,
    pub tags: Vec<String>,
    pub problems: Vec<String>,
    pub semantic: AspectOutcome,
    pub structural: AspectOutcome,
    pub bytewise: AspectOutcome,
    pub roundtrip: AspectOutcome,
    pub recovery: AspectOutcome,
    pub fuzz: AspectOutcome,
    pub linux: SeqResult,
    pub windows: Option<SeqResult>,
}

impl TestResult {
    /// The outcome the report should attribute to a given tag.
    pub fn outcome_for_tag(&self, tag: &str) -> &AspectOutcome {
        match tag {
            "semantic" => &self.semantic,
            "structural" => &self.structural,
            "bytewise" => &self.bytewise,
            "roundtrip" => &self.roundtrip,
            "recovery" => &self.recovery,
            "fuzz" => &self.fuzz,
            _ => &AspectOutcome::Na,
        }
    }
}

// --- op metadata ---

fn endpoint(op: &str) -> Option<(&'static str, &'static str)> {
    Some(match op {
        "hive_create" => ("POST", "/hive/create"),
        "hive_load" => ("POST", "/hive/load"),
        "hive_save" => ("POST", "/hive/save"),
        "hive_close" => ("POST", "/hive/close"),
        "key_create" => ("POST", "/key/create"),
        "key_delete" => ("POST", "/key/delete"),
        "key_rename" => ("POST", "/key/rename"),
        "key_list" => ("GET", "/key/list"),
        "key_info" => ("GET", "/key/info"),
        "value_set" => ("POST", "/value/set"),
        "value_delete" => ("POST", "/value/delete"),
        "value_get" => ("GET", "/value/get"),
        "key_security_get" => ("GET", "/key/security"),
        "key_security_set" => ("POST", "/key/security"),
        "hive_dump" => ("GET", "/hive/dump"),
        "hive_checksum" => ("GET", "/hive/checksum"),
        "hive_validate" => ("GET", "/hive/validate"),
        _ => return None,
    })
}

fn ymap_str<'a>(m: &'a serde_yaml::Mapping, key: &str) -> Option<&'a str> {
    m.get(serde_yaml::Value::String(key.to_string()))
        .and_then(|v| v.as_str())
}

/// Build the JSON request body from an op mapping, dropping control keys.
fn build_body(opmap: &serde_yaml::Mapping) -> Value {
    let mut m = serde_yaml::Mapping::new();
    for (k, v) in opmap {
        if let Some(ks) = k.as_str() {
            if matches!(ks, "op" | "capture" | "expect_error") {
                continue;
            }
            m.insert(k.clone(), v.clone());
        }
    }
    serde_json::to_value(serde_yaml::Value::Mapping(m)).unwrap_or_else(|_| json!({}))
}

fn substitute(v: &mut Value, vars: &HashMap<String, String>) {
    match v {
        Value::String(s) if s.starts_with('$') => {
            if let Some(val) = vars.get(&s[1..]) {
                *s = val.clone();
            }
        }
        Value::Array(a) => a.iter_mut().for_each(|x| substitute(x, vars)),
        Value::Object(m) => m.values_mut().for_each(|x| substitute(x, vars)),
        _ => {}
    }
}

fn str_field(data: &Value, key: &str) -> String {
    data.get(key).and_then(|v| v.as_str()).unwrap_or("").to_string()
}

fn snapshot(client: &Client, handle: &str) -> Snapshot {
    let dump = client
        .call("GET", "/hive/dump", &json!({ "handle": handle }))
        .ok()
        .filter(|e| e.ok)
        .and_then(|e| e.data.get("canonical_json").cloned())
        .unwrap_or(Value::Null);
    let (sha_file, sha_canon) = client
        .call("GET", "/hive/checksum", &json!({ "handle": handle }))
        .ok()
        .filter(|e| e.ok)
        .map(|e| (str_field(&e.data, "sha256_file"), str_field(&e.data, "sha256_canonical")))
        .unwrap_or_default();
    let validate = client
        .call("GET", "/hive/validate", &json!({ "handle": handle }))
        .ok()
        .filter(|e| e.ok)
        .map(|e| e.data)
        .unwrap_or(Value::Null);
    Snapshot { dump, sha_file, sha_canon, validate }
}

/// Run the operation sequence against a single agent.
fn run_sequence(client: &Client, test: &TestDef) -> SeqResult {
    let mut vars: HashMap<String, String> = HashMap::new();
    let mut open_hives: HashMap<String, String> = HashMap::new(); // var -> handle
    let mut paths: HashMap<String, String> = HashMap::new(); // var -> file path
    let mut saved: HashSet<String> = HashSet::new(); // vars whose hive was saved
    let mut snapshots: HashMap<String, Snapshot> = HashMap::new();
    let mut op_results = Vec::new();

    for opmap in &test.operations {
        let op_name = ymap_str(opmap, "op").unwrap_or("").to_string();
        let capture = ymap_str(opmap, "capture").map(|s| s.to_string());
        let expect_error = ymap_str(opmap, "expect_error").map(|s| s.to_string());

        let (method, path) = match endpoint(&op_name) {
            Some(e) => e,
            None => {
                op_results.push(OpResult {
                    op: op_name.clone(),
                    expect_error: expect_error.clone(),
                    ok: false,
                    code: None,
                    transport_error: Some(format!("unknown op: {op_name}")),
                    data: None,
                });
                continue;
            }
        };

        let mut body = build_body(opmap);
        substitute(&mut body, &vars);

        // Hive file paths in tests are logical; map them onto this agent's
        // filesystem (a Linux `/tmp/x.hiv` is not a valid offreg path). The
        // mapping is deterministic, so a later hive_load of the same logical
        // path resolves to the same file on this agent.
        if matches!(op_name.as_str(), "hive_create" | "hive_load") {
            if let Some(p) = body.get("path").and_then(|p| p.as_str()) {
                let mapped = client.map_hive_path(p);
                body["path"] = json!(mapped);
            }
        }

        // Snapshot a hive immediately before it is closed, so post-save state
        // is captured even when the test closes the handle.
        if op_name == "hive_close" {
            if let Some(h) = body.get("handle").and_then(|h| h.as_str()) {
                if let Some(var) = open_hives.iter().find(|(_, hv)| hv.as_str() == h).map(|(v, _)| v.clone()) {
                    snapshots.insert(var.clone(), snapshot(client, h));
                    open_hives.remove(&var);
                }
            }
        }

        match client.call(method, path, &body) {
            Ok(env) => {
                let read_data =
                    if env.ok && is_read_op(&op_name) { Some(env.data.clone()) } else { None };
                op_results.push(OpResult {
                    op: op_name.clone(),
                    expect_error: expect_error.clone(),
                    ok: env.ok,
                    code: env.code.clone(),
                    transport_error: None,
                    data: read_data,
                });
                if env.ok {
                    if let Some(cap) = &capture {
                        if let Some(h) = env.data.get("handle").and_then(|h| h.as_str()) {
                            vars.insert(cap.clone(), h.to_string());
                            if op_name == "hive_create" || op_name == "hive_load" {
                                open_hives.insert(cap.clone(), h.to_string());
                                if let Some(p) = body.get("path").and_then(|p| p.as_str()) {
                                    paths.insert(cap.clone(), p.to_string());
                                }
                            }
                        }
                    }
                    if op_name == "hive_save" {
                        if let Some(h) = body.get("handle").and_then(|h| h.as_str()) {
                            if let Some(var) = open_hives.iter().find(|(_, hv)| hv.as_str() == h).map(|(v, _)| v.clone()) {
                                saved.insert(var);
                            }
                        }
                    }
                }
            }
            Err(e) => op_results.push(OpResult {
                op: op_name.clone(),
                expect_error: expect_error.clone(),
                ok: false,
                code: None,
                transport_error: Some(e),
                data: None,
            }),
        }
    }

    // Snapshot any hives still open at end of sequence.
    for (var, h) in open_hives.clone() {
        snapshots.insert(var, snapshot(client, &h));
    }

    // Roundtrip: reload each saved hive from disk and dump it fresh.
    let mut roundtrip_dumps = HashMap::new();
    for var in &saved {
        if let Some(p) = paths.get(var) {
            if let Ok(env) = client.call("POST", "/hive/load", &json!({ "path": p })) {
                if env.ok {
                    if let Some(h2) = env.data.get("handle").and_then(|h| h.as_str()).map(|s| s.to_string()) {
                        let dump = client
                            .call("GET", "/hive/dump", &json!({ "handle": h2 }))
                            .ok()
                            .filter(|e| e.ok)
                            .and_then(|e| e.data.get("canonical_json").cloned())
                            .unwrap_or(Value::Null);
                        roundtrip_dumps.insert(var.clone(), dump);
                        let _ = client.call("POST", "/hive/close", &json!({ "handle": h2 }));
                    }
                }
            }
        }
    }

    // SMB byte-pull: for the Windows agent (offreg), pull each saved hive off
    // the VM and run the byte-level structural invariants on it. A pull failure
    // is a warning, never a test failure (the VM may be down).
    let mut byte_invariants = HashMap::new();
    if let Some(host) = client.smb_host() {
        for var in &saved {
            let Some(path) = paths.get(var) else { continue };
            let base = path.rsplit(['\\', '/']).next().unwrap_or(path);
            let local = std::env::temp_dir().join(format!("harness-smb-{base}"));
            match crate::smb::pull(host, base, &local) {
                Ok(()) => {
                    if let Ok(bytes) = std::fs::read(&local) {
                        byte_invariants.insert(var.clone(), structural::check_bytes(&bytes));
                    }
                    let _ = std::fs::remove_file(&local);
                }
                Err(e) => eprintln!("warning: SMB pull of {base} for byte checks failed: {e}"),
            }
        }
    }

    SeqResult { op_results, snapshots, roundtrip_dumps, byte_invariants }
}

/// Run a test against both agents and compute per-axis outcomes. This is the
/// stable entry point the fuzzer agent calls.
pub fn run_operations(test: &TestDef, agents: &Agents) -> TestResult {
    let linux = run_sequence(agents.linux, test);
    let windows = agents.windows.map(|w| run_sequence(w, test));

    let mut problems = Vec::new();
    let mut read_warnings = Vec::new();
    compare_op_results(&linux, windows.as_ref(), &mut problems, &mut read_warnings);

    let mut semantic = compute_semantic(&linux, windows.as_ref(), &problems);
    let mut structural = compute_structural(test, &linux, windows.as_ref());
    let mut bytewise = compute_bytewise(&linux, windows.as_ref());
    let mut roundtrip = compute_roundtrip(test, &linux, windows.as_ref());

    // Problems (transport errors, mismatched expected-error codes, cross-agent
    // op divergence) are agent-independent contract violations. They must fail
    // the test even when the comparison axes are n/a (e.g. single-agent mode,
    // where semantic and bytewise have no counterpart). Fail every tag the
    // test declares so the run goes RED and the failure is counted.
    if !problems.is_empty() {
        let summary = problems.join("; ");
        let fail_tag = |tag: &str, slot: &mut AspectOutcome| {
            if test.tags.iter().any(|t| t == tag) && !matches!(slot, AspectOutcome::Fail(_)) {
                *slot = AspectOutcome::Fail(summary.clone());
            }
        };
        fail_tag("semantic", &mut semantic);
        fail_tag("structural", &mut structural);
        fail_tag("bytewise", &mut bytewise);
        fail_tag("roundtrip", &mut roundtrip);
    }

    // A read-op warning with no hard failure (a one-sided SACL from
    // key_security_get) downgrades a passing semantic result to a warning,
    // mirroring how the dump-based SACL asymmetry is handled.
    if problems.is_empty() && !read_warnings.is_empty() && matches!(semantic, AspectOutcome::Pass) {
        semantic = AspectOutcome::Warn(read_warnings.join("; "));
    }

    TestResult {
        name: test.name.clone(),
        tags: test.tags.clone(),
        problems,
        semantic,
        structural,
        bytewise,
        roundtrip,
        recovery: AspectOutcome::Na,
        fuzz: AspectOutcome::Na,
        linux,
        windows,
    }
}

/// Per-op checks: expected errors, cross-agent code divergence, and cross-agent
/// divergence in the response payload of read ops. Hard divergences go to
/// `problems` (which fail the test); read-op warnings (a one-sided SACL from
/// `key_security_get`) go to `read_warnings`, which only downgrades `semantic`
/// to a warning.
fn compare_op_results(
    linux: &SeqResult,
    windows: Option<&SeqResult>,
    problems: &mut Vec<String>,
    read_warnings: &mut Vec<String>,
) {
    for (i, op) in linux.op_results.iter().enumerate() {
        if let Some(te) = &op.transport_error {
            problems.push(format!("op[{i}] {} transport error on linux: {te}", op.op));
        }
        if let Some(expected) = &op.expect_error {
            if op.ok {
                problems.push(format!("op[{i}] {} expected error {expected} but succeeded on linux", op.op));
            } else if op.code.as_deref() != Some(expected.as_str()) {
                problems.push(format!(
                    "op[{i}] {} expected error {expected} but got {:?} on linux",
                    op.op, op.code
                ));
            }
        }
    }
    if let Some(w) = windows {
        for (i, (l, r)) in linux.op_results.iter().zip(w.op_results.iter()).enumerate() {
            if l.ok != r.ok {
                problems.push(format!(
                    "op[{i}] {} success diverged: linux ok={}, windows ok={}",
                    l.op, l.ok, r.ok
                ));
            } else if !l.ok && l.code != r.code {
                problems.push(format!(
                    "op[{i}] {} error code diverged: linux={:?}, windows={:?}",
                    l.op, l.code, r.code
                ));
            }
            // Both agents succeeded on a read op: compare what they returned.
            // Reuse the semantic differ so `last_write` is ignored and `sddl`
            // is normalized (O/G/D always, SACL only when both report one).
            if l.ok && r.ok && is_read_op(&l.op) {
                if let (Some(ld), Some(rd)) = (&l.data, &r.data) {
                    let rep = semantic::compare(ld, rd, &semantic::SemanticOptions::default());
                    for d in rep.diffs {
                        problems.push(format!(
                            "op[{i}] {} response diverged at {}: {}",
                            l.op, d.path, d.detail
                        ));
                    }
                    for d in rep.warnings {
                        read_warnings.push(format!(
                            "op[{i}] {} response at {}: {}",
                            l.op, d.path, d.detail
                        ));
                    }
                }
            }
        }
    }
}

fn compute_semantic(linux: &SeqResult, windows: Option<&SeqResult>, problems: &[String]) -> AspectOutcome {
    let Some(w) = windows else { return AspectOutcome::Na };
    let opts = semantic::SemanticOptions::default();
    let mut diffs = Vec::new();
    let mut warnings = Vec::new();
    let mut compared = 0;
    for (var, lsnap) in &linux.snapshots {
        if let Some(wsnap) = w.snapshots.get(var) {
            compared += 1;
            let rep = semantic::compare(&lsnap.dump, &wsnap.dump, &opts);
            for d in rep.diffs {
                diffs.push(format!("hive '{var}' at {}: {}", d.path, d.detail));
            }
            for d in rep.warnings {
                warnings.push(format!("hive '{var}' at {}: {}", d.path, d.detail));
            }
        }
    }
    if compared == 0 {
        return AspectOutcome::Na;
    }
    if !problems.is_empty() {
        return AspectOutcome::Fail(format!("operation divergence: {}", problems.join("; ")));
    }
    if !diffs.is_empty() {
        AspectOutcome::Fail(diffs.join(" | "))
    } else if !warnings.is_empty() {
        AspectOutcome::Warn(warnings.join(" | "))
    } else {
        AspectOutcome::Pass
    }
}

fn compute_structural(test: &TestDef, linux: &SeqResult, windows: Option<&SeqResult>) -> AspectOutcome {
    let required: Vec<String> = match &test.expect.structural_valid {
        Some(list) => list.clone(),
        None => {
            let mut v = vec!["linux".to_string()];
            if windows.is_some() {
                v.push("windows".to_string());
            }
            v
        }
    };
    let mut failures = Vec::new();
    let mut checked = 0;
    for agent_name in &required {
        let seq = match agent_name.as_str() {
            "linux" => Some(linux),
            "windows" => windows,
            _ => None,
        };
        let Some(seq) = seq else { continue };
        for (var, snap) in &seq.snapshots {
            checked += 1;
            for r in structural::check(&snap.dump, &snap.validate) {
                if let structural::Status::Fail(msg) = r.status {
                    failures.push(format!(
                        "{agent_name} hive '{var}' invariant {} ({}): {msg}",
                        r.id, r.name
                    ));
                }
            }
            // Byte-level invariants from the SMB-pulled hive (Windows side),
            // when present, replace the Skipped 1 to 16 placeholders with real
            // results.
            for r in seq.byte_invariants.get(var).into_iter().flatten() {
                if let structural::Status::Fail(msg) = &r.status {
                    failures.push(format!(
                        "{agent_name} hive '{var}' invariant {} ({}) [bytes]: {msg}",
                        r.id, r.name
                    ));
                }
            }
        }
    }
    if checked == 0 {
        AspectOutcome::Na
    } else if failures.is_empty() {
        AspectOutcome::Pass
    } else {
        AspectOutcome::Fail(failures.join(" | "))
    }
}

fn compute_bytewise(linux: &SeqResult, windows: Option<&SeqResult>) -> AspectOutcome {
    let Some(w) = windows else { return AspectOutcome::Na };
    let mut differing = Vec::new();
    let mut compared = 0;
    for (var, lsnap) in &linux.snapshots {
        if let Some(wsnap) = w.snapshots.get(var) {
            compared += 1;
            if let bytewise::ByteVerdict::Differ { left, right } =
                bytewise::compare(&lsnap.sha_file, &wsnap.sha_file)
            {
                differing.push(format!("hive '{var}': linux={left:.12}, windows={right:.12}"));
            }
        }
    }
    if compared == 0 {
        AspectOutcome::Na
    } else if differing.is_empty() {
        AspectOutcome::Pass
    } else {
        // Allocator divergence is expected: warning, not failure.
        AspectOutcome::Warn(format!("file bytes differ (allocator divergence): {}", differing.join("; ")))
    }
}

fn compute_roundtrip(_test: &TestDef, linux: &SeqResult, windows: Option<&SeqResult>) -> AspectOutcome {
    let opts = semantic::SemanticOptions::default();
    let mut failures = Vec::new();
    let mut compared = 0;
    let check = |seq: &SeqResult, agent: &str, failures: &mut Vec<String>, compared: &mut usize| {
        for (var, dump) in &seq.roundtrip_dumps {
            if let Some(snap) = seq.snapshots.get(var) {
                *compared += 1;
                let diffs = semantic::diff(&snap.dump, dump, &opts);
                if !diffs.is_empty() {
                    failures.push(format!(
                        "{agent} hive '{var}' changed across save/reload: {} diffs (first: {} {})",
                        diffs.len(),
                        diffs[0].path,
                        diffs[0].detail
                    ));
                }
            }
        }
    };
    check(linux, "linux", &mut failures, &mut compared);
    if let Some(w) = windows {
        check(w, "windows", &mut failures, &mut compared);
    }
    if compared == 0 {
        AspectOutcome::Na
    } else if failures.is_empty() {
        AspectOutcome::Pass
    } else {
        AspectOutcome::Fail(failures.join(" | "))
    }
}
