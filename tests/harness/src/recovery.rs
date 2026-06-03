//! Recovery mode: drive libreg's crash-injection hook and check that a save
//! interrupted mid-write recovers on the next load (ADR 0004 / issue #61).
//!
//! Recovery is a libreg-internal property, not a cross-agent differential
//! (offreg writes no logs). For each case the runner builds and commits a
//! baseline, applies a mutation M, captures the in-memory dump D1 (baseline+M),
//! then `POST /test/crash_save { point }` instead of a normal save (so the log
//! holds M but the primary may be stale), closes the handle, reloads (which
//! recovers), and asserts the reloaded dump equals D1. Each case yields a
//! `recovery`-tagged `TestResult`, flipping that axis from n/a to a pass rate.
//!
//! Needs the libreg backend (`--backend libreg`); the in-memory backend has no
//! transaction logs and reports `crash_save` unsupported, which is mapped to a
//! skipped (`Na`) result rather than a failure.

use crate::client::Client;
use crate::differ::semantic::{self, SemanticOptions};
use crate::runner::{self, AspectOutcome, SeqResult, TestResult};
use serde::Deserialize;
use serde_json::{json, Value};
use std::collections::HashMap;
use std::path::Path;

#[derive(Deserialize)]
struct RecoveryTest {
    name: String,
    /// Crash point: after_first_log | after_log_before_primary | after_primary.
    point: String,
    /// Op sequence. Everything builds the hive; the ops after the last
    /// `hive_save` are the uncommitted mutation M that recovery must restore.
    #[serde(default)]
    operations: Vec<serde_yaml::Mapping>,
}

pub fn run(agent: &Client, tests_dir: &Path) -> Vec<TestResult> {
    let mut results: Vec<TestResult> =
        load_tests(tests_dir).iter().map(|t| run_case(agent, t)).collect();
    // A programmatic guard that needs a filesystem step (remove the primary,
    // keep the logs) the YAML op model cannot express.
    results.push(clean_primary_guard(agent));
    results
}

fn run_case(agent: &Client, test: &RecoveryTest) -> TestResult {
    let result = |outcome: AspectOutcome| TestResult {
        name: test.name.clone(),
        tags: vec!["recovery".to_string()],
        problems: Vec::new(),
        semantic: AspectOutcome::Na,
        structural: AspectOutcome::Na,
        bytewise: AspectOutcome::Na,
        roundtrip: AspectOutcome::Na,
        recovery: outcome,
        fuzz: AspectOutcome::Na,
        linux: empty_seq(),
        windows: None,
    };

    // Build the hive (baseline, save, then the uncommitted mutation), tracking
    // the working handle and the hive's path.
    let mut vars: HashMap<String, String> = HashMap::new();
    let mut handle: Option<String> = None;
    let mut hive_path: Option<String> = None;
    for opmap in &test.operations {
        let op_name = opmap
            .get(serde_yaml::Value::from("op"))
            .and_then(|v| v.as_str())
            .unwrap_or("");
        let Some((method, path)) = runner::endpoint(op_name) else {
            return result(AspectOutcome::Fail(format!("unknown op: {op_name}")));
        };
        let capture = opmap.get(serde_yaml::Value::from("capture")).and_then(|v| v.as_str());
        let mut body = runner::build_body(opmap);
        runner::substitute(&mut body, &vars);
        if op_name == "hive_create" {
            hive_path = body.get("path").and_then(|p| p.as_str()).map(String::from);
        }
        match agent.call(method, path, &body) {
            Ok(env) if env.ok => {
                if let (Some(cap), Some(h)) =
                    (capture, env.data.get("handle").and_then(|h| h.as_str()))
                {
                    vars.insert(cap.to_string(), h.to_string());
                    if op_name == "hive_create" || op_name == "hive_load" {
                        handle = Some(h.to_string());
                    }
                }
            }
            Ok(env) => return result(AspectOutcome::Fail(format!("op {op_name} failed: {:?}", env.error))),
            Err(e) => return result(AspectOutcome::Fail(format!("op {op_name} transport: {e}"))),
        }
    }
    let (Some(h), Some(path)) = (handle, hive_path) else {
        return result(AspectOutcome::Fail("test must hive_create with a capture".to_string()));
    };

    // D1: the intended committed state (baseline + M), in memory before the crash.
    let d1 = match dump(agent, &h) {
        Ok(d) => d,
        Err(e) => return result(AspectOutcome::Fail(e)),
    };

    // Crash-save instead of a normal save.
    match agent.call("POST", "/test/crash_save", &json!({ "handle": h, "point": test.point })) {
        Ok(env) if env.ok => {}
        Ok(env) => {
            let msg = env.error.unwrap_or_default();
            if msg.contains("only the libreg backend") {
                return result(AspectOutcome::Na); // wrong backend; skip rather than fail
            }
            return result(AspectOutcome::Fail(format!("crash_save: {msg}")));
        }
        Err(e) => return result(AspectOutcome::Fail(format!("crash_save transport: {e}"))),
    }

    // Discard in-memory state, then reload (which recovers).
    let _ = agent.call("POST", "/hive/close", &json!({ "handle": h }));
    let h2 = match agent.call("POST", "/hive/load", &json!({ "path": path })) {
        Ok(env) if env.ok => env.data.get("handle").and_then(|h| h.as_str()).map(String::from),
        Ok(env) => return result(AspectOutcome::Fail(format!("reload after crash: {:?}", env.error))),
        Err(e) => return result(AspectOutcome::Fail(format!("reload transport: {e}"))),
    };
    let Some(h2) = h2 else {
        return result(AspectOutcome::Fail("reload returned no handle".to_string()));
    };
    let d2 = match dump(agent, &h2) {
        Ok(d) => d,
        Err(e) => return result(AspectOutcome::Fail(e)),
    };
    let _ = agent.call("POST", "/hive/close", &json!({ "handle": h2 }));

    // The recovered hive must equal the pre-crash committed-plus-M state.
    let opts = SemanticOptions::default(); // ignores timestamps
    let diffs = semantic::compare(&d1, &d2, &opts).diffs;
    if diffs.is_empty() {
        result(AspectOutcome::Pass)
    } else {
        let s: Vec<String> = diffs.iter().take(6).map(|d| format!("{}: {}", d.path, d.detail)).collect();
        result(AspectOutcome::Fail(format!("recovered hive != pre-crash state: {}", s.join(" | "))))
    }
}

fn dump(agent: &Client, handle: &str) -> Result<Value, String> {
    let env = agent.call("GET", "/hive/dump", &json!({ "handle": handle }))?;
    env.data.get("canonical_json").cloned().ok_or_else(|| "dump missing canonical_json".to_string())
}

/// Guard for the CONTRACTS 0.1.9 invariant (issue #97, fixed by #96): a clean
/// primary (primary seq == secondary seq) is authoritative on load, so a stale
/// `.LOG1/.LOG2` left at the path MUST NOT be replayed over the freshly saved
/// primary. We build a high-generation hive (five saves populate both logs),
/// remove ONLY the primary, then write a fresh CLEAN primary at the same path and
/// reload: the reload must equal the clean in-memory state, not the stale log
/// generation. Single libreg agent; the in-memory backend has no logs, so it
/// reports `Na`.
fn clean_primary_guard(agent: &Client) -> TestResult {
    let result = |outcome: AspectOutcome| TestResult {
        name: "clean_primary_suppresses_stale_log".to_string(),
        tags: vec!["recovery".to_string()],
        problems: Vec::new(),
        semantic: AspectOutcome::Na,
        structural: AspectOutcome::Na,
        bytewise: AspectOutcome::Na,
        roundtrip: AspectOutcome::Na,
        recovery: outcome,
        fuzz: AspectOutcome::Na,
        linux: empty_seq(),
        windows: None,
    };
    let path = "/tmp/harness_clean_primary.hiv";
    let sweep = || {
        for ext in ["", ".LOG1", ".LOG2"] {
            let _ = std::fs::remove_file(format!("{path}{ext}"));
        }
    };
    sweep();

    // Gen 1: five saves with distinct keys populate the dual logs.
    let h1 = match create_hive(agent, path) {
        Ok(h) => h,
        Err(e) => return result(AspectOutcome::Fail(e)),
    };
    for i in 0..5 {
        if let Err(e) = ok(agent, "POST", "/key/create", &json!({ "handle": h1, "path": format!("OLD{i}") })) {
            return result(AspectOutcome::Fail(e));
        }
        if let Err(e) = ok(agent, "POST", "/hive/save", &json!({ "handle": h1 })) {
            // No logs on the in-memory backend; skip rather than fail.
            if e.contains("only the libreg backend") || e.contains("unsupported") {
                return result(AspectOutcome::Na);
            }
            return result(AspectOutcome::Fail(e));
        }
    }
    let _ = agent.call("POST", "/hive/close", &json!({ "handle": h1 }));

    // Confirm gen 1 actually produced logs; otherwise the stale-log scenario is
    // not exercised and a pass would be meaningless (report Na, not a false Pass).
    let logs_present =
        ["LOG1", "LOG2"].iter().any(|e| std::path::Path::new(&format!("{path}.{e}")).exists());
    if !logs_present {
        sweep();
        return result(AspectOutcome::Na);
    }

    // Remove ONLY the primary; the stale .LOG1/.LOG2 remain at the path.
    if let Err(e) = std::fs::remove_file(path) {
        sweep();
        return result(AspectOutcome::Fail(format!("removing primary: {e}")));
    }

    // Gen 2: a fresh hive, one key, one clean save => a clean primary.
    let h2 = match create_hive(agent, path) {
        Ok(h) => h,
        Err(e) => {
            sweep();
            return result(AspectOutcome::Fail(e));
        }
    };
    if let Err(e) = ok(agent, "POST", "/key/create", &json!({ "handle": h2, "path": "NEWONLY" })) {
        sweep();
        return result(AspectOutcome::Fail(e));
    }
    if let Err(e) = ok(agent, "POST", "/hive/save", &json!({ "handle": h2 })) {
        sweep();
        return result(AspectOutcome::Fail(e));
    }
    let d1 = match dump(agent, &h2) {
        Ok(d) => d,
        Err(e) => {
            sweep();
            return result(AspectOutcome::Fail(e));
        }
    };
    let _ = agent.call("POST", "/hive/close", &json!({ "handle": h2 }));

    // Reload: the clean primary must win; the stale logs must not replay.
    let h3 = match load_hive(agent, path) {
        Ok(h) => h,
        Err(e) => {
            sweep();
            return result(AspectOutcome::Fail(e));
        }
    };
    let d2 = match dump(agent, &h3) {
        Ok(d) => d,
        Err(e) => {
            sweep();
            return result(AspectOutcome::Fail(e));
        }
    };
    let _ = agent.call("POST", "/hive/close", &json!({ "handle": h3 }));
    sweep();

    let diffs = semantic::compare(&d1, &d2, &SemanticOptions::default()).diffs;
    if diffs.is_empty() {
        result(AspectOutcome::Pass)
    } else {
        let s: Vec<String> = diffs.iter().take(6).map(|d| format!("{}: {}", d.path, d.detail)).collect();
        result(AspectOutcome::Fail(format!("reload replayed a stale log over the clean primary: {}", s.join(" | "))))
    }
}

/// Call an endpoint expecting `ok`, returning the data payload or an error string.
fn ok(agent: &Client, method: &str, path: &str, body: &Value) -> Result<Value, String> {
    match agent.call(method, path, body) {
        Ok(env) if env.ok => Ok(env.data),
        Ok(env) => Err(format!("{path}: {:?}", env.error)),
        Err(e) => Err(format!("{path} transport: {e}")),
    }
}

fn create_hive(agent: &Client, path: &str) -> Result<String, String> {
    let data = ok(agent, "POST", "/hive/create", &json!({ "path": path }))?;
    data.get("handle").and_then(|h| h.as_str()).map(String::from).ok_or_else(|| "create: no handle".to_string())
}

fn load_hive(agent: &Client, path: &str) -> Result<String, String> {
    let data = ok(agent, "POST", "/hive/load", &json!({ "path": path }))?;
    data.get("handle").and_then(|h| h.as_str()).map(String::from).ok_or_else(|| "load: no handle".to_string())
}

fn empty_seq() -> SeqResult {
    SeqResult {
        op_results: Vec::new(),
        snapshots: HashMap::new(),
        roundtrip_dumps: HashMap::new(),
        byte_invariants: HashMap::new(),
    }
}

fn load_tests(dir: &Path) -> Vec<RecoveryTest> {
    let mut tests = Vec::new();
    let Ok(entries) = std::fs::read_dir(dir) else { return tests };
    let mut paths: Vec<_> = entries
        .filter_map(|e| e.ok().map(|e| e.path()))
        .filter(|p| matches!(p.extension().and_then(|x| x.to_str()), Some("yaml") | Some("yml")))
        .collect();
    paths.sort();
    for path in paths {
        if let Ok(content) = std::fs::read_to_string(&path) {
            for doc in serde_yaml::Deserializer::from_str(&content) {
                if let Ok(t) = RecoveryTest::deserialize(doc) {
                    tests.push(t);
                }
            }
        }
    }
    tests
}
