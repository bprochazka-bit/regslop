//! Client-differential mode: validate the `reg`/`sc` Linux CLIs the same way as
//! libreg, against the Windows originals. Run the same operation with our tool
//! against a hive file and with real `reg.exe`/`sc.exe` against an equivalent
//! hive on the VM, then compare the two result hives in canonical form. See
//! `clients/proposals/harness-client-differential.md` and issue #68.
//!
//! Both result hives are canonicalized by loading them into the libreg agent
//! (`/hive/load` + `/hive/dump`), so the same logical comparison that grades the
//! agent differential applies. Key security is ignored: `reg`/`sc` do not edit
//! ACLs, and a key created by a SYSTEM-run `reg.exe` has a different owner than
//! one our tool creates (proposal scope).
//!
//! Transport for the Windows side: `reg load`/`unload` need admin
//! (SeRestorePrivilege), and DCOM ports are filtered, so commands run as SYSTEM
//! via impacket `atexec` (task scheduler over SMB). The result hive is pushed /
//! pulled over the same `winreg` share. Admin creds are baked in (temporal lab
//! VM), like the SMB creds in `smb.rs`.

use crate::client::Client;
use crate::differ::semantic::{self, SemanticOptions};
use serde::Deserialize;
use serde_json::{json, Value};
use std::path::Path;
use std::process::Command;

const VM_ADMIN_USER: &str = "administrator";
const VM_ADMIN_PASS: &str = "password";
const ATEXEC: &str = "/usr/share/doc/python3-impacket/examples/atexec.py";
const WIN_SHARE_DIR: &str = "C:\\winreg";
const MOUNT: &str = "HKLM\\HarnessTmp";
const SEED: &str = "/tmp/client_seed.hiv";

#[derive(Deserialize)]
struct ClientTest {
    name: String,
    /// "reg" (default) or "sc".
    #[serde(default = "default_kind")]
    kind: String,
    /// For sc tests: the service name (used to reg-save and clean up the live
    /// service, and to extract its subtree from our offline hive).
    #[serde(default)]
    service: Option<String>,
    /// For reg_import tests: the `.reg` file body. `{ROOT}` is substituted with
    /// `HKEY_LOCAL_MACHINE` for our tool and `HKEY_LOCAL_MACHINE\HarnessTmp` for
    /// the loaded Windows hive.
    #[serde(default)]
    reg: Option<String>,
    /// For reg_export tests: the subkey to export, relative to the hive root
    /// (e.g. `Software\Exp`). The seed is first populated via `reg` (using our
    /// `reg import`, validated equal to `reg.exe import`), then both tools export
    /// the subtree and the `.reg` texts are compared, normalized.
    #[serde(default)]
    export: Option<String>,
    /// Shared command tails. For reg: `add Software\Foo /v ...` (the key is
    /// relative to the hive root; the runner prefixes `HKLM\` for our tool and
    /// `HKLM\HarnessTmp\` for the loaded Windows hive). For sc the same string
    /// runs both tools verbatim (`create Name binPath= ...`). Absent for
    /// reg_import tests (which use `reg`).
    #[serde(default)]
    ops: Vec<String>,
}

fn default_kind() -> String {
    "reg".to_string()
}

pub struct CaseResult {
    pub name: String,
    pub passed: bool,
    pub detail: String,
}

/// Run every `*.yaml` client test under `tests_dir`. `agent` is the libreg agent
/// (used to canonicalize result hives); `vm_host` is the Windows VM; `reg_bin` /
/// `sc_bin` are our tools (each needed only by tests of that kind).
pub fn run(
    agent: &Client,
    vm_host: &str,
    reg_bin: Option<&Path>,
    sc_bin: Option<&Path>,
    tests_dir: &Path,
) -> Vec<CaseResult> {
    if let Err(e) = make_seed(agent) {
        return vec![CaseResult { name: "<seed>".into(), passed: false, detail: e }];
    }
    let mut results = Vec::new();
    for test in load_tests(tests_dir) {
        let fail = |detail: String| CaseResult { name: test.name.clone(), passed: false, detail };
        let r = match test.kind.as_str() {
            "sc" => match sc_bin {
                Some(bin) => run_sc_case(agent, vm_host, bin, &test),
                None => fail("sc test but no --sc-bin given".to_string()),
            },
            "reg_import" => match reg_bin {
                Some(bin) => run_reg_import_case(agent, vm_host, bin, &test),
                None => fail("reg_import test but no --reg-bin given".to_string()),
            },
            "reg_export" => match reg_bin {
                Some(bin) => run_reg_export_case(vm_host, bin, &test),
                None => fail("reg_export test but no --reg-bin given".to_string()),
            },
            _ => match reg_bin {
                Some(bin) => run_case(agent, vm_host, bin, &test),
                None => fail("reg test but no --reg-bin given".to_string()),
            },
        };
        results.push(r);
    }
    results
}

fn run_case(agent: &Client, vm_host: &str, reg_bin: &Path, test: &ClientTest) -> CaseResult {
    let fail = |detail: String| CaseResult {
        name: test.name.clone(),
        passed: false,
        detail,
    };
    let safe = sanitize(&test.name);
    let l_hive = format!("/tmp/client_{safe}_lin.hiv");
    let w_local = format!("/tmp/client_{safe}_win.hiv");
    let remote = format!("cd_{safe}.hiv");

    // --- Linux side: copy the seed, run each op with our reg ---
    if let Err(e) = std::fs::copy(SEED, &l_hive) {
        return fail(format!("seed copy: {e}"));
    }
    for op in &test.ops {
        let t = shell_split(op);
        if t.len() < 2 {
            return fail(format!("malformed op (need verb + key): {op:?}"));
        }
        let mut cmd = Command::new(reg_bin);
        cmd.arg(&t[0]).arg(format!("HKLM\\{}", t[1]));
        for a in &t[2..] {
            cmd.arg(a);
        }
        cmd.arg("--hive").arg(&l_hive);
        match cmd.output() {
            Ok(o) if o.status.success() => {}
            Ok(o) => return fail(format!("linux `reg {op}` exit {:?}: {}", o.status.code(), String::from_utf8_lossy(&o.stderr).trim())),
            Err(e) => return fail(format!("running our reg: {e}")),
        }
    }

    // --- Windows side: push the seed, load/operate/unload via atexec, pull ---
    if let Err(e) = smb_put(vm_host, SEED, &remote) {
        return fail(format!("smb push: {e}"));
    }
    // Silently unload any stale mount first, then load. The ops chain with && so
    // a failure stops the rest, but the final unload uses a single & so it ALWAYS
    // runs (otherwise a failed op leaves HarnessTmp loaded and every later test's
    // `reg load` hits "Access is denied").
    let mut chain = format!(
        "reg unload {MOUNT} >nul 2>nul & reg load {MOUNT} {WIN_SHARE_DIR}\\{remote}"
    );
    for op in &test.ops {
        let t = shell_split(op);
        chain.push_str(&format!(" && reg {} {MOUNT}\\{}", t[0], t[1]));
        for a in &t[2..] {
            chain.push(' ');
            chain.push_str(&win_quote(a));
        }
    }
    chain.push_str(&format!(" & reg unload {MOUNT}"));
    let cmd = format!("cmd.exe /c \"{chain}\"");
    if let Err(e) = vm_exec(vm_host, &cmd) {
        let _ = smb_del(vm_host, &remote);
        return fail(format!("vm exec: {e}"));
    }
    if let Err(e) = smb_get(vm_host, &remote, &w_local) {
        return fail(format!("smb pull: {e}"));
    }
    let _ = smb_del(vm_host, &remote);

    // --- canonicalize both result hives via the libreg agent and compare ---
    let a = match canonicalize(agent, &l_hive) {
        Ok(v) => v,
        Err(e) => return fail(format!("canonicalize linux hive: {e}")),
    };
    let b = match canonicalize(agent, &w_local) {
        Ok(v) => v,
        Err(e) => return fail(format!("canonicalize windows hive: {e}")),
    };
    let _ = std::fs::remove_file(&l_hive);
    let _ = std::fs::remove_file(&w_local);

    let opts = SemanticOptions { ignore_timestamps: true, ignore_security: true };
    let diffs = semantic::compare(&a, &b, &opts).diffs;
    if diffs.is_empty() {
        CaseResult { name: test.name.clone(), passed: true, detail: String::new() }
    } else {
        let summary: Vec<String> = diffs.iter().take(6).map(|d| format!("{}: {}", d.path, d.detail)).collect();
        fail(summary.join(" | "))
    }
}

/// An `sc` case. `sc.exe` only talks to the live SCM, so it cannot target a
/// loaded hive the way `reg.exe load` lets `reg add`: instead we run `sc.exe`
/// against the live registry, `reg save` the resulting `Services\<name>`
/// subtree, and compare that to the same subtree our `sc` writes into an
/// offline SYSTEM hive. The live service is created and deleted on the VM.
fn run_sc_case(agent: &Client, vm_host: &str, sc_bin: &Path, test: &ClientTest) -> CaseResult {
    let fail = |detail: String| CaseResult { name: test.name.clone(), passed: false, detail };
    let Some(service) = &test.service else {
        return fail("sc test needs a `service` field".to_string());
    };
    let safe = sanitize(&test.name);
    let l_hive = format!("/tmp/client_{safe}_lin.hiv");
    let w_local = format!("/tmp/client_{safe}_win.hiv");
    let remote = format!("scd_{safe}.hiv");

    // --- Linux side: our sc against an offline SYSTEM hive (ControlSet001) ---
    if let Err(e) = std::fs::copy(SEED, &l_hive) {
        return fail(format!("seed copy: {e}"));
    }
    for op in &test.ops {
        let mut cmd = Command::new(sc_bin);
        for a in shell_split(op) {
            cmd.arg(a);
        }
        cmd.args(["--hive", &l_hive, "--controlset", "1"]);
        match cmd.output() {
            Ok(o) if o.status.success() => {}
            Ok(o) => return fail(format!("our `sc {op}` exit {:?}: {}", o.status.code(), String::from_utf8_lossy(&o.stderr).trim())),
            Err(e) => return fail(format!("running our sc: {e}")),
        }
    }

    // --- Windows side: live sc.exe, then reg-save the Services subtree ---
    let mut chain = format!("sc delete {service} >nul 2>nul"); // clear any stale service
    for op in &test.ops {
        chain.push_str(&format!(" & sc {op}"));
    }
    chain.push_str(&format!(
        " & reg save HKLM\\SYSTEM\\CurrentControlSet\\Services\\{service} {WIN_SHARE_DIR}\\{remote} /y"
    ));
    chain.push_str(&format!(" & sc delete {service}")); // always remove the live service
    if let Err(e) = vm_exec(vm_host, &format!("cmd.exe /c \"{chain}\"")) {
        return fail(format!("vm exec: {e}"));
    }
    if let Err(e) = smb_get(vm_host, &remote, &w_local) {
        return fail(format!("smb pull (service subtree): {e}"));
    }
    let _ = smb_del(vm_host, &remote);

    let lc = match canonicalize(agent, &l_hive) {
        Ok(v) => v,
        Err(e) => return fail(format!("canonicalize our hive: {e}")),
    };
    let wc = match canonicalize(agent, &w_local) {
        Ok(v) => v,
        Err(e) => return fail(format!("canonicalize service subtree: {e}")),
    };
    let _ = std::fs::remove_file(&l_hive);
    let _ = std::fs::remove_file(&w_local);

    // Our service node is at ControlSet001\Services\<name>; the reg-saved hive's
    // root IS that node. Compare the two as service views (top-level name elided).
    let ours = match extract_service(&lc, service) {
        Some(n) => n,
        None => return fail(format!("our hive has no ControlSet001\\Services\\{service}")),
    };
    let theirs = wc.get("root").cloned().unwrap_or(Value::Null);
    let opts = SemanticOptions { ignore_timestamps: true, ignore_security: true };
    let diffs = semantic::compare(&service_view(&ours), &service_view(&theirs), &opts).diffs;
    if diffs.is_empty() {
        CaseResult { name: test.name.clone(), passed: true, detail: String::new() }
    } else {
        let summary: Vec<String> = diffs.iter().take(6).map(|d| format!("{}: {}", d.path, d.detail)).collect();
        fail(summary.join(" | "))
    }
}

/// Find the `ControlSet001\Services\<service>` node in a canonical dump.
fn extract_service(canon: &Value, service: &str) -> Option<Value> {
    let root = canon.get("root")?;
    let cs = find_subkey(root, "ControlSet001")?;
    let services = find_subkey(cs, "Services")?;
    find_subkey(services, service).cloned()
}

fn find_subkey<'a>(node: &'a Value, name: &str) -> Option<&'a Value> {
    node.get("subkeys")?
        .as_array()?
        .iter()
        .find(|s| s.get("name").and_then(|n| n.as_str()).is_some_and(|n| n.eq_ignore_ascii_case(name)))
}

/// A comparable view of a service node: drop the top-level name (our node is
/// named `<service>`, the reg-saved root is unnamed) so only the values, class,
/// security, and subkeys are compared.
fn service_view(node: &Value) -> Value {
    let mut v = node.clone();
    if let Some(obj) = v.as_object_mut() {
        obj.insert("name".to_string(), Value::String(String::new()));
    }
    v
}

/// A `.reg import` case. Both tools import the same `.reg` body (with the root
/// substituted per side) into an equal hive, then the result hives are
/// compared. `reg.exe import` works on a loaded key, so the Windows side uses
/// the same load/import/unload wrapper as `reg add`.
fn run_reg_import_case(agent: &Client, vm_host: &str, reg_bin: &Path, test: &ClientTest) -> CaseResult {
    let fail = |detail: String| CaseResult { name: test.name.clone(), passed: false, detail };
    let Some(content) = &test.reg else {
        return fail("reg_import test needs a `reg` field".to_string());
    };
    let safe = sanitize(&test.name);
    let l_hive = format!("/tmp/client_{safe}_lin.hiv");
    let w_local = format!("/tmp/client_{safe}_win.hiv");
    let l_reg = format!("/tmp/client_{safe}_lin.reg");
    let w_reg = format!("/tmp/client_{safe}_win.reg");
    let remote_hive = format!("imp_{safe}.hiv");
    let remote_reg = format!("imp_{safe}.reg");
    // .reg files are CRLF; the root differs per side.
    let render = |root: &str| content.replace("{ROOT}", root).replace('\n', "\r\n");

    // --- Linux side ---
    if std::fs::write(&l_reg, render("HKEY_LOCAL_MACHINE")).is_err() || std::fs::copy(SEED, &l_hive).is_err() {
        return fail("writing linux .reg / seed".to_string());
    }
    match Command::new(reg_bin).args(["import", &l_reg, "--hive", &l_hive]).output() {
        Ok(o) if o.status.success() => {}
        Ok(o) => return fail(format!("our reg import exit {:?}: {}", o.status.code(), String::from_utf8_lossy(&o.stderr).trim())),
        Err(e) => return fail(format!("running our reg: {e}")),
    }

    // --- Windows side: load the hive, import the .reg, unload ---
    if std::fs::write(&w_reg, render("HKEY_LOCAL_MACHINE\\HarnessTmp")).is_err() {
        return fail("writing windows .reg".to_string());
    }
    if let Err(e) = smb_put(vm_host, SEED, &remote_hive) {
        return fail(format!("smb push hive: {e}"));
    }
    if let Err(e) = smb_put(vm_host, &w_reg, &remote_reg) {
        return fail(format!("smb push .reg: {e}"));
    }
    let chain = format!(
        "reg unload {MOUNT} >nul 2>nul & reg load {MOUNT} {WIN_SHARE_DIR}\\{remote_hive} \
         && reg import {WIN_SHARE_DIR}\\{remote_reg} & reg unload {MOUNT}"
    );
    if let Err(e) = vm_exec(vm_host, &format!("cmd.exe /c \"{chain}\"")) {
        return fail(format!("vm exec: {e}"));
    }
    if let Err(e) = smb_get(vm_host, &remote_hive, &w_local) {
        return fail(format!("smb pull: {e}"));
    }
    let _ = smb_del(vm_host, &remote_hive);
    let _ = smb_del(vm_host, &remote_reg);

    let a = match canonicalize(agent, &l_hive) {
        Ok(v) => v,
        Err(e) => return fail(format!("canonicalize linux hive: {e}")),
    };
    let b = match canonicalize(agent, &w_local) {
        Ok(v) => v,
        Err(e) => return fail(format!("canonicalize windows hive: {e}")),
    };
    for f in [&l_hive, &w_local, &l_reg, &w_reg] {
        let _ = std::fs::remove_file(f);
    }

    let opts = SemanticOptions { ignore_timestamps: true, ignore_security: true };
    let diffs = semantic::compare(&a, &b, &opts).diffs;
    if diffs.is_empty() {
        CaseResult { name: test.name.clone(), passed: true, detail: String::new() }
    } else {
        let summary: Vec<String> = diffs.iter().take(6).map(|d| format!("{}: {}", d.path, d.detail)).collect();
        fail(summary.join(" | "))
    }
}

/// A `reg export` case. The seed is populated once via our `reg import` (so both
/// sides get the identical input hive), then both tools export the subtree to a
/// `.reg` file and the texts are compared after normalizing away the legitimate
/// formatting differences (per-side root prefix, value/key ordering, and the
/// `\`-continuation line wrapping reg.exe applies to long hex values).
fn run_reg_export_case(vm_host: &str, reg_bin: &Path, test: &ClientTest) -> CaseResult {
    let fail = |detail: String| CaseResult { name: test.name.clone(), passed: false, detail };
    let (Some(content), Some(subkey)) = (&test.reg, &test.export) else {
        return fail("reg_export test needs `reg` (seed body) and `export` (subkey)".to_string());
    };
    let safe = sanitize(&test.name);
    let pop_reg = format!("/tmp/client_{safe}_pop.reg");
    let pop_hive = format!("/tmp/client_{safe}_pop.hiv");
    let l_out = format!("/tmp/client_{safe}_lin.reg");
    let w_out = format!("/tmp/client_{safe}_win.reg");
    let remote_hive = format!("exp_{safe}.hiv");
    let remote_reg = format!("exp_{safe}.reg");

    // 1. Populate the seed once with our reg import (validated equal to reg.exe).
    let seed_body = content.replace("{ROOT}", "HKEY_LOCAL_MACHINE").replace('\n', "\r\n");
    if std::fs::write(&pop_reg, seed_body).is_err() || std::fs::copy(SEED, &pop_hive).is_err() {
        return fail("writing seed .reg / copying seed".to_string());
    }
    match Command::new(reg_bin).args(["import", &pop_reg, "--hive", &pop_hive]).output() {
        Ok(o) if o.status.success() => {}
        Ok(o) => return fail(format!("seed import exit {:?}: {}", o.status.code(), String::from_utf8_lossy(&o.stderr).trim())),
        Err(e) => return fail(format!("running our reg import: {e}")),
    }

    // 2. Our reg exports the subtree.
    let l_key = format!("HKEY_LOCAL_MACHINE\\{subkey}");
    match Command::new(reg_bin).args(["export", &l_key, &l_out, "--hive", &pop_hive]).output() {
        Ok(o) if o.status.success() => {}
        Ok(o) => return fail(format!("our reg export exit {:?}: {}", o.status.code(), String::from_utf8_lossy(&o.stderr).trim())),
        Err(e) => return fail(format!("running our reg export: {e}")),
    }

    // 3. reg.exe exports the same subtree from the loaded hive.
    if let Err(e) = smb_put(vm_host, &pop_hive, &remote_hive) {
        return fail(format!("smb push hive: {e}"));
    }
    let w_key = format!("HKEY_LOCAL_MACHINE\\HarnessTmp\\{subkey}");
    let chain = format!(
        "reg unload {MOUNT} >nul 2>nul & reg load {MOUNT} {WIN_SHARE_DIR}\\{remote_hive} \
         && reg export {w_key} {WIN_SHARE_DIR}\\{remote_reg} & reg unload {MOUNT}"
    );
    if let Err(e) = vm_exec(vm_host, &format!("cmd.exe /c \"{chain}\"")) {
        return fail(format!("vm exec: {e}"));
    }
    if let Err(e) = smb_get(vm_host, &remote_reg, &w_out) {
        return fail(format!("smb pull .reg: {e}"));
    }
    let _ = smb_del(vm_host, &remote_hive);
    let _ = smb_del(vm_host, &remote_reg);

    // 4. Normalize both .reg texts and compare.
    let read_reg = |path: &str| std::fs::read(path).map_err(|e| format!("reading {path}: {e}")).map(|b| decode_reg(&b));
    let a = match read_reg(&l_out) {
        Ok(t) => canonical_reg(&t, "HKEY_LOCAL_MACHINE\\"),
        Err(e) => return fail(e),
    };
    let b = match read_reg(&w_out) {
        Ok(t) => canonical_reg(&t, "HKEY_LOCAL_MACHINE\\HarnessTmp\\"),
        Err(e) => return fail(e),
    };
    for f in [&pop_reg, &pop_hive, &l_out, &w_out] {
        let _ = std::fs::remove_file(f);
    }

    let diffs = diff_reg(&a, &b);
    if diffs.is_empty() {
        CaseResult { name: test.name.clone(), passed: true, detail: String::new() }
    } else {
        fail(diffs.into_iter().take(6).collect::<Vec<_>>().join(" | "))
    }
}

/// Decode `.reg` bytes (UTF-16LE with BOM, as both reg.exe and our reg emit) to a
/// UTF-8 string. Falls back to lossy UTF-8 if there is no UTF-16 BOM.
fn decode_reg(bytes: &[u8]) -> String {
    if bytes.starts_with(&[0xFF, 0xFE]) {
        let units: Vec<u16> = bytes[2..].chunks_exact(2).map(|c| u16::from_le_bytes([c[0], c[1]])).collect();
        String::from_utf16_lossy(&units)
    } else {
        let start = if bytes.starts_with(&[0xEF, 0xBB, 0xBF]) { 3 } else { 0 };
        String::from_utf8_lossy(&bytes[start..]).into_owned()
    }
}

/// Reduce a `.reg` document to `{ key (root stripped) -> sorted value lines }`,
/// ignoring the header, blank lines, value/key ordering, and the `\`-continuation
/// wrapping reg.exe applies to long hex values. What remains is the logical
/// content: the keys present and each key's `name=data` lines.
fn canonical_reg(text: &str, strip_root: &str) -> std::collections::BTreeMap<String, Vec<String>> {
    use std::collections::BTreeMap;
    // Join continuation lines: a line ending in `\` continues on the next, whose
    // leading whitespace reg.exe adds is dropped.
    let mut joined: Vec<String> = Vec::new();
    for raw in text.lines() {
        let line = raw.strip_suffix('\r').unwrap_or(raw);
        if let Some(prev) = joined.last_mut() {
            if prev.ends_with('\\') {
                prev.pop();
                prev.push_str(line.trim_start());
                continue;
            }
        }
        joined.push(line.to_string());
    }

    let mut out: BTreeMap<String, Vec<String>> = BTreeMap::new();
    let mut cur: Option<String> = None;
    for line in joined {
        let t = line.trim_start_matches('\u{feff}');
        if t.is_empty() || t.starts_with("Windows Registry Editor") || t.starts_with("REGEDIT4") {
            continue;
        }
        if let Some(inner) = t.strip_prefix('[').and_then(|s| s.strip_suffix(']')) {
            // Strip the export root (case-insensitively) so both sides share a key space.
            let key = if inner.to_ascii_lowercase().starts_with(&strip_root.to_ascii_lowercase()) {
                inner[strip_root.len()..].to_string()
            } else {
                inner.to_string()
            };
            cur = Some(key.clone());
            out.entry(key).or_default();
        } else if let Some(k) = &cur {
            out.get_mut(k).unwrap().push(t.to_string());
        }
    }
    for v in out.values_mut() {
        v.sort();
    }
    out
}

/// Compare two normalized `.reg` maps; return human-readable divergences.
fn diff_reg(
    a: &std::collections::BTreeMap<String, Vec<String>>,
    b: &std::collections::BTreeMap<String, Vec<String>>,
) -> Vec<String> {
    let mut diffs = Vec::new();
    for key in a.keys().chain(b.keys()).collect::<std::collections::BTreeSet<_>>() {
        match (a.get(key), b.get(key)) {
            (Some(_), None) => diffs.push(format!("[{key}] only in our export")),
            (None, Some(_)) => diffs.push(format!("[{key}] only in reg.exe export")),
            (Some(va), Some(vb)) => {
                for line in va {
                    if !vb.contains(line) {
                        diffs.push(format!("[{key}] our-only value: {line}"));
                    }
                }
                for line in vb {
                    if !va.contains(line) {
                        diffs.push(format!("[{key}] reg.exe-only value: {line}"));
                    }
                }
            }
            (None, None) => {}
        }
    }
    diffs
}

// --- fuzz: generated reg operation sequences ---

/// Run `count` fuzzed `reg` operation sequences through the client differential.
/// Each sequence is fully determined by its seed (`base_seed + i`), so a failure
/// is reproducible: the generated ops are written to `repro_dir/<name>.yaml`, a
/// file you can drop into `--client-tests-dir` to replay it. Every case batches
/// `ops_per` operations into one load/operate/unload VM round-trip, so the cost
/// is one round-trip per sequence, not per op.
pub fn run_fuzz(
    agent: &Client,
    vm_host: &str,
    reg_bin: &Path,
    count: u32,
    base_seed: u64,
    ops_per: u32,
    repro_dir: &Path,
) -> Vec<CaseResult> {
    if let Err(e) = make_seed(agent) {
        return vec![CaseResult { name: "<seed>".into(), passed: false, detail: e }];
    }
    let mut results = Vec::new();
    for i in 0..count {
        let seed = base_seed.wrapping_add(i as u64);
        let ops = gen_sequence(seed, ops_per);
        let test = ClientTest {
            name: format!("fuzz_{seed:016x}"),
            kind: "reg".to_string(),
            service: None,
            reg: None,
            export: None,
            ops: ops.clone(),
        };
        let mut r = run_case(agent, vm_host, reg_bin, &test);
        if !r.passed {
            let path = repro_dir.join(format!("{}.yaml", test.name));
            let body = format!(
                "# Reproduces fuzz seed {seed:#018x} ({ops_per} ops). Replay with\n\
                 # --client-tests-dir pointing at this directory.\nname: {}\nops:\n{}",
                test.name,
                ops.iter().map(|o| format!("  - {o}\n")).collect::<String>(),
            );
            let _ = std::fs::create_dir_all(repro_dir);
            let saved = std::fs::write(&path, body).is_ok();
            r.detail = format!(
                "seed={seed:#018x}{} :: {}",
                if saved { format!(" repro={}", path.display()) } else { String::new() },
                r.detail,
            );
        }
        results.push(r);
    }
    results
}

/// SplitMix64: a tiny seedable PRNG (no external crates), so each fuzz sequence
/// is deterministic from its seed.
struct Rng(u64);
impl Rng {
    fn next_u64(&mut self) -> u64 {
        self.0 = self.0.wrapping_add(0x9E37_79B9_7F4A_7C15);
        let mut z = self.0;
        z = (z ^ (z >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
        z = (z ^ (z >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
        z ^ (z >> 31)
    }
    fn below(&mut self, n: u64) -> u64 {
        self.next_u64() % n
    }
    fn pick<'a, T>(&mut self, xs: &'a [T]) -> &'a T {
        &xs[self.below(xs.len() as u64) as usize]
    }
}

/// Generate one valid `reg` op sequence. Existence is tracked so a generated
/// delete always targets a key/value that the sequence created earlier: every op
/// then succeeds on both sides, and any resulting hive difference is a genuine
/// semantic divergence rather than an "operation failed" artifact.
fn gen_sequence(seed: u64, n: u32) -> Vec<String> {
    const SEGS: &[&str] = &["S", "A", "B", "C", "D"];
    const NAMES: &[&str] = &["v0", "v1", "v2", "v3"];
    const TYPES: &[&str] =
        &["REG_SZ", "REG_DWORD", "REG_QWORD", "REG_BINARY", "REG_MULTI_SZ", "REG_EXPAND_SZ"];

    let mut r = Rng(seed ^ 0xD1B5_4A32_D192_ED03);
    let mut keys: Vec<String> = Vec::new();
    let mut vals: Vec<(String, String)> = Vec::new();
    let mut ops = Vec::new();

    let rand_key = |r: &mut Rng| {
        let depth = 1 + r.below(3); // 1..=3 segments under Software
        let mut k = String::from("Software");
        for _ in 0..depth {
            k.push('\\');
            k.push_str(r.pick(SEGS));
        }
        k
    };

    for _ in 0..n {
        match r.below(100) {
            // delete a value that exists
            d if d < 20 && !vals.is_empty() => {
                let idx = r.below(vals.len() as u64) as usize;
                let (k, name) = vals.remove(idx);
                ops.push(format!("delete {k} /v {name} /f"));
            }
            // delete a key that exists (recursively, like reg.exe)
            d if d < 35 && !keys.is_empty() => {
                let idx = r.below(keys.len() as u64) as usize;
                let k = keys.remove(idx);
                let prefix = format!("{k}\\");
                keys.retain(|e| !e.starts_with(&prefix));
                vals.retain(|(vk, _)| vk != &k && !vk.starts_with(&prefix));
                ops.push(format!("delete {k} /f"));
            }
            // bare key add (no value): reg.exe stamps an empty default value on
            // the leaf whether the key is new (clients #71) or already exists
            // (clients #84), and our reg matches both, so we generate it freely.
            d if d < 50 => {
                let k = rand_key(&mut r);
                if !keys.contains(&k) {
                    keys.push(k.clone());
                }
                ops.push(format!("add {k} /f"));
            }
            // add (or overwrite) a value
            _ => {
                let k = rand_key(&mut r);
                let name = *r.pick(NAMES);
                let ty = *r.pick(TYPES);
                let data = gen_data(&mut r, ty);
                if !keys.contains(&k) {
                    keys.push(k.clone());
                }
                let pair = (k.clone(), name.to_string());
                if !vals.contains(&pair) {
                    vals.push(pair);
                }
                ops.push(format!("add {k} /v {name} /t {ty} /d {data} /f"));
            }
        }
    }
    ops
}

/// Type-appropriate, round-trip-safe value data (no spaces, quotes, or
/// backslashes that would need shell/`.reg` escaping at this stage).
fn gen_data(r: &mut Rng, ty: &str) -> String {
    match ty {
        "REG_DWORD" => format!("{}", r.next_u64() as u32),
        "REG_QWORD" => format!("{}", r.next_u64()),
        "REG_BINARY" => {
            let len = 1 + r.below(12);
            (0..len).map(|_| format!("{:02x}", r.below(256))).collect()
        }
        "REG_MULTI_SZ" => {
            let parts = 1 + r.below(3);
            (0..parts).map(|i| format!("s{i}")).collect::<Vec<_>>().join("\\0")
        }
        // An undefined variable name: cmd.exe leaves `%FZnn%` literal (a real env
        // var like %WINDIR% would be expanded by the Windows-side shell transport
        // before reg.exe sees it, which is a harness artifact, not a reg result).
        "REG_EXPAND_SZ" => format!("%FZ{:02}%", r.below(100)),
        _ => {
            let len = 1 + r.below(8);
            (0..len).map(|_| (b'a' + r.below(26) as u8) as char).collect()
        }
    }
}

// --- helpers ---

/// Create a fresh empty hive via the libreg agent for use as the seed.
fn make_seed(agent: &Client) -> Result<(), String> {
    let env = agent.call("POST", "/hive/create", &json!({ "path": SEED }))?;
    let h = handle(&env.data)?;
    agent.call("POST", "/hive/save", &json!({ "handle": h }))?;
    agent.call("POST", "/hive/close", &json!({ "handle": h }))?;
    Ok(())
}

/// Load a hive file into the libreg agent and return its canonical dump.
fn canonicalize(agent: &Client, path: &str) -> Result<Value, String> {
    let env = agent.call("POST", "/hive/load", &json!({ "path": path }))?;
    if !env.ok {
        return Err(format!("load {path}: {:?}", env.error));
    }
    let h = handle(&env.data)?;
    let dump = agent.call("GET", "/hive/dump", &json!({ "handle": h }))?;
    let canon = dump.data.get("canonical_json").cloned().ok_or("dump missing canonical_json")?;
    let _ = agent.call("POST", "/hive/close", &json!({ "handle": h }));
    Ok(canon)
}

fn handle(data: &Value) -> Result<String, String> {
    data.get("handle").and_then(|h| h.as_str()).map(|s| s.to_string()).ok_or_else(|| "no handle in response".to_string())
}

/// Run a command on the VM as SYSTEM via impacket atexec (task scheduler, SMB).
fn vm_exec(host: &str, cmd: &str) -> Result<(), String> {
    let out = Command::new("python3")
        .arg(ATEXEC)
        .arg(format!("{VM_ADMIN_USER}:{VM_ADMIN_PASS}@{host}"))
        .arg(cmd)
        .output()
        .map_err(|e| format!("running atexec: {e}"))?;
    let combined = format!("{}{}", String::from_utf8_lossy(&out.stdout), String::from_utf8_lossy(&out.stderr));
    if !out.status.success() {
        return Err(format!("atexec failed: {}", combined.trim()));
    }
    // reg.exe prints an error and the && chain stops; surface obvious failures.
    let low = combined.to_lowercase();
    if low.contains("access is denied") || low.contains("error:") || low.contains("the system was unable") {
        return Err(format!("reg.exe reported an error: {}", combined.trim()));
    }
    Ok(())
}

fn smb_cmd(host: &str, script: &str) -> Result<(), String> {
    let out = Command::new("smbclient")
        .arg(format!("//{host}/winreg"))
        .args(["-U", &format!("{VM_ADMIN_USER}%{VM_ADMIN_PASS}")])
        .args(["-c", script])
        .output()
        .map_err(|e| format!("running smbclient: {e}"))?;
    if !out.status.success() {
        return Err(String::from_utf8_lossy(&out.stderr).trim().to_string());
    }
    Ok(())
}

fn smb_put(host: &str, local: &str, remote: &str) -> Result<(), String> {
    smb_cmd(host, &format!("put {local} {remote}"))
}
fn smb_get(host: &str, remote: &str, local: &str) -> Result<(), String> {
    smb_cmd(host, &format!("get {remote} {local}"))
}
fn smb_del(host: &str, remote: &str) -> Result<(), String> {
    smb_cmd(host, &format!("del {remote}"))
}

/// Quote a Windows command argument if it contains whitespace.
fn win_quote(a: &str) -> String {
    if a.chars().any(char::is_whitespace) {
        format!("\"{a}\"")
    } else {
        a.to_string()
    }
}

/// Minimal quote-aware splitter: split on unquoted whitespace, strip double
/// quotes. Enough for `reg`/`sc` command tails.
fn shell_split(s: &str) -> Vec<String> {
    let mut out = Vec::new();
    let mut cur = String::new();
    let mut inq = false;
    let mut started = false;
    for c in s.chars() {
        match c {
            '"' => {
                inq = !inq;
                started = true;
            }
            c if c.is_whitespace() && !inq => {
                if started {
                    out.push(std::mem::take(&mut cur));
                    started = false;
                }
            }
            c => {
                cur.push(c);
                started = true;
            }
        }
    }
    if started {
        out.push(cur);
    }
    out
}

fn sanitize(s: &str) -> String {
    s.chars().map(|c| if c.is_ascii_alphanumeric() || c == '_' { c } else { '_' }).collect()
}

fn load_tests(dir: &Path) -> Vec<ClientTest> {
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
                if let Ok(t) = ClientTest::deserialize(doc) {
                    tests.push(t);
                }
            }
        }
    }
    tests
}
