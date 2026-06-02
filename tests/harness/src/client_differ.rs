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
