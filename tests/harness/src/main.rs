//! libreg differential harness CLI.
//!
//! Drives the Linux agent and, when `--windows-host` is given, the Windows
//! agent, runs every YAML test in the tests directory against both, compares
//! results across CONTRACTS.md axes, and writes a report.
//!
//! The harness does not prefer either side: when a differ fires it reports
//! which agent diverged and lets the implementing agent investigate.
//!
//! Single-agent mode (no `--windows-host`) is supported: cross-agent axes
//! (semantic, bytewise) report n/a, while structural and roundtrip still run
//! against the Linux agent alone. The same protocol drives any agent, so a
//! second Linux agent can stand in for the Windows side during bring-up.

mod client;
mod client_differ;
mod corpus;
mod differ;
mod recovery;
mod report;
mod runner;
mod smb;
mod util;

mod winvm_lock;

use client::Client;
use runner::{Agents, TestDef};
use serde::Deserialize;
use std::path::PathBuf;
use std::process::ExitCode;

struct Args {
    linux_host: String,
    linux_port: u16,
    windows_host: Option<String>,
    windows_port: u16,
    tests_dir: PathBuf,
    results_dir: PathBuf,
    lock_path: PathBuf,
    tag_filter: Option<String>,
    linux_hive_dir: String,
    windows_hive_dir: String,
    corpus_dir: PathBuf,
    windows_smb: bool,
    /// Client-differential mode: directory of client test YAMLs. When set, the
    /// harness validates the reg/sc CLIs vs the Windows tools instead of the
    /// agent differential.
    client_tests_dir: Option<PathBuf>,
    /// Path to the `reg` binary for client-differential mode.
    reg_bin: Option<PathBuf>,
    /// Path to the `sc` binary for client-differential mode.
    sc_bin: Option<PathBuf>,
    /// Directory of recovery test YAMLs. When set, the harness drives the
    /// crash-injection hook against the libreg agent and reports a `recovery`
    /// pass rate.
    recovery_tests_dir: Option<PathBuf>,
    /// Number of fuzzed `reg` operation sequences to run through the client
    /// differential (0 = off). Reported under the `fuzz` tag.
    client_fuzz: u32,
    /// Base seed for the client fuzzer (sequence i uses `seed + i`); fixed by
    /// default so runs are reproducible.
    client_fuzz_seed: u64,
    /// Operations per fuzzed sequence (batched into one VM round-trip).
    client_fuzz_ops: u32,
}

impl Default for Args {
    fn default() -> Self {
        Args {
            linux_host: "127.0.0.1".to_string(),
            linux_port: 7878,
            windows_host: None,
            windows_port: 7879,
            tests_dir: PathBuf::from("tests/harness/tests"),
            results_dir: PathBuf::from("tests/harness/results"),
            lock_path: PathBuf::from("/tmp/libreg-winvm.lock"),
            tag_filter: None,
            linux_hive_dir: "/tmp".to_string(),
            windows_hive_dir: "C:\\Windows\\Temp".to_string(),
            corpus_dir: PathBuf::from("tests/corpus/synthetic"),
            windows_smb: false,
            client_tests_dir: None,
            reg_bin: None,
            sc_bin: None,
            recovery_tests_dir: None,
            client_fuzz: 0,
            client_fuzz_seed: 0x5EED_1B5E_0000_0001,
            client_fuzz_ops: 20,
        }
    }
}

fn fatal(msg: impl AsRef<str>) -> ! {
    eprintln!("harness error: {}", msg.as_ref());
    std::process::exit(2);
}

fn parse_args() -> Args {
    let mut a = Args::default();
    let mut it = std::env::args().skip(1);
    while let Some(arg) = it.next() {
        let mut next = || it.next().unwrap_or_else(|| fatal(format!("{arg} needs a value")));
        match arg.as_str() {
            "--linux-host" => a.linux_host = next(),
            "--linux-port" => a.linux_port = next().parse().unwrap_or_else(|_| fatal("bad --linux-port")),
            "--windows-host" => a.windows_host = Some(next()),
            "--windows-port" => a.windows_port = next().parse().unwrap_or_else(|_| fatal("bad --windows-port")),
            "--tests-dir" => a.tests_dir = PathBuf::from(next()),
            "--results-dir" => a.results_dir = PathBuf::from(next()),
            "--lock-path" => a.lock_path = PathBuf::from(next()),
            "--tag" => a.tag_filter = Some(next()),
            "--linux-hive-dir" => a.linux_hive_dir = next(),
            "--windows-hive-dir" => a.windows_hive_dir = next(),
            "--corpus-dir" => a.corpus_dir = PathBuf::from(next()),
            "--windows-smb" => a.windows_smb = true,
            "--client-tests-dir" => a.client_tests_dir = Some(PathBuf::from(next())),
            "--reg-bin" => a.reg_bin = Some(PathBuf::from(next())),
            "--sc-bin" => a.sc_bin = Some(PathBuf::from(next())),
            "--recovery-tests-dir" => a.recovery_tests_dir = Some(PathBuf::from(next())),
            "--client-fuzz" => a.client_fuzz = next().parse().unwrap_or_else(|_| fatal("bad --client-fuzz")),
            "--client-fuzz-seed" => a.client_fuzz_seed = next().parse().unwrap_or_else(|_| fatal("bad --client-fuzz-seed")),
            "--client-fuzz-ops" => a.client_fuzz_ops = next().parse().unwrap_or_else(|_| fatal("bad --client-fuzz-ops")),
            "-h" | "--help" => {
                println!(
                    "libreg-harness [--linux-host H] [--linux-port N] \\\n  \
                     [--windows-host H] [--windows-port N] [--tests-dir DIR] \\\n  \
                     [--results-dir DIR] [--lock-path PATH] [--tag TAG] \\\n  \
                     [--linux-hive-dir DIR] [--windows-hive-dir DIR] \\\n  \
                     [--corpus-dir DIR] [--windows-smb] \\\n  \
                     [--client-tests-dir DIR] [--reg-bin PATH] [--sc-bin PATH] \\\n  \
                     [--recovery-tests-dir DIR] \\\n  \
                     [--client-fuzz N] [--client-fuzz-seed S] [--client-fuzz-ops K]"
                );
                std::process::exit(0);
            }
            other => fatal(format!("unknown argument: {other}")),
        }
    }
    a
}

fn major(version: &str) -> &str {
    version.split('.').next().unwrap_or(version)
}

/// Accept either a bare host or a `host:port` form, so `--windows-host
/// vmreg.lan:7879` works as well as `--windows-host vmreg.lan --windows-port
/// 7879`. A trailing numeric segment is treated as the port and overrides
/// `default_port`; an out-of-range port fails with a clear message rather than
/// surfacing as an opaque "invalid authority" URL error later.
fn split_host_port(host: &str, default_port: u16) -> (String, u16) {
    if let Some((h, p)) = host.rsplit_once(':') {
        if !p.is_empty() && p.chars().all(|c| c.is_ascii_digit()) {
            match p.parse::<u16>() {
                Ok(port) => return (h.to_string(), port),
                Err(_) => fatal(format!(
                    "port '{p}' in --host '{host}' is out of range (valid ports are 1 to 65535)"
                )),
            }
        }
    }
    (host.to_string(), default_port)
}

fn load_tests(dir: &PathBuf) -> Vec<TestDef> {
    let mut tests = Vec::new();
    let entries = std::fs::read_dir(dir)
        .unwrap_or_else(|e| fatal(format!("cannot read tests dir {}: {e}", dir.display())));
    let mut files: Vec<PathBuf> = entries
        .filter_map(|e| e.ok().map(|e| e.path()))
        .filter(|p| {
            matches!(p.extension().and_then(|x| x.to_str()), Some("yaml") | Some("yml"))
        })
        .collect();
    files.sort();
    for path in files {
        let content = std::fs::read_to_string(&path)
            .unwrap_or_else(|e| fatal(format!("reading {}: {e}", path.display())));
        // A file may contain multiple YAML documents separated by `---`.
        for doc in serde_yaml::Deserializer::from_str(&content) {
            match TestDef::deserialize(doc) {
                Ok(t) => tests.push(t),
                Err(e) => fatal(format!("parsing {}: {e}", path.display())),
            }
        }
    }
    tests
}

/// Client-differential mode: run the reg/sc CLI tests under `dir` against the
/// Windows tools on the VM, using `agent` (the libreg agent) to canonicalize
/// both result hives. Holds the VM flock for the run.
fn run_client_differential(agent: &Client, args: &Args) -> ExitCode {
    let vm_host = match &args.windows_host {
        Some(h) => split_host_port(h, 0).0,
        None => fatal("client-differential mode needs --windows-host (the VM)"),
    };
    if args.reg_bin.is_none() && args.sc_bin.is_none() {
        fatal("client-differential mode needs --reg-bin and/or --sc-bin");
    }
    if args.client_fuzz > 0 && args.reg_bin.is_none() {
        fatal("--client-fuzz needs --reg-bin (it fuzzes reg)");
    }
    let _lock = winvm_lock::WinVmLock::acquire(&args.lock_path).unwrap_or_else(|e| fatal(e));
    eprintln!("Client-differential vs reg.exe/sc.exe on {vm_host}");

    let mut all_passed = true;

    // Authored corpus (if a tests dir is given). Spec ruling (issue #68): the
    // client differential asserts the same canonical-JSON equality as the agent
    // path, so it reports under the existing `semantic` tag.
    if let Some(dir) = &args.client_tests_dir {
        let results =
            client_differ::run(agent, &vm_host, args.reg_bin.as_deref(), args.sc_bin.as_deref(), dir);
        all_passed &= report_client("semantic", &results);
    }

    // Fuzzed reg sequences, reported under the `fuzz` tag.
    if args.client_fuzz > 0 {
        let repro_dir = args.results_dir.join("client-fuzz");
        let reg_bin = args.reg_bin.as_deref().unwrap();
        eprintln!(
            "\nFuzzing reg: {} sequences x {} ops (base seed {:#018x})",
            args.client_fuzz, args.client_fuzz_ops, args.client_fuzz_seed
        );
        let results = client_differ::run_fuzz(
            agent,
            &vm_host,
            reg_bin,
            args.client_fuzz,
            args.client_fuzz_seed,
            args.client_fuzz_ops,
            &repro_dir,
        );
        all_passed &= report_client("fuzz", &results);
    }

    if all_passed {
        ExitCode::SUCCESS
    } else {
        ExitCode::from(1)
    }
}

/// Print per-case verdicts and a `<tag> (client-differential): passed/total`
/// summary; return whether every case passed.
fn report_client(tag: &str, results: &[client_differ::CaseResult]) -> bool {
    let total = results.len();
    let passed = results.iter().filter(|r| r.passed).count();
    eprintln!();
    for r in results {
        eprintln!("  {:34} {}", r.name, if r.passed { "PASS" } else { "FAIL" });
        if !r.passed {
            eprintln!("      {}", r.detail);
        }
    }
    eprintln!("\n{tag} (client-differential): {passed}/{total}");
    total > 0 && passed == total
}

fn main() -> ExitCode {
    let mut args = parse_args();
    // SMB byte-pull needs the Windows agent to save into the exported `winreg`
    // share, so force that hive dir when --windows-smb is on.
    if args.windows_smb {
        args.windows_hive_dir = "C:\\winreg".to_string();
    }

    let (lhost, lport) = split_host_port(&args.linux_host, args.linux_port);
    let mut linux = Client::new("linux", &lhost, lport);
    let windows_endpoint = args
        .windows_host
        .as_ref()
        .map(|h| split_host_port(h, args.windows_port));
    let mut windows = windows_endpoint
        .as_ref()
        .map(|(whost, wport)| Client::new("windows", whost, *wport));

    // Handshake. Abort on major version mismatch (CONTRACTS.md versioning).
    let lh = linux
        .version()
        .unwrap_or_else(|e| fatal(format!("{e}\nIs the Linux agent running on {lhost}:{lport}?")));
    eprintln!("Linux agent: agent={} protocol={} backend={}", lh.agent, lh.protocol, lh.backend);

    // Client-differential mode: validate the reg/sc CLIs vs the Windows tools.
    // Uses the (libreg) agent only to canonicalize result hives; no Windows
    // agent, so dispatch before the Windows handshake.
    if args.client_tests_dir.is_some() || args.client_fuzz > 0 {
        return run_client_differential(&linux, &args);
    }

    let mut windows_backend = None;
    let mut windows_agent = None;
    if let Some(w) = &windows {
        let wh = w.version().unwrap_or_else(|e| {
            fatal(format!(
                "{e}\nThe Windows agent did not respond. Note: the Windows agent is \
                 still a skeleton in this repo. For a local dry run use \
                 'scripts/run.sh --standin' (a second Linux agent stands in), or omit \
                 --windows-host to run single-agent."
            ))
        });
        eprintln!("Windows agent: agent={} protocol={} backend={}", wh.agent, wh.protocol, wh.backend);
        if major(&lh.protocol) != major(&wh.protocol) {
            fatal(format!(
                "protocol major version mismatch: linux={} windows={}; refusing to run",
                lh.protocol, wh.protocol
            ));
        }
        windows_agent = Some(wh.agent.clone());
        windows_backend = Some(wh.backend);
    }

    // Map logical hive paths to each agent's filesystem. The path style follows
    // the agent's reported `agent` field, not which side it is wired to, so a
    // Linux stand-in posing as the Windows side still gets Linux paths.
    let configure = |c: &mut Client, agent: &str| {
        let win = agent == "windows";
        let dir = if win { args.windows_hive_dir.clone() } else { args.linux_hive_dir.clone() };
        c.set_hive_location(dir, win);
    };
    configure(&mut linux, &lh.agent);
    if let (Some(w), Some(wa)) = (windows.as_mut(), windows_agent.as_ref()) {
        configure(w, wa);
    }

    // Enable SMB byte-pull on the real Windows agent (not a Linux stand-in,
    // which has no regf bytes to pull).
    if args.windows_smb {
        match (windows.as_mut(), windows_agent.as_deref(), windows_endpoint.as_ref()) {
            (Some(w), Some("windows"), Some((whost, _))) => {
                w.set_smb_host(whost.clone());
                eprintln!("SMB byte-pull enabled: pulling saved hives from //{whost}/winreg");
            }
            (Some(_), Some(other), _) => {
                eprintln!("warning: --windows-smb ignored; the windows-side agent reports '{other}', not offreg");
            }
            _ => {}
        }
    }

    // The Windows VM is a shared resource: serialize harness runs behind an
    // advisory lock. Only needed when actually driving the Windows agent.
    let _vm_lock = if windows.is_some() {
        Some(winvm_lock::WinVmLock::acquire(&args.lock_path).unwrap_or_else(|e| fatal(e)))
    } else {
        None
    };

    let mut tests = load_tests(&args.tests_dir);
    if let Some(tag) = &args.tag_filter {
        tests.retain(|t| t.tags.iter().any(|x| x == tag));
    }
    if tests.is_empty() {
        fatal(format!("no tests found in {}", args.tests_dir.display()));
    }
    eprintln!("Loaded {} tests from {}", tests.len(), args.tests_dir.display());

    let agents = Agents { linux: &linux, windows: windows.as_ref() };
    let mut results = Vec::with_capacity(tests.len());
    for t in &tests {
        results.push(runner::run_operations(t, &agents));
    }

    // Corpus: byte-level structural invariants against real hive files. This is
    // independent of the agents (it reads files), so it runs in every mode. The
    // corpus is tagged `structural`, so honor the tag filter.
    if args.tag_filter.as_deref().map_or(true, |t| t == "structural") {
        let corpus = corpus::run_corpus(&args.corpus_dir);
        if !corpus.is_empty() {
            eprintln!("Loaded {} corpus hives from {}", corpus.len(), args.corpus_dir.display());
            results.extend(corpus);
        }
    }

    // Recovery: drive the crash-injection hook against the libreg agent. Single
    // agent, tagged `recovery`, so honor the tag filter.
    if let Some(dir) = &args.recovery_tests_dir {
        if args.tag_filter.as_deref().map_or(true, |t| t == "recovery") {
            let rec = recovery::run(&linux, dir);
            if !rec.is_empty() {
                eprintln!("Ran {} recovery test(s) from {}", rec.len(), dir.display());
                results.extend(rec);
            }
        }
    }

    // Report how many saved hives got their on-disk bytes byte-validated on
    // each side (Linux reads local files, Windows pulls over SMB; only real
    // regf files are checked, so a MemBackend run shows 0).
    let lin_bytes: usize = results.iter().map(|r| r.linux.byte_invariants.len()).sum();
    let win_bytes: usize =
        results.iter().filter_map(|r| r.windows.as_ref()).map(|w| w.byte_invariants.len()).sum();
    if lin_bytes + win_bytes > 0 {
        eprintln!("Byte-level structural checks ran on {lin_bytes} Linux and {win_bytes} Windows hive(s)");
    }

    let now = util::now_unix();
    let meta = report::Meta {
        timestamp: util::iso8601(now),
        linux_backend: lh.backend,
        windows_backend,
    };
    let out_dir = args.results_dir.join(util::compact_stamp(now));
    let summary = report::write_all(&out_dir, &meta, &results, &tests)
        .unwrap_or_else(|e| fatal(format!("writing report: {e}")));

    // Echo the human-readable report to stdout.
    let (text, _) = report::render_text(&meta, &results);
    println!("{text}");
    println!("Report written to {}", out_dir.display());

    if summary.green {
        ExitCode::SUCCESS
    } else {
        ExitCode::FAILURE
    }
}
