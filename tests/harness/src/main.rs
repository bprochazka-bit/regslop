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
mod corpus;
mod differ;
mod report;
mod runner;
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
            "-h" | "--help" => {
                println!(
                    "libreg-harness [--linux-host H] [--linux-port N] \\\n  \
                     [--windows-host H] [--windows-port N] [--tests-dir DIR] \\\n  \
                     [--results-dir DIR] [--lock-path PATH] [--tag TAG] \\\n  \
                     [--linux-hive-dir DIR] [--windows-hive-dir DIR] \\\n  \
                     [--corpus-dir DIR]"
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

fn main() -> ExitCode {
    let args = parse_args();

    let (lhost, lport) = split_host_port(&args.linux_host, args.linux_port);
    let mut linux = Client::new("linux", &lhost, lport);
    let mut windows = args.windows_host.as_ref().map(|h| {
        let (whost, wport) = split_host_port(h, args.windows_port);
        Client::new("windows", &whost, wport)
    });

    // Handshake. Abort on major version mismatch (CONTRACTS.md versioning).
    let lh = linux
        .version()
        .unwrap_or_else(|e| fatal(format!("{e}\nIs the Linux agent running on {lhost}:{lport}?")));
    eprintln!("Linux agent: agent={} protocol={} backend={}", lh.agent, lh.protocol, lh.backend);
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
