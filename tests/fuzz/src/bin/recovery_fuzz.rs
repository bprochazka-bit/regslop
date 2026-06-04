//! Recovery fuzzer: generate baseline+mutation sequences with a crash point,
//! feed them to the harness recovery runner, and report cases where the hive
//! recovered after a simulated crash does not match the intended pre-crash
//! state. A mismatch is data loss or corruption in libreg's transaction-log
//! replay (the layer that bug #97 lived in).
//!
//! The harness owns the crash-injection protocol (`POST /test/crash_save`,
//! `tests/harness/src/recovery.rs`); this binary only generates the YAML cases
//! and drives the harness with `--recovery-tests-dir`. Needs `--backend libreg`
//! (the in-memory backend has no logs and reports recovery as n/a).
//!
//! Usage:
//!   recovery_fuzz [--seed S] [--count N] [--out DIR] [--gen-only]
//!                 [--harness-bin PATH] [--linux-port N] [--interesting-dir DIR]

use libreg_fuzz::generators::recovery::{self, RecSeq};
use libreg_fuzz::harness_runner::{self, HarnessConfig};
use libreg_fuzz::triage::{self, FailureKind};
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

struct Args {
    seed: u64,
    count: u64,
    out: PathBuf,
    gen_only: bool,
    harness_bin: PathBuf,
    linux_port: u16,
    interesting_dir: PathBuf,
}

impl Default for Args {
    fn default() -> Self {
        Args {
            seed: 0x5EC0_0000_0000_0001,
            count: 60,
            out: PathBuf::from("tests/fuzz/corpus/pending-recovery"),
            gen_only: false,
            harness_bin: PathBuf::from("tests/harness/target/release/libreg-harness"),
            linux_port: 7878,
            interesting_dir: PathBuf::from("tests/fuzz/corpus/interesting"),
        }
    }
}

fn fatal(msg: &str) -> ! {
    eprintln!("recovery_fuzz error: {msg}");
    std::process::exit(2);
}

fn parse_args() -> Args {
    let mut a = Args::default();
    let mut it = std::env::args().skip(1);
    while let Some(arg) = it.next() {
        let mut next = || it.next().unwrap_or_else(|| fatal(&format!("{arg} needs a value")));
        match arg.as_str() {
            "--seed" => {
                let s = next();
                a.seed = s.strip_prefix("0x").map(|h| u64::from_str_radix(h, 16))
                    .unwrap_or_else(|| s.parse()).unwrap_or_else(|_| fatal("bad --seed"));
            }
            "--count" => a.count = next().parse().unwrap_or_else(|_| fatal("bad --count")),
            "--out" => a.out = PathBuf::from(next()),
            "--gen-only" => a.gen_only = true,
            "--harness-bin" => a.harness_bin = PathBuf::from(next()),
            "--linux-port" => a.linux_port = next().parse().unwrap_or_else(|_| fatal("bad --linux-port")),
            "--interesting-dir" => a.interesting_dir = PathBuf::from(next()),
            "-h" | "--help" => {
                println!("recovery_fuzz [--seed S] [--count N] [--out DIR] [--gen-only] [--harness-bin PATH] [--linux-port N] [--interesting-dir DIR]");
                std::process::exit(0);
            }
            other => fatal(&format!("unknown argument: {other}")),
        }
    }
    a
}

fn write_case(dir: &Path, c: &RecSeq) {
    std::fs::write(dir.join(format!("{}.yaml", c.name)), c.to_yaml())
        .unwrap_or_else(|e| fatal(&format!("writing {}: {e}", c.name)));
}

fn main() {
    let args = parse_args();

    // 1. Generate, cycling the three crash points so each gets coverage.
    let _ = std::fs::remove_dir_all(&args.out);
    std::fs::create_dir_all(&args.out).ok();
    let mut cases: Vec<RecSeq> = Vec::with_capacity(args.count as usize);
    for i in 0..args.count {
        let c = recovery::generate(args.seed.wrapping_add(i), i as usize);
        write_case(&args.out, &c);
        cases.push(c);
    }
    eprintln!(
        "Generated {} recovery cases (seed {:#018x}) into {}; crash points cycled over {:?}",
        args.count, args.seed, args.out.display(), recovery::CRASH_POINTS
    );

    if args.gen_only {
        return;
    }

    // The harness needs a non-empty --tests-dir (it fatals otherwise). Recovery
    // cases live in a separate dir it reads via --recovery-tests-dir, so give it
    // a trivial placeholder here that contributes nothing (recovery=n/a).
    let placeholder_dir = args.out.join("_placeholder");
    std::fs::create_dir_all(&placeholder_dir).ok();
    std::fs::write(
        placeholder_dir.join("placeholder.yaml"),
        "name: rf_placeholder\ntags: [recovery]\noperations:\n  - op: hive_create\n    path: /tmp/rf_placeholder.hiv\n    capture: h\n  - op: hive_save\n    handle: $h\n",
    ).ok();

    // Sweep stale recovery hives + logs so no reload replays an old log.
    harness_runner::sweep_companions(Path::new("/tmp"), "rec_");

    let cfg = HarnessConfig {
        bin: args.harness_bin.clone(),
        linux_host: "127.0.0.1".to_string(),
        linux_port: args.linux_port,
        windows_host: None,
        windows_port: 7879,
        lock_path: PathBuf::from("/tmp/libreg-winvm.lock"),
        extra: vec!["--recovery-tests-dir".to_string(), args.out.to_string_lossy().to_string()],
    };
    let verdicts = harness_runner::run(&cfg, &placeholder_dir, &PathBuf::from("tests/fuzz/results-recovery"))
        .unwrap_or_else(|e| fatal(&format!("running harness: {e}")));

    // Only recovery-kind verdicts are ours; the placeholder is recovery=n/a.
    let mine: Vec<_> = verdicts.iter().filter(|v| v.name.starts_with("recfuzz_") || v.name == "clean_primary_suppresses_stale_log").collect();
    let fails: Vec<_> = mine.iter().filter(|v| v.kind == Some(FailureKind::Recovery)).collect();
    let graded = mine.iter().filter(|v| v.name.starts_with("recfuzz_")).count();
    eprintln!(
        "\nRecovery: {} cases graded, {} recovered correctly, {} FAILED",
        graded,
        graded - fails.iter().filter(|v| v.name.starts_with("recfuzz_")).count(),
        fails.len()
    );

    if fails.is_empty() {
        eprintln!("No recovery failures: every crash point recovered to the intended state.");
        // Surface whether cases actually ran (libreg backend) vs were skipped (n/a).
        if graded == 0 {
            eprintln!("WARNING: 0 cases graded. Is the agent running --backend libreg? (mem reports n/a)");
        }
        return;
    }

    std::fs::create_dir_all(&args.interesting_dir).ok();
    let by_name: std::collections::HashMap<&str, &RecSeq> =
        cases.iter().map(|c| (c.name.as_str(), c)).collect();
    let mut seen = std::collections::HashSet::new();
    for v in &fails {
        let sig = triage::signature(FailureKind::Recovery, &v.detail);
        if !seen.insert(sig) {
            continue;
        }
        let fname = format!("recovery_{:016x}.yaml", sig);
        if let Some(c) = by_name.get(v.name.as_str()) {
            std::fs::write(args.interesting_dir.join(&fname), c.to_yaml()).ok();
        }
        let when = SystemTime::now().duration_since(UNIX_EPOCH).map(|d| d.as_secs()).unwrap_or(0);
        if let Ok(mut f) = std::fs::OpenOptions::new().create(true).append(true).open("tests/fuzz/triage.log") {
            use std::io::Write;
            let _ = writeln!(
                f, "{when} P1 recovery sig={sig:#018x} from={} file={} \n  detail: {}",
                v.name, args.interesting_dir.join(&fname).display(), v.detail.replace('\n', " | ")
            );
        }
        eprintln!("  [P1] {} ({}) -> {}", v.name, v.detail.split(':').next().unwrap_or(""), fname);
    }
    eprintln!("\nFiled {} unique recovery finding(s) to {}", seen.len(), args.interesting_dir.display());
    std::process::exit(1);
}
