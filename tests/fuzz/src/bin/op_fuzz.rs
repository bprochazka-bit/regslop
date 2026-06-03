//! Operation fuzzer: generate weighted-random operation sequences, run them
//! through the differential harness, and triage any failures.
//!
//! Priority 1 of the three fuzzing modes (CLAUDE-fuzz.md). Determinism is the
//! core contract: `--seed S --count N` always produces the same N sequences
//! (sequence i uses `S + i`), so any failure replays from `(seed, libreg
//! commit)`.
//!
//! Usage:
//!   op_fuzz [--seed S] [--count N] [--ops K] [--out DIR] [--gen-only]
//!           [--harness-bin PATH] [--linux-port N]
//!           [--windows-host H] [--windows-port N]
//!           [--crashes-dir DIR] [--no-minimize]
//!
//! Without `--gen-only` the agents must already be running (see
//! `scripts/run-fuzz.sh`, which starts them and then calls this).

use libreg_fuzz::coverage::Coverage;
use libreg_fuzz::generators::ops::{self, OpSeq};
use libreg_fuzz::harness_runner::{self, HarnessConfig, Verdict};
use libreg_fuzz::triage::{self, FailureKind};
use std::collections::HashSet;
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

struct Args {
    seed: u64,
    count: u64,
    ops: usize,
    out: PathBuf,
    gen_only: bool,
    harness_bin: PathBuf,
    linux_host: String,
    linux_port: u16,
    windows_host: Option<String>,
    windows_port: u16,
    crashes_dir: PathBuf,
    interesting_dir: PathBuf,
    /// The agent's hive directory (where `/tmp/fuzz_*.hiv` actually land). Swept
    /// of stale generated hives and their .LOG companions before each run so a
    /// reload never replays a previous run's transaction log (a real source of
    /// false roundtrip failures: the harness reuses a path per seed across runs).
    hive_dir: PathBuf,
    minimize: bool,
    extra: Vec<String>,
}

impl Default for Args {
    fn default() -> Self {
        Args {
            seed: 0x5EED_0000_0000_0001,
            count: 200,
            ops: 40,
            out: PathBuf::from("tests/fuzz/corpus/pending"),
            gen_only: false,
            harness_bin: PathBuf::from("tests/harness/target/release/libreg-harness"),
            linux_host: "127.0.0.1".to_string(),
            linux_port: 7878,
            windows_host: None,
            windows_port: 7879,
            crashes_dir: PathBuf::from("tests/fuzz/corpus/crashes"),
            interesting_dir: PathBuf::from("tests/fuzz/corpus/interesting"),
            hive_dir: PathBuf::from("/tmp"),
            minimize: true,
            extra: Vec::new(),
        }
    }
}

fn parse_args() -> Args {
    let mut a = Args::default();
    let mut it = std::env::args().skip(1);
    while let Some(arg) = it.next() {
        let mut next = || it.next().unwrap_or_else(|| fatal(&format!("{arg} needs a value")));
        match arg.as_str() {
            "--seed" => a.seed = parse_seed(&next()),
            "--count" => a.count = next().parse().unwrap_or_else(|_| fatal("bad --count")),
            "--ops" => a.ops = next().parse().unwrap_or_else(|_| fatal("bad --ops")),
            "--out" => a.out = PathBuf::from(next()),
            "--gen-only" => a.gen_only = true,
            "--harness-bin" => a.harness_bin = PathBuf::from(next()),
            "--linux-host" => a.linux_host = next(),
            "--linux-port" => a.linux_port = next().parse().unwrap_or_else(|_| fatal("bad --linux-port")),
            "--windows-host" => a.windows_host = Some(next()),
            "--windows-port" => a.windows_port = next().parse().unwrap_or_else(|_| fatal("bad --windows-port")),
            "--crashes-dir" => a.crashes_dir = PathBuf::from(next()),
            "--interesting-dir" => a.interesting_dir = PathBuf::from(next()),
            "--hive-dir" => a.hive_dir = PathBuf::from(next()),
            "--no-minimize" => a.minimize = false,
            "--windows-smb" => a.extra.push("--windows-smb".to_string()),
            "-h" | "--help" => {
                println!(
                    "op_fuzz [--seed S] [--count N] [--ops K] [--out DIR] [--gen-only]\n        \
                     [--harness-bin PATH] [--linux-host H] [--linux-port N]\n        \
                     [--windows-host H] [--windows-port N] [--windows-smb]\n        \
                     [--crashes-dir DIR] [--interesting-dir DIR]\n        \
                     [--hive-dir DIR] [--no-minimize]"
                );
                std::process::exit(0);
            }
            other => fatal(&format!("unknown argument: {other}")),
        }
    }
    a
}

/// Accept decimal or `0x`-prefixed hex seeds.
fn parse_seed(s: &str) -> u64 {
    let t = s.trim();
    let r = if let Some(hex) = t.strip_prefix("0x").or_else(|| t.strip_prefix("0X")) {
        u64::from_str_radix(hex, 16)
    } else {
        t.parse()
    };
    r.unwrap_or_else(|_| fatal("bad --seed"))
}

fn fatal(msg: &str) -> ! {
    eprintln!("op_fuzz error: {msg}");
    std::process::exit(2);
}

/// Ops that make the in-memory hive diverge from what is on disk. After the last
/// one of these, a `hive_save` is required for the persisted state to match the
/// final in-memory state (`hive_load` is excluded: it resets memory to disk, so
/// it leaves the two consistent).
const MUTATORS: &[&str] = &[
    "key_create", "key_delete", "key_rename", "value_set", "value_delete", "key_security_set",
];

/// True if the sequence has no unsaved modification at the end: every mutating op
/// is followed by a `hive_save`. Only such sequences are valid roundtrip tests
/// (final in-memory state == last saved state). The minimizer must keep this
/// invariant, else it shrinks a real save/reload divergence down to a trivial
/// "this change was never saved, so disk differs" sequence, which is not a bug.
fn roundtrip_consistent(seq: &OpSeq) -> bool {
    let op_at = |i: usize| seq.operations[i].get("op").and_then(|v| v.as_str()).unwrap_or("");
    let last_mut = (0..seq.operations.len()).rev().find(|&i| MUTATORS.contains(&op_at(i)));
    let last_save = (0..seq.operations.len()).rev().find(|&i| op_at(i) == "hive_save");
    match last_mut {
        None => true,
        Some(m) => last_save.is_some_and(|s| s > m),
    }
}

fn write_seq(dir: &Path, seq: &OpSeq) -> std::io::Result<()> {
    std::fs::create_dir_all(dir)?;
    std::fs::write(dir.join(format!("{}.yaml", seq.name)), seq.to_yaml())
}

/// Sweep this fuzzer's generated hives + transaction logs from the agent's hive
/// dir so no reload replays a stale log (see `harness_runner::sweep_companions`).
fn sweep_hive_dir(dir: &Path) {
    harness_runner::sweep_companions(dir, "fuzz_");
}

fn main() {
    let args = parse_args();

    // 1. Generate. Coverage steers op selection across the whole batch.
    let mut cov = Coverage::new();
    let mut seqs: Vec<OpSeq> = Vec::with_capacity(args.count as usize);
    for i in 0..args.count {
        seqs.push(ops::generate(args.seed.wrapping_add(i), args.ops, &mut cov));
    }

    // Fresh output dir so a re-run does not mix old sequences in.
    let _ = std::fs::remove_dir_all(&args.out);
    for seq in &seqs {
        write_seq(&args.out, seq).unwrap_or_else(|e| fatal(&format!("writing sequence: {e}")));
    }
    eprintln!(
        "Generated {} sequences (seed {:#018x}, {} ops each) into {}",
        args.count, args.seed, args.ops, args.out.display()
    );
    print_coverage(&cov);

    if args.gen_only {
        return;
    }

    // 2. Run the whole batch through the harness once. Sweep stale hives +
    // transaction logs first so no reload replays a previous run's log.
    sweep_hive_dir(&args.hive_dir);
    let cfg = HarnessConfig {
        bin: args.harness_bin.clone(),
        linux_host: args.linux_host.clone(),
        linux_port: args.linux_port,
        windows_host: args.windows_host.clone(),
        windows_port: args.windows_port,
        lock_path: PathBuf::from("/tmp/libreg-winvm.lock"),
        extra: args.extra.clone(),
    };
    let results_root = PathBuf::from("tests/fuzz/results");
    let verdicts = harness_runner::run(&cfg, &args.out, &results_root)
        .unwrap_or_else(|e| fatal(&format!("running harness: {e}")));

    let by_name: std::collections::HashMap<&str, &OpSeq> =
        seqs.iter().map(|s| (s.name.as_str(), s)).collect();

    let failures: Vec<&Verdict> = verdicts.iter().filter(|v| v.failed()).collect();
    eprintln!(
        "\nHarness graded {} sequences: {} passed, {} failed",
        verdicts.len(),
        verdicts.len() - failures.len(),
        failures.len()
    );

    if failures.is_empty() {
        eprintln!("No divergences or crashes. Green.");
        return;
    }

    // 3. Triage: dedup by signature, minimize, file, log. Crashes and hangs
    // (P0) go to corpus/crashes/; differ findings (P1) to corpus/interesting/,
    // matching the tests/fuzz layout in CLAUDE-fuzz.md.
    std::fs::create_dir_all(&args.crashes_dir).ok();
    std::fs::create_dir_all(&args.interesting_dir).ok();
    let mut seen: HashSet<u64> = HashSet::new();
    let mut filed = 0;
    for v in failures {
        let kind = v.kind.unwrap();
        let sig = triage::signature(kind, &v.detail);
        if !seen.insert(sig) {
            continue; // same bug shape already filed this run
        }
        let Some(seq) = by_name.get(v.name.as_str()) else { continue };

        let minimized = if args.minimize {
            eprintln!("Minimizing {} ({}, sig {:#018x}) ...", v.name, kind.as_str(), sig);
            let cfg = &cfg;
            let hive_dir = &args.hive_dir;
            // Preserve the exact failure SIGNATURE, not just the kind. A coarser
            // "same kind" predicate lets minimization slip to a different bug of
            // the same kind (e.g. dropping the trailing hive_save turns a real
            // save/reload divergence into a trivial "unsaved change differs from
            // disk" mismatch). Requiring the same signature keeps the repro
            // faithful to the finding.
            triage::minimize(seq, |cand| {
                // Reject any candidate that ends with an unsaved modification:
                // it would be a trivial mismatch, not the real save/reload bug.
                roundtrip_consistent(cand)
                    && run_single(cfg, hive_dir, cand)
                        .map(|(k, detail)| (k, triage::signature(k, &detail)))
                        == Some((kind, sig))
            })
        } else {
            OpSeq { name: format!("{}_min", v.name), tags: seq.tags.clone(),
                    operations: seq.operations.clone(),
                    expect: ops::ExpectOut { semantic_equal: seq.expect.semantic_equal } }
        };

        let dir = if kind.priority() == "P0" { &args.crashes_dir } else { &args.interesting_dir };
        let fname = format!("{}_{:016x}.yaml", kind.as_str().replace('-', "_"), sig);
        let path = dir.join(&fname);
        std::fs::write(&path, minimized.to_yaml()).ok();
        append_triage_log(kind, sig, v, &minimized, &path);
        filed += 1;
        eprintln!(
            "  [{}] {} -> {} ({} ops)",
            kind.priority(), v.name, path.display(), minimized.operations.len()
        );
    }

    eprintln!(
        "\nFiled {} unique finding(s) ({} raw failures); P0 -> {}, P1 -> {}",
        filed,
        verdicts.iter().filter(|v| v.failed()).count(),
        args.crashes_dir.display(),
        args.interesting_dir.display()
    );
    std::process::exit(1);
}

/// Run a single sequence through the harness and return its failure kind and
/// detail (if it failed). Used as the minimizer's reproduction predicate; the
/// caller hashes the detail into a signature so minimization preserves the exact
/// failure, not merely its category.
fn run_single(cfg: &HarnessConfig, hive_dir: &Path, seq: &OpSeq) -> Option<(FailureKind, String)> {
    // Probes reuse the same hive path, so sweep its stale logs before each one.
    sweep_hive_dir(hive_dir);
    let dir = std::env::temp_dir().join(format!("op_fuzz_min_{}", unique_suffix(seq)));
    let _ = std::fs::remove_dir_all(&dir);
    if write_seq(&dir, seq).is_err() {
        return None;
    }
    let res_dir = dir.join("results");
    let verdicts = harness_runner::run(cfg, &dir, &res_dir).ok()?;
    let v = verdicts.into_iter().find(|v| v.name == seq.name)?;
    let _ = std::fs::remove_dir_all(&dir);
    v.kind.map(|k| (k, v.detail))
}

/// A stable-per-content suffix so concurrent/sequential minimizer probes do not
/// collide on the same temp dir. Content hash, not a clock, keeps it tidy.
fn unique_suffix(seq: &OpSeq) -> String {
    format!("{:016x}", triage::fnv1a(&seq.to_yaml()))
}

fn append_triage_log(kind: FailureKind, sig: u64, v: &Verdict, min: &OpSeq, path: &Path) {
    use std::io::Write;
    let when = SystemTime::now().duration_since(UNIX_EPOCH).map(|d| d.as_secs()).unwrap_or(0);
    let line = format!(
        "{when} {} {} sig={:#018x} from={} minimized_ops={} file={}\n  detail: {}\n",
        kind.priority(),
        kind.as_str(),
        sig,
        v.name,
        min.operations.len(),
        path.display(),
        v.detail.replace('\n', " | "),
    );
    if let Ok(mut f) = std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open("tests/fuzz/triage.log")
    {
        let _ = f.write_all(line.as_bytes());
    }
}

fn print_coverage(cov: &Coverage) {
    eprintln!("Endpoint coverage ({:.0}% of endpoints hit):", cov.fraction_hit() * 100.0);
    for (op, n) in cov.report() {
        eprintln!("  {op:<20} {n}");
    }
    let unhit = cov.unhit();
    if !unhit.is_empty() {
        eprintln!("  not yet hit: {unhit:?}");
    }
}
