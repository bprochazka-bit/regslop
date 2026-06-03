//! Hive fuzzer: structure-aware byte mutation of corpus hives. Priority 3 of
//! the three modes (CLAUDE-fuzz.md). Takes a known-good hive, applies seeded
//! structural mutations, and loads the result via the libreg agent. The bar
//! (hard rule 7, and the mode's own goal) is that libreg either accepts the
//! mutated hive gracefully or rejects it with a clean error, but never crashes
//! and never reads out of bounds.
//!
//! Detection reuses the harness (hard rule 3): each mutated hive gets a tiny
//! load+validate sequence. A clean rejection shows as an `ok:false` op and is
//! acceptable; a crash or hang kills the agent, so the next op transport-errors,
//! which the harness records as a problem (a failure). When a mutated hive does
//! crash libreg, the mutation set is minimized to the smallest subset that still
//! crashes before being filed.
//!
//! Requires the agent to be started with `--backend libreg`: the in-memory
//! stand-in does not parse `regf` bytes. See `scripts/run-fuzz.sh`.
//!
//! Usage:
//!   hive_fuzz [--corpus PATH|DIR] [--seed S] [--count N] [--muts M]
//!             [--hive-dir DIR] [--out DIR] [--gen-only]
//!             [--harness-bin PATH] [--linux-port N]
//!             [--crashes-dir DIR] [--no-minimize]

use libreg_fuzz::generators::mutate::{self, Mutation};
use libreg_fuzz::harness_runner::{self, HarnessConfig};
use serde_json::json;
use std::path::{Path, PathBuf};

struct Args {
    corpus: PathBuf,
    seed: u64,
    count: u64,
    muts: usize,
    hive_dir: PathBuf,
    out: PathBuf,
    gen_only: bool,
    harness_bin: PathBuf,
    linux_port: u16,
    crashes_dir: PathBuf,
    minimize: bool,
}

impl Default for Args {
    fn default() -> Self {
        Args {
            corpus: PathBuf::from("tests/corpus/synthetic"),
            seed: 0x4956_4548_0000_0001,
            count: 200,
            muts: 4,
            hive_dir: PathBuf::from("/tmp"),
            out: PathBuf::from("tests/fuzz/corpus/pending-hive"),
            gen_only: false,
            harness_bin: PathBuf::from("tests/harness/target/release/libreg-harness"),
            linux_port: 7878,
            crashes_dir: PathBuf::from("tests/fuzz/corpus/crashes"),
            minimize: true,
        }
    }
}

fn fatal(msg: &str) -> ! {
    eprintln!("hive_fuzz error: {msg}");
    std::process::exit(2);
}

fn parse_args() -> Args {
    let mut a = Args::default();
    let mut it = std::env::args().skip(1);
    while let Some(arg) = it.next() {
        let mut next = || it.next().unwrap_or_else(|| fatal(&format!("{arg} needs a value")));
        match arg.as_str() {
            "--corpus" => a.corpus = PathBuf::from(next()),
            "--seed" => a.seed = next().parse().unwrap_or_else(|_| fatal("bad --seed")),
            "--count" => a.count = next().parse().unwrap_or_else(|_| fatal("bad --count")),
            "--muts" => a.muts = next().parse().unwrap_or_else(|_| fatal("bad --muts")),
            "--hive-dir" => a.hive_dir = PathBuf::from(next()),
            "--out" => a.out = PathBuf::from(next()),
            "--gen-only" => a.gen_only = true,
            "--harness-bin" => a.harness_bin = PathBuf::from(next()),
            "--linux-port" => a.linux_port = next().parse().unwrap_or_else(|_| fatal("bad --linux-port")),
            "--crashes-dir" => a.crashes_dir = PathBuf::from(next()),
            "--no-minimize" => a.minimize = false,
            "-h" | "--help" => {
                println!("hive_fuzz [--corpus PATH|DIR] [--seed S] [--count N] [--muts M] [--hive-dir DIR] [--out DIR] [--gen-only] [--harness-bin PATH] [--linux-port N] [--crashes-dir DIR] [--no-minimize]");
                std::process::exit(0);
            }
            other => fatal(&format!("unknown argument: {other}")),
        }
    }
    a
}

/// Gather the corpus hive files: either the one given file or every `.hiv` in a
/// directory.
fn corpus_files(path: &Path) -> Vec<PathBuf> {
    if path.is_file() {
        return vec![path.to_path_buf()];
    }
    let mut files = Vec::new();
    if let Ok(rd) = std::fs::read_dir(path) {
        for e in rd.flatten() {
            let p = e.path();
            if p.extension().and_then(|x| x.to_str()) == Some("hiv") {
                files.push(p);
            }
        }
    }
    files.sort();
    files
}

struct Case {
    name: String,
    /// Basename the mutated hive is written under in `hive_dir`.
    hive_name: String,
    seed: u64,
    base: String, // corpus file stem
    muts: Vec<Mutation>,
}

/// Write a mutated hive to `hive_dir/<hive_name>` and a YAML load+validate test
/// to `out_dir`. The YAML `path` uses the same basename so the harness maps it
/// back to this file.
fn materialize(case: &Case, original: &[u8], hive_dir: &Path, out_dir: &Path) {
    let mutated = mutate::apply_all(original, &case.muts);
    std::fs::write(hive_dir.join(&case.hive_name), &mutated)
        .unwrap_or_else(|e| fatal(&format!("writing mutated hive: {e}")));

    let logical = format!("/tmp/{}", case.hive_name);
    let ops = vec![
        json!({"op": "hive_load", "path": logical, "capture": "h"}),
        json!({"op": "hive_validate", "handle": "$h"}),
        json!({"op": "key_list", "handle": "$h", "path": ""}),
        json!({"op": "hive_close", "handle": "$h"}),
    ];
    let td = json!({
        "name": case.name,
        "tags": ["structural"],
        "operations": ops,
        "expect": { "semantic_equal": true },
    });
    let yaml = serde_yaml::to_string(&td).unwrap_or_default();
    std::fs::write(out_dir.join(format!("{}.yaml", case.name)), yaml)
        .unwrap_or_else(|e| fatal(&format!("writing test yaml: {e}")));
}

/// Run a single case through the harness and report whether libreg crashed
/// (any harness "problem", surfaced as a failing verdict). Re-materializes the
/// hive for the given mutation set first, so it doubles as the minimizer probe.
fn crashes(cfg: &HarnessConfig, case: &Case, original: &[u8], hive_dir: &Path) -> bool {
    let dir = std::env::temp_dir().join(format!("hive_fuzz_{}", case.name));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).ok();
    materialize(case, original, hive_dir, &dir);
    let res = dir.join("results");
    let verdict = harness_runner::run(cfg, &dir, &res)
        .ok()
        .and_then(|v| v.into_iter().find(|v| v.name == case.name))
        .map(|v| v.failed())
        .unwrap_or(false);
    let _ = std::fs::remove_dir_all(&dir);
    verdict
}

/// Greedily drop mutations while the crash persists, yielding a 1-minimal set.
fn minimize_muts(cfg: &HarnessConfig, case: &Case, original: &[u8], hive_dir: &Path) -> Vec<Mutation> {
    let mut keep = case.muts.clone();
    let mut changed = true;
    while changed && keep.len() > 1 {
        changed = false;
        for i in 0..keep.len() {
            let mut trial = keep.clone();
            trial.remove(i);
            let probe = Case { muts: trial.clone(), ..clone_case(case) };
            if crashes(cfg, &probe, original, hive_dir) {
                keep = trial;
                changed = true;
                break;
            }
        }
    }
    keep
}

fn clone_case(c: &Case) -> Case {
    Case {
        name: format!("{}_probe", c.name),
        hive_name: c.hive_name.clone(),
        seed: c.seed,
        base: c.base.clone(),
        muts: c.muts.clone(),
    }
}

fn main() {
    use libreg_fuzz::rng::Rng;
    let args = parse_args();
    let files = corpus_files(&args.corpus);
    if files.is_empty() {
        fatal(&format!("no corpus hives under {}", args.corpus.display()));
    }
    eprintln!("Corpus: {} hive(s) from {}", files.len(), args.corpus.display());

    let _ = std::fs::remove_dir_all(&args.out);
    std::fs::create_dir_all(&args.out).ok();
    std::fs::create_dir_all(&args.hive_dir).ok();
    // Clear stale mutated hives + their transaction logs so a load never replays
    // a previous run's log over a freshly written mutant.
    harness_runner::sweep_companions(&args.hive_dir, "hivefuzz_");

    // Load each corpus file once; reuse its bytes across its mutated children.
    let mut originals: Vec<(String, Vec<u8>)> = Vec::new();
    for f in &files {
        let stem = f.file_stem().and_then(|s| s.to_str()).unwrap_or("hive").to_string();
        match std::fs::read(f) {
            Ok(b) => originals.push((stem, b)),
            Err(e) => eprintln!("warning: cannot read {}: {e}", f.display()),
        }
    }

    let mut cases: Vec<Case> = Vec::new();
    for i in 0..args.count {
        let seed = args.seed.wrapping_add(i);
        let (stem, bytes) = &originals[(i as usize) % originals.len()];
        let mut rng = Rng::new(seed);
        let muts = mutate::plan(bytes, &mut rng, args.muts);
        let name = format!("hivefuzz_{stem}_{seed:016x}");
        let hive_name = format!("{name}.hiv");
        let case = Case { name, hive_name, seed, base: stem.clone(), muts };
        materialize(&case, bytes, &args.hive_dir, &args.out);
        cases.push(case);
    }
    eprintln!(
        "Generated {} mutated hives ({} mutations each) into {} (hives in {})",
        cases.len(), args.muts, args.out.display(), args.hive_dir.display()
    );

    if args.gen_only {
        return;
    }

    let cfg = HarnessConfig {
        bin: args.harness_bin.clone(),
        linux_host: "127.0.0.1".to_string(),
        linux_port: args.linux_port,
        windows_host: None,
        windows_port: 7879,
        lock_path: PathBuf::from("/tmp/libreg-winvm.lock"),
        extra: Vec::new(),
    };

    let verdicts = harness_runner::run(&cfg, &args.out, &PathBuf::from("tests/fuzz/results-hive"))
        .unwrap_or_else(|e| fatal(&format!("running harness: {e}")));
    let crashed: Vec<_> = verdicts.iter().filter(|v| v.failed()).collect();
    eprintln!(
        "\n{} mutated hives loaded: {} clean (accepted or cleanly rejected), {} CRASHED libreg",
        verdicts.len(),
        verdicts.len() - crashed.len(),
        crashed.len()
    );

    if crashed.is_empty() {
        eprintln!("No crashes. libreg rejected every malformed hive cleanly.");
        return;
    }

    std::fs::create_dir_all(&args.crashes_dir).ok();
    let by_name: std::collections::HashMap<&str, &Case> =
        cases.iter().map(|c| (c.name.as_str(), c)).collect();
    for v in &crashed {
        let Some(case) = by_name.get(v.name.as_str()) else { continue };
        let (_, original) = originals.iter().find(|(s, _)| *s == case.base).unwrap();
        let muts = if args.minimize {
            eprintln!("Minimizing crash {} ({} mutations) ...", v.name, case.muts.len());
            minimize_muts(&cfg, case, original, &args.hive_dir)
        } else {
            case.muts.clone()
        };
        // File the minimized mutated hive bytes plus a manifest of the mutations.
        let mutated = mutate::apply_all(original, &muts);
        let stem = format!("hivecrash_{}_{:016x}", case.base, case.seed);
        std::fs::write(args.crashes_dir.join(format!("{stem}.hiv")), &mutated).ok();
        let manifest = format!(
            "corpus_base: {}\nseed: {:#018x}\nmutations ({}):\n{}\n",
            case.base,
            case.seed,
            muts.len(),
            muts.iter().map(|m| format!("  {:?}", m)).collect::<Vec<_>>().join("\n"),
        );
        std::fs::write(args.crashes_dir.join(format!("{stem}.txt")), manifest).ok();
        eprintln!("  [P0] {} -> {}/{stem}.hiv ({} mutations)", v.name, args.crashes_dir.display(), muts.len());
    }
    std::process::exit(1);
}
