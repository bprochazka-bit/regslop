//! Drive the differential harness binary over a directory of generated YAML.
//!
//! "Use the harness, do not reimplement" (CLAUDE-fuzz.md hard rule 3). The
//! fuzzer never compares hives itself: it writes sequences to a temp tests dir,
//! shells out to `libreg-harness`, and reads the `report.json` verdict. The
//! harness already knows how to start nothing (the agents are started
//! separately, e.g. by `scripts/run-fuzz.sh`) and to grade every CONTRACTS.md
//! axis.

use crate::triage::{self, FailureKind};
use serde_json::Value;
use std::path::{Path, PathBuf};
use std::process::Command;

/// Remove generated hive files and their `.LOG1`/`.LOG2` transaction-log
/// companions from a directory, matched by a basename marker. A leftover log
/// from a previous run is replayed on the next `hive_load` and silently changes
/// the reloaded hive, which surfaces as a phantom roundtrip failure. Every fuzzer
/// that reuses hive paths across runs sweeps before driving the agent so each run
/// is hermetic.
///
/// The marker is matched as a substring, not a prefix: the harness deconflicts
/// two local agents by prefixing the basename with the agent's port (issue #94),
/// so a generated `fuzz_<seed>.hiv` actually lands on disk as `7878-fuzz_...`.
/// A prefix match would miss those.
pub fn sweep_companions(dir: &Path, marker: &str) {
    if let Ok(rd) = std::fs::read_dir(dir) {
        for e in rd.flatten() {
            let name = e.file_name();
            let s = name.to_string_lossy();
            if s.contains(marker) && s.contains(".hiv") {
                let _ = std::fs::remove_file(e.path());
            }
        }
    }
}

/// Where the agents are and which harness binary to drive.
pub struct HarnessConfig {
    pub bin: PathBuf,
    pub linux_host: String,
    pub linux_port: u16,
    pub windows_host: Option<String>,
    pub windows_port: u16,
    pub lock_path: PathBuf,
    /// Extra flags appended verbatim (e.g. `--windows-smb`).
    pub extra: Vec<String>,
}

impl HarnessConfig {
    /// Single-agent local default: Linux agent on 7878, no Windows side.
    pub fn local(bin: PathBuf) -> Self {
        HarnessConfig {
            bin,
            linux_host: "127.0.0.1".to_string(),
            linux_port: 7878,
            windows_host: None,
            windows_port: 7879,
            lock_path: PathBuf::from("/tmp/libreg-winvm.lock"),
            extra: Vec::new(),
        }
    }
}

/// The harness's verdict for one generated test.
#[derive(Debug, Clone)]
pub struct Verdict {
    pub name: String,
    /// `None` means the test passed (or only warned). `Some` is a failure.
    pub kind: Option<FailureKind>,
    /// Human-readable failure detail, read from the per-failure summary.txt.
    pub detail: String,
}

impl Verdict {
    pub fn failed(&self) -> bool {
        self.kind.is_some()
    }
}

/// Run every YAML test under `tests_dir` through the harness, writing harness
/// artifacts under `results_dir`. Returns one `Verdict` per test.
pub fn run(cfg: &HarnessConfig, tests_dir: &Path, results_dir: &Path) -> Result<Vec<Verdict>, String> {
    let mut cmd = Command::new(&cfg.bin);
    cmd.arg("--linux-host").arg(&cfg.linux_host);
    cmd.arg("--linux-port").arg(cfg.linux_port.to_string());
    cmd.arg("--tests-dir").arg(tests_dir);
    cmd.arg("--results-dir").arg(results_dir);
    // No real corpus to grade here: point the corpus dir at the tests dir, which
    // has no `.hiv` files, so the corpus pass is a no-op instead of noise.
    cmd.arg("--corpus-dir").arg(tests_dir);
    cmd.arg("--lock-path").arg(&cfg.lock_path);
    if let Some(w) = &cfg.windows_host {
        cmd.arg("--windows-host").arg(w);
        cmd.arg("--windows-port").arg(cfg.windows_port.to_string());
    }
    for e in &cfg.extra {
        cmd.arg(e);
    }

    let out = cmd
        .output()
        .map_err(|e| format!("spawning harness {}: {e}", cfg.bin.display()))?;

    let stdout = String::from_utf8_lossy(&out.stdout);
    // The harness exits 2 on setup failure (agent down, version mismatch); a
    // graded run (green or red) exits 0/1. Distinguish: a report dir line is
    // only printed on a graded run.
    let report_dir = stdout
        .lines()
        .rev()
        .find_map(|l| l.strip_prefix("Report written to "))
        .map(|s| PathBuf::from(s.trim()));

    let Some(report_dir) = report_dir else {
        let stderr = String::from_utf8_lossy(&out.stderr);
        return Err(format!(
            "harness did not produce a report (exit {:?}). stderr:\n{}",
            out.status.code(),
            stderr.trim()
        ));
    };

    parse_report(&report_dir)
}

/// Read `report.json` and the per-failure `summary.txt` artifacts into verdicts.
pub fn parse_report(report_dir: &Path) -> Result<Vec<Verdict>, String> {
    let report_path = report_dir.join("report.json");
    let text = std::fs::read_to_string(&report_path)
        .map_err(|e| format!("reading {}: {e}", report_path.display()))?;
    let report: Value =
        serde_json::from_str(&text).map_err(|e| format!("parsing report.json: {e}"))?;

    let tests = report
        .get("tests")
        .and_then(|t| t.as_array())
        .ok_or("report.json has no tests array")?;

    let mut verdicts = Vec::with_capacity(tests.len());
    for t in tests {
        let name = t.get("name").and_then(|n| n.as_str()).unwrap_or("?").to_string();
        let kind = triage::classify(t);
        let detail = if kind.is_some() {
            read_summary(report_dir, &name).unwrap_or_default()
        } else {
            String::new()
        };
        verdicts.push(Verdict { name, kind, detail });
    }
    Ok(verdicts)
}

/// The harness writes failure detail to `failures/<safe_name>/summary.txt`,
/// where `safe_name` maps every non `[A-Za-z0-9_-]` char to `_` (see
/// `report.rs::safe_name`). Mirror that to find the file.
fn read_summary(report_dir: &Path, test_name: &str) -> Option<String> {
    let safe: String = test_name
        .chars()
        .map(|c| if c.is_ascii_alphanumeric() || c == '_' || c == '-' { c } else { '_' })
        .collect();
    let path = report_dir.join("failures").join(safe).join("summary.txt");
    std::fs::read_to_string(path).ok().map(|s| s.trim().to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_a_report_dir() {
        // Build a fake harness report dir and confirm we read verdicts back.
        let dir = std::env::temp_dir().join(format!("fuzz-report-test-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(dir.join("failures").join("fuzz_bad")).unwrap();
        let report = serde_json::json!({
            "tests": [
                { "name": "fuzz_good", "problems": [], "outcomes": {"semantic": "PASS"} },
                { "name": "fuzz_bad", "problems": [], "outcomes": {"structural": "FAIL"} },
            ]
        });
        std::fs::write(dir.join("report.json"), report.to_string()).unwrap();
        std::fs::write(
            dir.join("failures").join("fuzz_bad").join("summary.txt"),
            "structural: invariant 7 violated\n",
        )
        .unwrap();

        let verdicts = parse_report(&dir).unwrap();
        assert_eq!(verdicts.len(), 2);
        let good = verdicts.iter().find(|v| v.name == "fuzz_good").unwrap();
        assert!(!good.failed());
        let bad = verdicts.iter().find(|v| v.name == "fuzz_bad").unwrap();
        assert_eq!(bad.kind, Some(FailureKind::DifferStructural));
        assert!(bad.detail.contains("invariant 7"));

        let _ = std::fs::remove_dir_all(&dir);
    }
}
