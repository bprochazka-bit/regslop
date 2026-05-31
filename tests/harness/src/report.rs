//! Report aggregation and output. Produces the per-tag pass-rate table from
//! the harness CLAUDE.md, a machine-readable JSON sibling, and a per-failure
//! directory containing enough to reproduce (the operation sequence and both
//! canonical dumps), per hard rule 2 (every test is reproducible).

use crate::runner::{AspectOutcome, TestDef, TestResult};
use serde_json::{json, Value};
use std::path::{Path, PathBuf};

/// The canonical tag set, in report order (CONTRACTS.md "Test Categories").
pub const TAGS: [&str; 6] = ["semantic", "structural", "bytewise", "roundtrip", "recovery", "fuzz"];

#[derive(Debug, Default, Clone)]
pub struct TagStat {
    pub total: usize,
    pub passed: usize,
    pub warnings: usize,
    pub failures: usize,
}

pub struct Meta {
    pub timestamp: String,
    pub linux_backend: String,
    pub windows_backend: Option<String>,
}

pub struct Summary {
    pub green: bool,
    // Surfaced in the returned summary for callers/CI that want counts beyond
    // the green/red bit.
    #[allow(dead_code)]
    pub total_failures: usize,
    #[allow(dead_code)]
    pub total_warnings: usize,
}

fn aggregate(results: &[TestResult]) -> Vec<(&'static str, TagStat)> {
    TAGS.iter()
        .map(|&tag| {
            let mut stat = TagStat::default();
            for r in results {
                if !r.tags.iter().any(|t| t == tag) {
                    continue;
                }
                match r.outcome_for_tag(tag) {
                    AspectOutcome::Pass => {
                        stat.total += 1;
                        stat.passed += 1;
                    }
                    AspectOutcome::Warn(_) => {
                        stat.total += 1;
                        stat.passed += 1; // a warning still passes
                        stat.warnings += 1;
                    }
                    AspectOutcome::Fail(_) => {
                        stat.total += 1;
                        stat.failures += 1;
                    }
                    AspectOutcome::Na => {} // not counted in the denominator
                }
            }
            (tag, stat)
        })
        .collect()
}

fn outcome_label(o: &AspectOutcome) -> &'static str {
    match o {
        AspectOutcome::Pass => "PASS",
        AspectOutcome::Warn(_) => "WARN",
        AspectOutcome::Fail(_) => "FAIL",
        AspectOutcome::Na => "n/a",
    }
}

pub fn render_text(meta: &Meta, results: &[TestResult]) -> (String, Summary) {
    let stats = aggregate(results);
    let mut out = String::new();
    out.push_str(&format!("libreg harness run {}\n", meta.timestamp));
    out.push_str(&format!("Linux agent: {}\n", meta.linux_backend));
    match &meta.windows_backend {
        Some(w) => out.push_str(&format!("Windows agent: {w}\n")),
        None => out.push_str("Windows agent: (absent, single-agent mode)\n"),
    }
    out.push('\n');

    let mut total_failures = 0;
    let mut total_warnings = 0;
    for (tag, s) in &stats {
        total_failures += s.failures;
        total_warnings += s.warnings;
        let line = if s.total == 0 {
            format!("{:<12} n/a\n", format!("{tag}:"))
        } else {
            let pct = 100.0 * s.passed as f64 / s.total as f64;
            let mut note = String::new();
            if s.warnings > 0 || s.failures > 0 {
                note = format!(
                    " [{} warnings, {} failures]",
                    s.warnings, s.failures
                );
            }
            format!(
                "{:<12} {}/{} ({:5.1}%){}\n",
                format!("{tag}:"),
                s.passed,
                s.total,
                pct,
                note
            )
        };
        out.push_str(&line);
    }

    out.push('\n');
    let green = total_failures == 0;
    out.push_str(&format!(
        "Overall: {} ({} failures, {} warnings)\n",
        if green { "GREEN" } else { "RED" },
        total_failures,
        total_warnings
    ));

    // Per-test detail, so a failing run is legible without opening the dirs.
    out.push_str("\nPer-test:\n");
    for r in results {
        let tagcols: Vec<String> = r
            .tags
            .iter()
            .map(|t| format!("{t}={}", outcome_label(r.outcome_for_tag(t))))
            .collect();
        out.push_str(&format!("  {:<28} {}\n", r.name, tagcols.join(" ")));
        for p in &r.problems {
            out.push_str(&format!("      ! {p}\n"));
        }
        for tag in r.tags.iter() {
            if let AspectOutcome::Fail(msg) | AspectOutcome::Warn(msg) = r.outcome_for_tag(tag) {
                out.push_str(&format!("      {tag}: {msg}\n"));
            }
        }
    }

    (out, Summary { green, total_failures, total_warnings })
}

pub fn render_json(meta: &Meta, results: &[TestResult]) -> Value {
    let stats = aggregate(results);
    let tags_json: Value = stats
        .iter()
        .map(|(tag, s)| {
            (
                tag.to_string(),
                json!({
                    "total": s.total,
                    "passed": s.passed,
                    "warnings": s.warnings,
                    "failures": s.failures,
                }),
            )
        })
        .collect::<serde_json::Map<_, _>>()
        .into();

    let tests_json: Vec<Value> = results
        .iter()
        .map(|r| {
            let outcomes: serde_json::Map<String, Value> = r
                .tags
                .iter()
                .map(|t| (t.clone(), json!(outcome_label(r.outcome_for_tag(t)))))
                .collect();
            json!({
                "name": r.name,
                "tags": r.tags,
                "problems": r.problems,
                "outcomes": outcomes,
            })
        })
        .collect();

    json!({
        "timestamp": meta.timestamp,
        "linux_backend": meta.linux_backend,
        "windows_backend": meta.windows_backend,
        "tags": tags_json,
        "tests": tests_json,
    })
}

fn test_failed(r: &TestResult) -> bool {
    !r.problems.is_empty()
        || r.tags.iter().any(|t| matches!(r.outcome_for_tag(t), AspectOutcome::Fail(_)))
}

/// Write report.txt, report.json, and per-failure directories under `out_dir`.
/// `tests` is parallel to `results` for reproduction artifacts.
pub fn write_all(
    out_dir: &Path,
    meta: &Meta,
    results: &[TestResult],
    tests: &[TestDef],
) -> std::io::Result<Summary> {
    std::fs::create_dir_all(out_dir)?;
    let (text, summary) = render_text(meta, results);
    std::fs::write(out_dir.join("report.txt"), &text)?;
    let json = render_json(meta, results);
    std::fs::write(out_dir.join("report.json"), serde_json::to_string_pretty(&json).unwrap())?;

    let failures_dir = out_dir.join("failures");
    for (i, r) in results.iter().enumerate() {
        if !test_failed(r) {
            continue;
        }
        let dir = failures_dir.join(safe_name(&r.name));
        std::fs::create_dir_all(&dir)?;
        if let Some(t) = tests.get(i) {
            if let Ok(yaml) = serde_yaml::to_string(t) {
                std::fs::write(dir.join("ops.yaml"), yaml)?;
            }
        }
        write_dumps(&dir, "linux", &r.linux)?;
        if let Some(w) = &r.windows {
            write_dumps(&dir, "windows", w)?;
        }
        let mut summary_txt = String::new();
        summary_txt.push_str(&format!("test: {}\ntags: {}\n\n", r.name, r.tags.join(", ")));
        for p in &r.problems {
            summary_txt.push_str(&format!("problem: {p}\n"));
        }
        for tag in &r.tags {
            if let AspectOutcome::Fail(m) | AspectOutcome::Warn(m) = r.outcome_for_tag(tag) {
                summary_txt.push_str(&format!("{tag}: {m}\n"));
            }
        }
        std::fs::write(dir.join("summary.txt"), summary_txt)?;
    }

    Ok(summary)
}

fn write_dumps(dir: &Path, agent: &str, seq: &crate::runner::SeqResult) -> std::io::Result<()> {
    for (var, snap) in &seq.snapshots {
        let path: PathBuf = dir.join(format!("{agent}.{}.canonical.json", safe_name(var)));
        std::fs::write(path, serde_json::to_string_pretty(&snap.dump).unwrap())?;
    }
    Ok(())
}

fn safe_name(s: &str) -> String {
    s.chars()
        .map(|c| if c.is_ascii_alphanumeric() || c == '_' || c == '-' { c } else { '_' })
        .collect()
}
