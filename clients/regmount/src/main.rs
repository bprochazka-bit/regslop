//! `regmount`: generate a libreg mount map by inspecting hive files.
//!
//! Point it at a hive file or a directory of hives (for example a mounted
//! Windows `System32\config` directory or a user profile). It opens each file,
//! identifies which registry root and subpath it belongs at (by file name and
//! top-level key shape, see `cli_core::identify`), and prints a mount map in the
//! `hives.conf` format. With `--output FILE` it also writes that map to a file.
//!
//! Hives it can place become active `ROOT\subpath = /path` lines; hives it
//! cannot place, and any that collide with an already-mapped point, are written
//! as comments so the generated map stays valid and the operator can finish it
//! by hand.

use cli_core::error::{CliError, CliResult};
use cli_core::identify::{identify_hive, Identification};
use std::collections::BTreeSet;
use std::path::{Path, PathBuf};
use std::process::ExitCode;

fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().skip(1).collect();
    match run(&args) {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("regmount: {e}");
            ExitCode::from(e.exit_code() as u8)
        }
    }
}

struct Options {
    path: PathBuf,
    output: Option<PathBuf>,
    recursive: bool,
    force: bool,
}

fn run(args: &[String]) -> CliResult<()> {
    let opts = match parse_args(args)? {
        Some(o) => o,
        None => return Ok(()), // help was printed
    };

    if !opts.path.exists() {
        return Err(CliError::Io(format!("path does not exist: {}", opts.path.display())));
    }

    // Gather the files to inspect.
    let (files, single) = if opts.path.is_dir() {
        let mut v = Vec::new();
        collect_files(&opts.path, opts.recursive, &mut v)?;
        v.sort();
        (v, false)
    } else {
        (vec![opts.path.clone()], true)
    };

    // Identify each file. In directory mode, files that are not hives are
    // skipped with a note; in single-file mode a non-hive is a hard error.
    let mut ids: Vec<Identification> = Vec::new();
    let mut skipped: Vec<(PathBuf, String)> = Vec::new();
    for f in &files {
        match identify_hive(f) {
            Ok(id) => ids.push(id),
            Err(e) if single => return Err(e),
            Err(e) => skipped.push((f.clone(), e.to_string())),
        }
    }

    let map = render_map(&opts.path, &ids);

    // Print the map to stdout (the "screen"); notes go to stderr so a piped
    // stdout stays a clean mount map.
    print!("{map}");
    report_summary(&ids, &skipped);

    if let Some(out) = &opts.output {
        write_output(out, &map, opts.force)?;
        eprintln!("wrote mount map to {}", out.display());
    }

    Ok(())
}

fn parse_args(args: &[String]) -> CliResult<Option<Options>> {
    let mut path: Option<PathBuf> = None;
    let mut output = None;
    let mut recursive = false;
    let mut force = false;
    let mut i = 0;
    while i < args.len() {
        match args[i].as_str() {
            "-o" | "--output" => {
                i += 1;
                output = Some(PathBuf::from(
                    args.get(i).ok_or_else(|| CliError::usage("--output needs a file"))?,
                ));
            }
            "-r" | "--recursive" => recursive = true,
            "-f" | "--force" => force = true,
            "-h" | "--help" => {
                print_usage();
                return Ok(None);
            }
            other if other.starts_with('-') => {
                return Err(CliError::usage(format!("unknown option '{other}'")));
            }
            other => {
                if path.is_some() {
                    return Err(CliError::usage(format!("unexpected extra argument '{other}'")));
                }
                path = Some(PathBuf::from(other));
            }
        }
        i += 1;
    }
    let path = path.ok_or_else(|| CliError::usage("a path (a hive file or a directory) is required"))?;
    Ok(Some(Options {
        path,
        output,
        recursive,
        force,
    }))
}

/// Collect candidate hive files under `dir`, skipping registry log and
/// transaction companions that share the regf magic but are not hives.
fn collect_files(dir: &Path, recursive: bool, out: &mut Vec<PathBuf>) -> CliResult<()> {
    let entries = std::fs::read_dir(dir)
        .map_err(|e| CliError::Io(format!("reading directory {}: {e}", dir.display())))?;
    for entry in entries {
        let entry = entry.map_err(|e| CliError::Io(e.to_string()))?;
        let p = entry.path();
        let ft = entry.file_type().map_err(|e| CliError::Io(e.to_string()))?;
        if ft.is_dir() {
            if recursive {
                collect_files(&p, recursive, out)?;
            }
        } else if ft.is_file() && !is_log_companion(&p) {
            out.push(p);
        }
    }
    Ok(())
}

/// True for registry transaction logs and similar companions, which we never
/// want in a mount map even though the newer log format opens with "regf".
fn is_log_companion(path: &Path) -> bool {
    let name = path
        .file_name()
        .and_then(|s| s.to_str())
        .unwrap_or("")
        .to_ascii_lowercase();
    name.ends_with(".log")
        || name.ends_with(".log1")
        || name.ends_with(".log2")
        || name.ends_with(".regtrans-ms")
        || name.ends_with(".blf")
        || name.contains(".tmcontainer")
        || name.ends_with(".tm.blf")
}

/// Build the mount map text from the identifications.
fn render_map(scanned: &Path, ids: &[Identification]) -> String {
    let mut out = String::new();
    out.push_str(&format!(
        "# libreg mount map generated by regmount from {}\n",
        display_abs(scanned)
    ));
    out.push_str("# registry root/subpath = hive file. '#' starts a comment.\n");

    // Track points already mapped so later collisions are commented out, which
    // keeps longest-prefix resolution unambiguous.
    let mut seen: BTreeSet<String> = BTreeSet::new();
    let mut active = 0usize;

    for id in ids {
        out.push('\n');
        let file = display_abs(&id.file);
        match &id.mount {
            Some(point) => {
                let key = point.display_long().to_ascii_uppercase();
                if seen.insert(key) {
                    out.push_str(&format!("# {}: {}\n", id.kind, id.reason));
                    out.push_str(&format!("{} = {}\n", point.display_long(), file));
                    active += 1;
                } else {
                    out.push_str(&format!(
                        "# {} already mapped above; left commented to avoid a duplicate:\n",
                        point.display_long()
                    ));
                    out.push_str(&format!("# {} = {}\n", point.display_long(), file));
                }
            }
            None => {
                out.push_str(&format!("# {}: {}\n", file, id.reason));
                out.push_str("#   add a 'ROOT\\subpath = file' line here once you know the mount point\n");
            }
        }
    }

    if active == 0 {
        out.push_str("\n# (no hives could be placed automatically)\n");
    }
    out
}

/// Print a one-line summary plus any skips to stderr.
fn report_summary(ids: &[Identification], skipped: &[(PathBuf, String)]) {
    let placed = ids.iter().filter(|i| i.mount.is_some()).count();
    let unrecognized = ids.len() - placed;
    eprintln!(
        "\nregmount: {} hive(s) placed, {} unrecognized, {} non-hive file(s) skipped",
        placed,
        unrecognized,
        skipped.len()
    );
    for (f, why) in skipped {
        eprintln!("  skipped {}: {}", f.display(), why);
    }
}

fn write_output(out: &Path, text: &str, force: bool) -> CliResult<()> {
    if out.exists() && !force {
        return Err(CliError::usage(format!(
            "{} already exists (pass --force to overwrite)",
            out.display()
        )));
    }
    if let Some(parent) = out.parent() {
        if !parent.as_os_str().is_empty() {
            std::fs::create_dir_all(parent)
                .map_err(|e| CliError::Io(format!("creating {}: {e}", parent.display())))?;
        }
    }
    std::fs::write(out, text)
        .map_err(|e| CliError::Io(format!("writing {}: {e}", out.display())))?;
    Ok(())
}

/// Absolute path for the map, falling back to the given path if it cannot be
/// canonicalized (for example a not-yet-existing parent).
fn display_abs(path: &Path) -> String {
    std::fs::canonicalize(path)
        .unwrap_or_else(|_| path.to_path_buf())
        .display()
        .to_string()
}

fn print_usage() {
    println!(
        "regmount (libreg) - generate a mount map by inspecting hive files\n\
         \n\
         Usage:\n\
         \x20 regmount <PATH> [-o FILE] [-r] [-f]\n\
         \n\
         PATH is a hive file or a directory of hives (for example a mounted\n\
         Windows System32\\config directory). regmount identifies each hive and\n\
         prints a mount map; hives it cannot place are written as comments.\n\
         \n\
         Options:\n\
         \x20 -o, --output FILE   also write the generated map to FILE\n\
         \x20 -r, --recursive     recurse into subdirectories of a directory PATH\n\
         \x20 -f, --force         overwrite FILE if it already exists\n\
         \x20 -h, --help          show this help\n\
         \n\
         The output uses the hives.conf format ('ROOT\\subpath = /path/to/hive').\n\
         Point $LIBREG_HIVES at the written file, or copy it to\n\
         ~/.config/libreg/hives.conf, to use it with reg, winsc, and regedit."
    );
}
