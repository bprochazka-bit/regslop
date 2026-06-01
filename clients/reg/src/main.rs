//! `reg`: a reg.exe-compatible registry tool for offline hives.
//!
//! Windows `reg.exe` works on the live registry through predefined roots. On
//! Linux there is no live registry, so a registry path is resolved to a hive
//! file through the mount map (see `cli-core::mount`). A `--hive FILE` override
//! is available for one-off files.
//!
//! Supported subcommands: query, add, delete, copy, save, restore, load,
//! unload, export, import, compare. Syntax mirrors reg.exe.

use cli_core::error::{CliError, CliResult};
use cli_core::mount::MountMap;
use cli_core::path::RegPath;
use cli_core::regfile::{self, RegOp};
use cli_core::session::Session;
use cli_core::value;
use std::path::PathBuf;
use std::process::ExitCode;

fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().skip(1).collect();
    match run(&args) {
        Ok(code) => ExitCode::from(code as u8),
        Err(e) => {
            eprintln!("ERROR: {e}");
            ExitCode::from(e.exit_code() as u8)
        }
    }
}

/// A small flag bag parsed from the tail of a command line.
struct Flags {
    /// Positional (non-flag) arguments in order.
    positional: Vec<String>,
    /// Switch flags present (lowercased, without leading slash), value if any.
    opts: Vec<(String, Option<String>)>,
    /// The `--hive FILE` override, if given.
    hive_override: Option<PathBuf>,
}

impl Flags {
    /// Parse, treating the listed switch names as value-taking (they consume the
    /// next argument). Everything else starting with `/` is a bare switch.
    fn parse(args: &[String], value_switches: &[&str]) -> CliResult<Flags> {
        let mut positional = Vec::new();
        let mut opts = Vec::new();
        let mut hive_override = None;
        let mut i = 0;
        while i < args.len() {
            let a = &args[i];
            if a == "--hive" {
                i += 1;
                let f = args.get(i).ok_or_else(|| CliError::usage("--hive needs a file path"))?;
                hive_override = Some(PathBuf::from(f));
            } else if is_switch(a) {
                let name = a.strip_prefix('/').unwrap();
                let key = name.to_ascii_lowercase();
                if value_switches.contains(&key.as_str()) {
                    i += 1;
                    let v = args
                        .get(i)
                        .ok_or_else(|| CliError::usage(format!("/{name} needs a value")))?;
                    opts.push((key, Some(v.clone())));
                } else {
                    opts.push((key, None));
                }
            } else {
                positional.push(a.clone());
            }
            i += 1;
        }
        Ok(Flags {
            positional,
            opts,
            hive_override,
        })
    }

    fn has(&self, name: &str) -> bool {
        self.opts.iter().any(|(k, _)| k == name)
    }

    fn get(&self, name: &str) -> Option<&str> {
        self.opts
            .iter()
            .find(|(k, _)| k == name)
            .and_then(|(_, v)| v.as_deref())
    }
}

/// Is `token` a reg.exe-style switch (`/v`, `/s`, ...) rather than a file path?
/// On Linux an absolute path also starts with `/`, so a real switch is a short
/// token with no further path separator and no `.` (which a filename has).
fn is_switch(token: &str) -> bool {
    match token.strip_prefix('/') {
        Some(rest) => !rest.is_empty() && !rest.contains('/') && !rest.contains('.') && rest.len() <= 4,
        None => false,
    }
}

/// Run a command, returning the process exit code (0 success; `reg compare`
/// returns 2 when the trees differ, matching reg.exe).
fn run(args: &[String]) -> CliResult<i32> {
    let (cmd, rest) = match args.split_first() {
        Some((c, r)) => (c.to_ascii_lowercase(), r),
        None => {
            print_usage();
            return Ok(0);
        }
    };
    match cmd.as_str() {
        "query" => cmd_query(rest),
        "add" => cmd_add(rest).map(|_| 0),
        "delete" => cmd_delete(rest).map(|_| 0),
        "copy" => cmd_copy(rest).map(|_| 0),
        "save" => cmd_save(rest).map(|_| 0),
        "restore" => cmd_restore(rest).map(|_| 0),
        "load" => cmd_load(rest).map(|_| 0),
        "unload" => cmd_unload(rest).map(|_| 0),
        "export" => cmd_export(rest).map(|_| 0),
        "import" => cmd_import(rest).map(|_| 0),
        "compare" => cmd_compare(rest),
        "/?" | "-h" | "--help" | "help" => {
            print_usage();
            Ok(0)
        }
        other => Err(CliError::usage(format!("unknown reg operation '{other}'"))),
    }
}

/// Resolve a key argument to (file, in-hive path) using the mount map and any
/// `--hive` override.
fn resolve(key: &str, flags: &Flags) -> CliResult<(PathBuf, String, RegPath)> {
    let path = RegPath::parse(key)?;
    let map = MountMap::load_default()?;
    let res = map.resolve_with_override(&path, flags.hive_override.as_deref())?;
    let in_hive = res.in_hive_path();
    Ok((res.file, in_hive, path))
}

// ---- query -----------------------------------------------------------------

fn cmd_query(args: &[String]) -> CliResult<i32> {
    let flags = Flags::parse(args, &["v", "f", "t"])?;
    let key = flags
        .positional
        .first()
        .ok_or_else(|| CliError::usage("reg query needs a key name"))?;
    let (file, in_hive, regpath) = resolve(key, &flags)?;
    let session = Session::open(&file)?;
    let recursive = flags.has("s");
    let only_value = flags.get("v");
    let default_only = flags.has("ve");

    // Optional value-type filter (/t) and content search (/f).
    let type_filter = match flags.get("t") {
        Some(t) => Some(value::type_from_name(t).ok_or_else(|| CliError::usage(format!("unknown type {t}")))?),
        None => None,
    };
    let filter = flags.get("f").map(|pattern| {
        cli_core::search::Filter::new(pattern, flags.has("k"), flags.has("d"), flags.has("c"), flags.has("e"))
    });

    let dumps = if recursive {
        session.dump_recursive(&in_hive)?
    } else {
        vec![session.dump_key(&in_hive)?]
    };

    let mut match_count = 0usize;
    for d in &dumps {
        let display = display_for(&regpath, &in_hive, &d.path);
        // Values that pass the /v, /ve, and /t filters (independent of search).
        let candidates: Vec<&cli_core::session::ValueDump> = d
            .values
            .iter()
            .filter(|v| only_value.map(|want| v.name.eq_ignore_ascii_case(want)).unwrap_or(true))
            .filter(|v| !default_only || v.name.is_empty())
            .filter(|v| type_filter.map(|t| v.ty == t).unwrap_or(true))
            .collect();

        match &filter {
            None => {
                // Plain listing: print the key and its (filtered) values.
                println!("\n{display}");
                for v in &candidates {
                    print_value_row(v);
                }
            }
            Some(f) => {
                // Search mode: print the key only if its name or one of its
                // values matches, and count each match.
                let key_name = display.rsplit('\\').next().unwrap_or(&display);
                let key_hit = f.in_keys && f.text_matches(key_name);
                let value_hits: Vec<&&cli_core::session::ValueDump> = candidates
                    .iter()
                    .filter(|v| {
                        (f.in_value_names && f.text_matches(if v.name.is_empty() { "(Default)" } else { &v.name }))
                            || (f.in_data && f.text_matches(&v.display()))
                    })
                    .collect();
                if key_hit {
                    match_count += 1;
                }
                match_count += value_hits.len();
                if key_hit {
                    // A key-name hit prints the key and all its values.
                    println!("\n{display}");
                    for v in &candidates {
                        print_value_row(v);
                    }
                } else if !value_hits.is_empty() {
                    println!("\n{display}");
                    for v in &value_hits {
                        print_value_row(v);
                    }
                }
            }
        }
    }

    if filter.is_some() {
        println!("\nEnd of search: {match_count} match(es) found.");
        // reg.exe returns 1 when a search finds nothing.
        return Ok(if match_count == 0 { 1 } else { 0 });
    }
    println!();
    Ok(0)
}

fn print_value_row(v: &cli_core::session::ValueDump) {
    let name = if v.name.is_empty() { "(Default)" } else { &v.name };
    println!("    {}    {}    {}", name, value::type_name(v.ty), v.display());
}

/// Build the full display path of an in-hive `key_path`, given the original
/// query path (`regpath`) and the in-hive base it resolved to.
fn display_for(regpath: &RegPath, base_in_hive: &str, key_path: &str) -> String {
    // The portion of key_path beyond the base is appended to the query path.
    let extra = key_path
        .strip_prefix(base_in_hive)
        .unwrap_or(key_path)
        .trim_start_matches('\\');
    if extra.is_empty() {
        regpath.display_long()
    } else {
        format!("{}\\{}", regpath.display_long(), extra)
    }
}

// ---- add -------------------------------------------------------------------

fn cmd_add(args: &[String]) -> CliResult<()> {
    let flags = Flags::parse(args, &["v", "t", "d", "s"])?;
    let key = flags
        .positional
        .first()
        .ok_or_else(|| CliError::usage("reg add needs a key name"))?;
    let (file, in_hive, _) = resolve(key, &flags)?;
    let mut session = Session::open_or_create(&file)?;
    let force = flags.has("f");

    let existed = session.exists(&in_hive)?;
    session.hive_mut().create_key(&in_hive)?;

    // reg.exe operates on a value whenever one is named (/v), the default is
    // named (/ve), or value details are given (/t, /d). A bare add of a *new*
    // key also sets the default value to an empty REG_SZ: reg.exe leaves an
    // empty (Default) on a freshly created key, so we match it (the harness
    // client-differential flagged us for creating the key with no value). An
    // existing key is left as-is by a bare add, so "ensure a key exists" does
    // not clobber its default.
    let explicit_value = flags.has("v") || flags.has("ve") || flags.has("t") || flags.has("d");
    if explicit_value || !existed {
        // /v gives the value name; /ve and a bare add both target the default.
        let name = flags.get("v").unwrap_or("").to_string();
        let ty = match flags.get("t") {
            Some(t) => value::type_from_name(t)
                .ok_or_else(|| CliError::usage(format!("unknown type {t}")))?,
            None => value::REG_SZ,
        };
        // Without /f, prompt-on-overwrite is the Windows behavior; offline and
        // non-interactive, we treat a missing /f on an existing value as an
        // error so scripts do not silently clobber.
        if !force && session.hive().get_value(&in_hive, &name)?.is_some() {
            return Err(CliError::usage(format!(
                "value '{}' already exists (use /f to overwrite)",
                if name.is_empty() { "(Default)" } else { &name }
            )));
        }
        let sep = flags.get("s").unwrap_or("\\0");
        let data = value::encode_cli(ty, flags.get("d").unwrap_or(""), sep)?;
        session.hive_mut().set_value(&in_hive, &name, ty, &data)?;
    }

    session.save()?;
    println!("The operation completed successfully.");
    Ok(())
}

// ---- delete ----------------------------------------------------------------

fn cmd_delete(args: &[String]) -> CliResult<()> {
    let flags = Flags::parse(args, &["v"])?;
    let key = flags
        .positional
        .first()
        .ok_or_else(|| CliError::usage("reg delete needs a key name"))?;
    let (file, in_hive, _) = resolve(key, &flags)?;
    let mut session = Session::open(&file)?;

    if flags.has("va") {
        // Delete all values under the key, leaving subkeys.
        for v in session.read_values(&in_hive)? {
            session.hive_mut().delete_value(&in_hive, &v.name)?;
        }
    } else if flags.has("v") || flags.has("ve") {
        let name = if flags.has("ve") {
            String::new()
        } else {
            flags.get("v").unwrap_or("").to_string()
        };
        if !session.hive_mut().delete_value(&in_hive, &name)? {
            return Err(CliError::not_found(format!(
                "the value '{}' does not exist",
                if name.is_empty() { "(Default)" } else { &name }
            )));
        }
    } else {
        // Delete the whole key (and subtree).
        if in_hive.is_empty() {
            return Err(CliError::usage("refusing to delete the hive root"));
        }
        session.hive_mut().delete_key(&in_hive, true)?;
    }
    session.save()?;
    println!("The operation completed successfully.");
    Ok(())
}

// ---- copy ------------------------------------------------------------------

fn cmd_copy(args: &[String]) -> CliResult<()> {
    let flags = Flags::parse(args, &[])?;
    let src = flags.positional.first().ok_or_else(|| CliError::usage("reg copy needs a source"))?;
    let dst = flags.positional.get(1).ok_or_else(|| CliError::usage("reg copy needs a destination"))?;
    let (src_file, src_path, _) = resolve(src, &flags)?;
    let (dst_file, dst_path, _) = resolve(dst, &flags)?;

    if src_file == dst_file {
        let mut session = Session::open(&src_file)?;
        if !session.exists(&src_path)? {
            return Err(CliError::not_found(format!("source key not found: {src}")));
        }
        copy_one_level(&mut session, &src_path, &dst_path, flags.has("s"))?;
        session.save()?;
    } else {
        let source = Session::open(&src_file)?;
        let mut dest = Session::open_or_create(&dst_file)?;
        cross_copy(&source, &mut dest, &src_path, &dst_path, flags.has("s"))?;
        dest.save()?;
    }
    println!("The operation completed successfully.");
    Ok(())
}

fn copy_one_level(session: &mut Session, src: &str, dst: &str, recursive: bool) -> CliResult<()> {
    if recursive {
        session.copy_subtree(src, dst)?;
    } else {
        session.hive_mut().create_key(dst)?;
        for v in session.read_values(src)? {
            session.hive_mut().set_value(dst, &v.name, v.ty, &v.data)?;
        }
    }
    Ok(())
}

fn cross_copy(source: &Session, dest: &mut Session, src: &str, dst: &str, recursive: bool) -> CliResult<()> {
    dest.hive_mut().create_key(dst)?;
    for v in source.read_values(src)? {
        dest.hive_mut().set_value(dst, &v.name, v.ty, &v.data)?;
    }
    if recursive {
        for sub in source.hive().subkeys(src)? {
            let s = if src.is_empty() { sub.clone() } else { format!("{src}\\{sub}") };
            let d = if dst.is_empty() { sub.clone() } else { format!("{dst}\\{sub}") };
            cross_copy(source, dest, &s, &d, true)?;
        }
    }
    Ok(())
}

// ---- save / restore --------------------------------------------------------

fn cmd_save(args: &[String]) -> CliResult<()> {
    let flags = Flags::parse(args, &[])?;
    let key = flags.positional.first().ok_or_else(|| CliError::usage("reg save needs a key"))?;
    let dest = flags.positional.get(1).ok_or_else(|| CliError::usage("reg save needs a file name"))?;
    let (file, in_hive, _) = resolve(key, &flags)?;
    let source = Session::open(&file)?;
    if !source.exists(&in_hive)? {
        return Err(CliError::not_found(format!("key not found: {key}")));
    }
    // Build a new hive whose root is the saved key (copy its subtree to root).
    let mut out = Session::create(std::path::Path::new(dest));
    cross_copy(&source, &mut out, &in_hive, "", true)?;
    out.save_as(std::path::Path::new(dest))?;
    println!("The operation completed successfully.");
    Ok(())
}

fn cmd_restore(args: &[String]) -> CliResult<()> {
    let flags = Flags::parse(args, &[])?;
    let key = flags.positional.first().ok_or_else(|| CliError::usage("reg restore needs a key"))?;
    let from = flags.positional.get(1).ok_or_else(|| CliError::usage("reg restore needs a file name"))?;
    let (file, in_hive, _) = resolve(key, &flags)?;
    let source = Session::open(std::path::Path::new(from))?;
    let mut dest = Session::open_or_create(&file)?;
    // Replace the target key with the file's contents.
    if dest.exists(&in_hive)? && !in_hive.is_empty() {
        dest.hive_mut().delete_key(&in_hive, true)?;
    }
    cross_copy(&source, &mut dest, "", &in_hive, true)?;
    dest.save()?;
    println!("The operation completed successfully.");
    Ok(())
}

// ---- load / unload (mount management) --------------------------------------

fn cmd_load(args: &[String]) -> CliResult<()> {
    let flags = Flags::parse(args, &[])?;
    let key = flags.positional.first().ok_or_else(|| CliError::usage("reg load needs a key name"))?;
    let file = flags.positional.get(1).ok_or_else(|| CliError::usage("reg load needs a file name"))?;
    let point = RegPath::parse(key)?;
    let path = PathBuf::from(file);
    // Validate the file is a real hive before mounting it.
    Session::open(&path)?;
    let mut map = MountMap::load_default()?;
    if map.source.is_none() {
        map.source = MountMap::default_path();
    }
    map.insert(point, std::fs::canonicalize(&path).unwrap_or(path));
    map.save()?;
    println!("The operation completed successfully.");
    Ok(())
}

fn cmd_unload(args: &[String]) -> CliResult<()> {
    let flags = Flags::parse(args, &[])?;
    let key = flags.positional.first().ok_or_else(|| CliError::usage("reg unload needs a key name"))?;
    let point = RegPath::parse(key)?;
    let mut map = MountMap::load_default()?;
    if !map.remove(&point) {
        return Err(CliError::not_found(format!("no hive is mounted at {key}")));
    }
    map.save()?;
    println!("The operation completed successfully.");
    Ok(())
}

// ---- export / import -------------------------------------------------------

fn cmd_export(args: &[String]) -> CliResult<()> {
    let flags = Flags::parse(args, &[])?;
    let key = flags.positional.first().ok_or_else(|| CliError::usage("reg export needs a key"))?;
    let dest = flags.positional.get(1).ok_or_else(|| CliError::usage("reg export needs a file name"))?;
    let (file, in_hive, regpath) = resolve(key, &flags)?;
    let session = Session::open(&file)?;
    let dumps = session.dump_recursive(&in_hive)?;

    let mut doc = regfile::export_header();
    for d in &dumps {
        let display = display_for(&regpath, &in_hive, &d.path);
        doc.push_str(&regfile::export_key(&display, &d.values));
    }
    std::fs::write(dest, regfile::to_utf16le_bom(&doc))
        .map_err(|e| CliError::Io(format!("writing {dest}: {e}")))?;
    println!("The operation completed successfully.");
    Ok(())
}

fn cmd_import(args: &[String]) -> CliResult<()> {
    let flags = Flags::parse(args, &[])?;
    let from = flags.positional.first().ok_or_else(|| CliError::usage("reg import needs a file name"))?;
    let bytes = std::fs::read(from).map_err(|e| CliError::Io(format!("reading {from}: {e}")))?;
    let ops = regfile::parse(&bytes)?;
    let map = MountMap::load_default()?;

    // Group operations by hive file so each file is loaded and saved once.
    use std::collections::BTreeMap;
    let mut touched: BTreeMap<PathBuf, Session> = BTreeMap::new();

    for op in ops {
        let (display_key, _) = op_key(&op);
        let regpath = RegPath::parse(display_key)?;
        let res = map.resolve_with_override(&regpath, flags.hive_override.as_deref())?;
        let session = match touched.get_mut(&res.file) {
            Some(s) => s,
            None => {
                let s = Session::open_or_create(&res.file)?;
                touched.entry(res.file.clone()).or_insert(s)
            }
        };
        apply_op(session, &op, &res.in_hive_path())?;
    }
    for session in touched.values() {
        session.save()?;
    }
    println!("The operation completed successfully.");
    Ok(())
}

fn op_key(op: &RegOp) -> (&str, &str) {
    match op {
        RegOp::AddKey(k) | RegOp::DelKey(k) => (k.as_str(), ""),
        RegOp::SetValue { key, name, .. } | RegOp::DelValue { key, name } => (key.as_str(), name.as_str()),
    }
}

fn apply_op(session: &mut Session, op: &RegOp, in_hive: &str) -> CliResult<()> {
    match op {
        RegOp::AddKey(_) => {
            session.hive_mut().create_key(in_hive)?;
        }
        RegOp::DelKey(_) => {
            if session.exists(in_hive)? && !in_hive.is_empty() {
                session.hive_mut().delete_key(in_hive, true)?;
            }
        }
        RegOp::SetValue { name, ty, data, .. } => {
            session.hive_mut().create_key(in_hive)?;
            session.hive_mut().set_value(in_hive, name, *ty, data)?;
        }
        RegOp::DelValue { name, .. } => {
            session.hive_mut().delete_value(in_hive, name)?;
        }
    }
    Ok(())
}

// ---- compare ---------------------------------------------------------------

fn cmd_compare(args: &[String]) -> CliResult<i32> {
    let flags = Flags::parse(args, &["v"])?;
    let a = flags.positional.first().ok_or_else(|| CliError::usage("reg compare needs two keys"))?;
    let b = flags.positional.get(1).ok_or_else(|| CliError::usage("reg compare needs two keys"))?;
    let (fa, pa, _) = resolve(a, &flags)?;
    let (fb, pb, _) = resolve(b, &flags)?;
    let sa = Session::open(&fa)?;
    let sb = Session::open(&fb)?;

    // Output mode: /od differences (default), /os matches only, /oa all, /on none.
    let show_diff = flags.has("oa") || flags.has("od") || !(flags.has("os") || flags.has("on"));
    let show_same = flags.has("oa") || flags.has("os");

    // A non-recursive compare looks at the named keys only (their value sets);
    // /s walks the whole subtree. dump_recursive already covers the subtree.
    let dump = |s: &Session, base: &str| -> CliResult<Vec<cli_core::session::KeyDump>> {
        if flags.has("s") {
            s.dump_recursive(base)
        } else {
            Ok(vec![s.dump_key(base)?])
        }
    };
    let da = dump(&sa, &pa)?;
    let db = dump(&sb, &pb)?;

    let rel = |base: &str, p: &str| p.strip_prefix(base).unwrap_or(p).trim_start_matches('\\').to_string();
    use std::collections::BTreeMap;
    type Vals = Vec<(String, u32, Vec<u8>)>;
    let index = |dumps: &[cli_core::session::KeyDump], base: &str| -> BTreeMap<String, Vals> {
        let mut m = BTreeMap::new();
        for d in dumps {
            m.insert(
                rel(base, &d.path),
                d.values.iter().map(|v| (v.name.to_uppercase(), v.ty, v.data.clone())).collect(),
            );
        }
        m
    };
    let left = index(&da, &pa);
    let right = index(&db, &pb);

    let label = |k: &str| if k.is_empty() { "<top>".to_string() } else { k.to_string() };
    let mut differences = 0;
    for (k, lv) in &left {
        match right.get(k) {
            None => {
                differences += 1;
                if show_diff {
                    println!("Only in {a}: {}", label(k));
                }
            }
            Some(rv) if rv != lv => {
                differences += 1;
                if show_diff {
                    println!("Different values at: {}", label(k));
                }
            }
            Some(_) => {
                if show_same {
                    println!("Identical: {}", label(k));
                }
            }
        }
    }
    for k in right.keys() {
        if !left.contains_key(k) {
            differences += 1;
            if show_diff {
                println!("Only in {b}: {}", label(k));
            }
        }
    }

    // reg.exe: "Result Compared" line, exit 0 identical / 2 different.
    if differences == 0 {
        println!("Result Compared: Identical");
        Ok(0)
    } else {
        println!("Result Compared: Different");
        Ok(2)
    }
}

fn print_usage() {
    println!(
        "reg (libreg) - offline registry tool\n\
         \n\
         Usage:\n\
         \x20 reg query   <Key> [/v Name | /ve] [/s] [/f Pattern [/k|/d] [/c] [/e]] [/t Type]\n\
         \x20 reg add     <Key> [/v Name | /ve] [/t Type] [/d Data] [/s Sep] [/f]\n\
         \x20 reg delete  <Key> [/v Name | /ve | /va] [/f]\n\
         \x20 reg copy    <Src> <Dest> [/s] [/f]\n\
         \x20 reg save    <Key> <File.hiv>\n\
         \x20 reg restore <Key> <File.hiv>\n\
         \x20 reg load    <Key> <File.hiv>\n\
         \x20 reg unload  <Key>\n\
         \x20 reg export  <Key> <File.reg>\n\
         \x20 reg import  <File.reg>\n\
         \x20 reg compare <Key1> <Key2> [/s] [/oa|/od|/os|/on]   (exit 0 same, 2 different)\n\
         \n\
         Roots (HKLM, HKCU, ...) resolve to hive files via the mount map\n\
         ($LIBREG_HIVES or ~/.config/libreg/hives.conf). Use --hive <File> to\n\
         operate on a specific file directly."
    );
}
