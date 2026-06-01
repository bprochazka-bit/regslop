//! `sc`: an sc.exe-compatible service tool for offline hives.
//!
//! Windows services live in the registry under
//! `HKLM\SYSTEM\<ControlSet>\Services\<name>`. With no running Service Control
//! Manager on Linux, `sc` here is an offline editor of that registry data: it
//! supports the static, registry-backed verbs (create, config, delete, qc,
//! query, description) and refuses the runtime verbs (start, stop, pause,
//! continue) that need a live SCM.
//!
//! The SYSTEM hive is located through the mount map entry for `HKLM\SYSTEM`
//! (or a `--hive FILE` override). The control set defaults to ControlSet001
//! and is overridable with `--controlset N`.

use cli_core::error::{CliError, CliResult};
use cli_core::mount::MountMap;
use cli_core::path::RegPath;
use cli_core::session::Session;
use cli_core::value;
use std::path::{Path, PathBuf};
use std::process::ExitCode;

fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().skip(1).collect();
    match run(&args) {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("[SC] {e}");
            ExitCode::from(e.exit_code() as u8)
        }
    }
}

/// sc service-config registry values and their encodings.
struct Parsed {
    /// Service name (first positional after the verb).
    name: Option<String>,
    /// `key= value` style options (lowercased key without the `=`).
    options: Vec<(String, String)>,
    /// Free positional args after the name (used by `description`).
    extra: Vec<String>,
    hive_override: Option<PathBuf>,
    controlset: String,
}

fn run(args: &[String]) -> CliResult<()> {
    // Pull the global extensions (--hive / --controlset) out from anywhere in
    // the line so they may precede or follow the verb.
    let (globals, mut args) = extract_globals(args)?;
    // A leading \\server token is accepted and ignored (no remote SCM).
    if args.first().map(|a| a.starts_with("\\\\")).unwrap_or(false) {
        args.remove(0);
    }
    let (verb, rest) = match args.split_first() {
        Some((v, r)) => (v.to_ascii_lowercase(), r.to_vec()),
        None => {
            print_usage();
            return Ok(());
        }
    };
    let mut parsed = parse(&rest)?;
    parsed.hive_override = globals.0;
    if let Some(cs) = globals.1 {
        parsed.controlset = cs;
    }
    match verb.as_str() {
        "create" => cmd_create(&parsed),
        "config" => cmd_config(&parsed),
        "delete" => cmd_delete(&parsed),
        "qc" => cmd_qc(&parsed),
        "query" => cmd_query(&parsed),
        "description" => cmd_description(&parsed),
        "start" | "stop" | "pause" | "continue" | "control" => Err(CliError::unsupported(format!(
            "'{verb}' controls a running service and is not available on offline hives"
        ))),
        "/?" | "-h" | "--help" | "help" => {
            print_usage();
            Ok(())
        }
        other => Err(CliError::usage(format!("unknown sc command '{other}'"))),
    }
}

/// Pull `--hive FILE` and `--controlset N` out of the argument list (they may
/// appear before or after the verb), returning the remaining arguments.
type Globals = (Option<PathBuf>, Option<String>);
fn extract_globals(args: &[String]) -> CliResult<(Globals, Vec<String>)> {
    let mut hive = None;
    let mut cs = None;
    let mut rest = Vec::new();
    let mut i = 0;
    while i < args.len() {
        match args[i].as_str() {
            "--hive" => {
                i += 1;
                hive = Some(PathBuf::from(
                    args.get(i).ok_or_else(|| CliError::usage("--hive needs a file"))?,
                ));
            }
            "--controlset" => {
                i += 1;
                let n = args.get(i).ok_or_else(|| CliError::usage("--controlset needs a number"))?;
                cs = Some(controlset_name(n));
            }
            other => rest.push(other.to_string()),
        }
        i += 1;
    }
    Ok(((hive, cs), rest))
}

/// Parse the tail of an sc command: a service name and `key= value` options.
fn parse(args: &[String]) -> CliResult<Parsed> {
    let mut name = None;
    let mut options = Vec::new();
    let mut extra = Vec::new();
    let mut hive_override = None;
    let mut controlset = "ControlSet001".to_string();
    let mut i = 0;
    while i < args.len() {
        let a = &args[i];
        if a == "--hive" {
            i += 1;
            hive_override = Some(PathBuf::from(
                args.get(i).ok_or_else(|| CliError::usage("--hive needs a file"))?,
            ));
        } else if a == "--controlset" {
            i += 1;
            let n = args.get(i).ok_or_else(|| CliError::usage("--controlset needs a number"))?;
            controlset = controlset_name(n);
        } else if let Some(key) = a.strip_suffix('=') {
            // sc style: "binPath=" then the value as the next argument.
            i += 1;
            let v = args
                .get(i)
                .ok_or_else(|| CliError::usage(format!("{a} needs a value")))?;
            options.push((key.to_ascii_lowercase(), v.clone()));
        } else if let Some((key, val)) = a.split_once('=') {
            // Combined "binPath=value" form, accepted for convenience.
            options.push((key.to_ascii_lowercase(), val.to_string()));
        } else if name.is_none() {
            name = Some(a.clone());
        } else {
            extra.push(a.clone());
        }
        i += 1;
    }
    Ok(Parsed {
        name,
        options,
        extra,
        hive_override,
        controlset,
    })
}

fn controlset_name(n: &str) -> String {
    match n.parse::<u32>() {
        Ok(num) => format!("ControlSet{num:03}"),
        Err(_) => n.to_string(),
    }
}

impl Parsed {
    fn name(&self) -> CliResult<&str> {
        self.name.as_deref().ok_or_else(|| CliError::usage("a service name is required"))
    }

    fn opt(&self, key: &str) -> Option<&str> {
        self.options.iter().find(|(k, _)| k == key).map(|(_, v)| v.as_str())
    }
}

/// Locate the SYSTEM hive file and the in-hive `...\Services` base path.
fn resolve_services(p: &Parsed) -> CliResult<(PathBuf, String)> {
    let services = format!("{}\\Services", p.controlset);
    if let Some(file) = &p.hive_override {
        return Ok((file.clone(), services));
    }
    let regpath = RegPath::parse(&format!("HKLM\\SYSTEM\\{services}"))?;
    let map = MountMap::load_default()?;
    let res = map.resolve(&regpath)?;
    let in_hive = res.in_hive_path();
    Ok((res.file, in_hive))
}

// ---- create / config -------------------------------------------------------

fn cmd_create(p: &Parsed) -> CliResult<()> {
    let name = p.name()?.to_string();
    let (file, services) = resolve_services(p)?;
    let mut session = Session::open_or_create(&file)?;
    let key = format!("{services}\\{name}");
    if session.exists(&key)? {
        return Err(CliError::Exists(format!(
            "the specified service '{name}' already exists"
        )));
    }
    session.hive_mut().create_key(&key)?;
    // Defaults matching sc.exe: type own, start demand, error normal.
    set_dword(&mut session, &key, "Type", parse_type(p.opt("type").unwrap_or("own"))?)?;
    set_dword(&mut session, &key, "Start", parse_start(p.opt("start").unwrap_or("demand"))?)?;
    set_dword(&mut session, &key, "ErrorControl", parse_error(p.opt("error").unwrap_or("normal"))?)?;
    apply_common_options(&mut session, &key, p)?;
    session.save()?;
    println!("[SC] CreateService SUCCESS");
    Ok(())
}

fn cmd_config(p: &Parsed) -> CliResult<()> {
    let name = p.name()?.to_string();
    let (file, services) = resolve_services(p)?;
    let mut session = Session::open(&file)?;
    let key = format!("{services}\\{name}");
    if !session.exists(&key)? {
        return Err(CliError::not_found(format!(
            "the specified service '{name}' does not exist"
        )));
    }
    if let Some(t) = p.opt("type") {
        set_dword(&mut session, &key, "Type", parse_type(t)?)?;
    }
    if let Some(s) = p.opt("start") {
        set_dword(&mut session, &key, "Start", parse_start(s)?)?;
    }
    if let Some(e) = p.opt("error") {
        set_dword(&mut session, &key, "ErrorControl", parse_error(e)?)?;
    }
    apply_common_options(&mut session, &key, p)?;
    session.save()?;
    println!("[SC] ChangeServiceConfig SUCCESS");
    Ok(())
}

/// Apply the string/list service options common to create and config.
fn apply_common_options(session: &mut Session, key: &str, p: &Parsed) -> CliResult<()> {
    if let Some(bin) = p.opt("binpath") {
        set_value(session, key, "ImagePath", value::REG_EXPAND_SZ, &value::build_sz(bin))?;
    }
    if let Some(dn) = p.opt("displayname") {
        set_value(session, key, "DisplayName", value::REG_SZ, &value::build_sz(dn))?;
    }
    if let Some(obj) = p.opt("obj") {
        set_value(session, key, "ObjectName", value::REG_SZ, &value::build_sz(obj))?;
    }
    if let Some(group) = p.opt("group") {
        set_value(session, key, "Group", value::REG_SZ, &value::build_sz(group))?;
    }
    if let Some(dep) = p.opt("depend") {
        // sc separates dependencies with '/'.
        let parts: Vec<&str> = if dep.is_empty() { Vec::new() } else { dep.split('/').collect() };
        set_value(session, key, "DependOnService", value::REG_MULTI_SZ, &value::build_multi_sz(&parts))?;
    }
    if let Some(tag) = p.opt("tag") {
        if let Some(n) = value::parse_int(tag) {
            set_value(session, key, "Tag", value::REG_DWORD, &(n as u32).to_le_bytes())?;
        }
    }
    Ok(())
}

fn cmd_delete(p: &Parsed) -> CliResult<()> {
    let name = p.name()?.to_string();
    let (file, services) = resolve_services(p)?;
    let mut session = Session::open(&file)?;
    let key = format!("{services}\\{name}");
    if !session.exists(&key)? {
        return Err(CliError::not_found(format!(
            "the specified service '{name}' does not exist"
        )));
    }
    session.hive_mut().delete_key(&key, true)?;
    session.save()?;
    println!("[SC] DeleteService SUCCESS");
    Ok(())
}

// ---- qc / query / description ---------------------------------------------

fn cmd_qc(p: &Parsed) -> CliResult<()> {
    let name = p.name()?.to_string();
    let (file, services) = resolve_services(p)?;
    let session = Session::open(&file)?;
    let key = format!("{services}\\{name}");
    if !session.exists(&key)? {
        return Err(CliError::not_found(format!(
            "the specified service '{name}' does not exist"
        )));
    }
    let dword = |n: &str| read_dword(&session, &key, n);
    let string = |n: &str| read_string(&session, &key, n);

    println!("[SC] QueryServiceConfig SUCCESS");
    println!();
    println!("SERVICE_NAME: {name}");
    let ty = dword("Type").unwrap_or(0);
    println!("        TYPE               : {:<4x}  {}", ty, type_label(ty));
    let start = dword("Start").unwrap_or(3);
    println!("        START_TYPE         : {:<4x}  {}", start, start_label(start));
    let err = dword("ErrorControl").unwrap_or(1);
    println!("        ERROR_CONTROL      : {:<4x}  {}", err, error_label(err));
    println!("        BINARY_PATH_NAME   : {}", string("ImagePath").unwrap_or_default());
    println!("        TAG                : {}", dword("Tag").map(|t| t.to_string()).unwrap_or_default());
    println!("        DISPLAY_NAME       : {}", string("DisplayName").unwrap_or_default());
    println!("        DEPENDENCIES       : {}", read_multi(&session, &key, "DependOnService").join(" "));
    println!("        SERVICE_START_NAME : {}", string("ObjectName").unwrap_or_default());
    Ok(())
}

fn cmd_query(p: &Parsed) -> CliResult<()> {
    let (file, services) = resolve_services(p)?;
    let session = Session::open(&file)?;
    let names: Vec<String> = match &p.name {
        Some(n) => vec![n.clone()],
        None => session.hive().subkeys(&services)?,
    };
    for name in names {
        let key = format!("{services}\\{name}");
        if !session.exists(&key)? {
            return Err(CliError::not_found(format!("the specified service '{name}' does not exist")));
        }
        let ty = read_dword(&session, &key, "Type").unwrap_or(0);
        println!("SERVICE_NAME: {name}");
        println!("        TYPE               : {:<4x}  {}", ty, type_label(ty));
        // State is a runtime property; offline we cannot report RUNNING/STOPPED.
        println!("        STATE              : N/A   (offline hive, no running SCM)");
        println!();
    }
    Ok(())
}

fn cmd_description(p: &Parsed) -> CliResult<()> {
    let name = p.name()?.to_string();
    let text = p.extra.join(" ");
    let (file, services) = resolve_services(p)?;
    let mut session = Session::open(&file)?;
    let key = format!("{services}\\{name}");
    if !session.exists(&key)? {
        return Err(CliError::not_found(format!(
            "the specified service '{name}' does not exist"
        )));
    }
    set_value(&mut session, &key, "Description", value::REG_SZ, &value::build_sz(&text))?;
    session.save()?;
    println!("[SC] ChangeServiceConfig2 SUCCESS");
    Ok(())
}

// ---- value helpers ---------------------------------------------------------

fn set_dword(session: &mut Session, key: &str, name: &str, v: u32) -> CliResult<()> {
    set_value(session, key, name, value::REG_DWORD, &v.to_le_bytes())
}

fn set_value(session: &mut Session, key: &str, name: &str, ty: u32, data: &[u8]) -> CliResult<()> {
    session.hive_mut().set_value(key, name, ty, data)?;
    Ok(())
}

fn read_dword(session: &Session, key: &str, name: &str) -> Option<u32> {
    let (_, data) = session.hive().get_value(key, name).ok()??;
    let mut buf = [0u8; 4];
    let n = data.len().min(4);
    buf[..n].copy_from_slice(&data[..n]);
    Some(u32::from_le_bytes(buf))
}

fn read_string(session: &Session, key: &str, name: &str) -> Option<String> {
    let (_, data) = session.hive().get_value(key, name).ok()??;
    Some(value::parse_sz(&data))
}

fn read_multi(session: &Session, key: &str, name: &str) -> Vec<String> {
    match session.hive().get_value(key, name) {
        Ok(Some((_, data))) => value::parse_multi_sz(&data),
        _ => Vec::new(),
    }
}

// ---- service constant mapping ---------------------------------------------

fn parse_type(s: &str) -> CliResult<u32> {
    Ok(match s.to_ascii_lowercase().as_str() {
        "kernel" => 0x1,
        "filesys" => 0x2,
        "rec" => 0x8,
        "own" => 0x10,
        "share" => 0x20,
        "interact" => 0x100 | 0x10, // interactive implies own by default
        "userown" => 0x50,
        "usershare" => 0x60,
        other => value::parse_int(other)
            .map(|n| n as u32)
            .ok_or_else(|| CliError::usage(format!("unknown service type '{other}'")))?,
    })
}

fn parse_start(s: &str) -> CliResult<u32> {
    Ok(match s.to_ascii_lowercase().as_str() {
        "boot" => 0,
        "system" => 1,
        "auto" => 2,
        "demand" => 3,
        "disabled" => 4,
        other => value::parse_int(other)
            .map(|n| n as u32)
            .ok_or_else(|| CliError::usage(format!("unknown start type '{other}'")))?,
    })
}

fn parse_error(s: &str) -> CliResult<u32> {
    Ok(match s.to_ascii_lowercase().as_str() {
        "ignore" => 0,
        "normal" => 1,
        "severe" => 2,
        "critical" => 3,
        other => value::parse_int(other)
            .map(|n| n as u32)
            .ok_or_else(|| CliError::usage(format!("unknown error control '{other}'")))?,
    })
}

fn type_label(ty: u32) -> &'static str {
    match ty & 0xff {
        0x1 => "KERNEL_DRIVER",
        0x2 => "FILE_SYSTEM_DRIVER",
        0x8 => "RECOGNIZER_DRIVER",
        0x10 => "WIN32_OWN_PROCESS",
        0x20 => "WIN32_SHARE_PROCESS",
        _ => "UNKNOWN",
    }
}

fn start_label(s: u32) -> &'static str {
    match s {
        0 => "BOOT_START",
        1 => "SYSTEM_START",
        2 => "AUTO_START",
        3 => "DEMAND_START",
        4 => "DISABLED",
        _ => "UNKNOWN",
    }
}

fn error_label(e: u32) -> &'static str {
    match e {
        0 => "IGNORE",
        1 => "NORMAL",
        2 => "SEVERE",
        3 => "CRITICAL",
        _ => "UNKNOWN",
    }
}

fn print_usage() {
    println!(
        "sc (libreg) - offline service configuration tool\n\
         \n\
         Usage:\n\
         \x20 sc create <name> binPath= <path> [type= own|share|kernel|...] \\\n\
         \x20           [start= boot|system|auto|demand|disabled] [error= normal|...] \\\n\
         \x20           [DisplayName= <text>] [depend= a/b/c] [obj= <account>] [group= <g>]\n\
         \x20 sc config <name> [same options]\n\
         \x20 sc delete <name>\n\
         \x20 sc qc <name>\n\
         \x20 sc query [name]\n\
         \x20 sc description <name> <text>\n\
         \n\
         Operates on HKLM\\SYSTEM\\<ControlSet>\\Services in the mounted SYSTEM hive.\n\
         Use --hive <File> to target a file and --controlset N to pick a control set\n\
         (default ControlSet001). Runtime verbs (start, stop, ...) need a live SCM\n\
         and are not supported offline."
    );
    let _ = Path::new("");
}
