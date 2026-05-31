//! Pull a saved hive off the Windows VM over SMB so the harness can run the
//! byte-level structural invariants on offreg's live on-disk output.
//!
//! The Windows agent has no raw-hive-bytes endpoint (see the project memory
//! "vm-hive-access"): it saves hives under `C:\winreg`, which the VM exports as
//! the `winreg` SMB share. Credentials are baked in on purpose. The VM is
//! temporal lab infrastructure with throwaway creds (`user`/`password`), not a
//! secret, and gating the byte-level checks behind environment configuration
//! just adds friction every time the VM is recycled. If the share is
//! unreachable the caller degrades gracefully (no byte-level results, never a
//! failure).

use std::path::Path;

// Temporal lab VM creds. Intentionally committed; see the module docs.
const SMB_USER: &str = "user";
const SMB_PASS: &str = "password";
const SHARE: &str = "winreg";

/// Pull `remote_name` from `//host/winreg` to `local_path` using smbclient.
/// Returns Err with smbclient's stderr if the share or file is unreachable.
pub fn pull(host: &str, remote_name: &str, local_path: &Path) -> Result<(), String> {
    let url = format!("//{host}/{SHARE}");
    let auth = format!("{SMB_USER}%{SMB_PASS}");
    let script = format!("get \"{remote_name}\" \"{}\"", local_path.display());
    let out = std::process::Command::new("smbclient")
        .arg(&url)
        .args(["-U", &auth])
        .args(["-c", &script])
        .output()
        .map_err(|e| format!("running smbclient (is it installed?): {e}"))?;
    if !out.status.success() {
        let stderr = String::from_utf8_lossy(&out.stderr);
        return Err(format!("smbclient get {remote_name}: {}", stderr.trim()));
    }
    Ok(())
}
