# winreg-agent

HTTP agent wrapping `offreg.dll`. This is the ground-truth oracle for the
libreg differential test project: it answers the same HTTP protocol as the
Linux agent (see `../../CONTRACTS.md`) but backs every operation with the
Windows offline-registry API, so the harness can compare libreg's output
against a real Windows implementation.

## Build

Cross-compiled from Linux. No Windows host is needed to build.

```bash
rustup target add x86_64-pc-windows-gnu       # one time
cargo build --release --target x86_64-pc-windows-gnu
```

The artifact is `target/x86_64-pc-windows-gnu/release/winreg-agent.exe`.

We do not link an offreg import library (none is available on the build host).
offreg.dll is loaded dynamically at startup with `LoadLibraryW` /
`GetProcAddress`. kernel32 and advapi32 are linked normally through the mingw
import libraries.

## Runtime requirements (Windows VM)

- **Windows ADK Deployment Tools** must be installed: `offreg.dll` ships with
  the ADK, not the base OS. Pin the ADK version on the VM and record it.
  The agent exits with a clear error if `offreg.dll` cannot be loaded.
- **Privileges**: `OROpenHive` needs `SeBackupPrivilege` and `SeRestorePrivilege`
  on some Windows versions. Run the agent **as administrator** (or ship an
  application manifest that requests those privileges).
- **Snapshot the VM** after installing offreg/ADK and before each test run, so
  a corrupt hive write (from either agent) cannot persist.

## Run

```
winreg-agent.exe --port 7879 --bind 0.0.0.0
```

Flags:

| Flag              | Default         | Meaning                                            |
|-------------------|-----------------|----------------------------------------------------|
| `--port`          | 7879            | TCP port                                            |
| `--bind`          | 0.0.0.0         | bind address                                        |
| `--audit`         | audit.log       | append-only JSONL operation log                     |
| `--backend`       | offreg-unknown  | backend string reported in `/version` handshake     |
| `--hive-os-major` | 6               | OS major version offreg stamps into saved hives     |
| `--hive-os-minor` | 3               | OS minor version (6.3 = Win 8.1 => v1.5 hives)       |

Set `--backend` to the real offreg/ADK version, for example
`--backend offreg-10.0.22621`, so the handshake reflects what is installed.

## Endpoints

All endpoints follow the `{ ok, error, data }` envelope from CONTRACTS; errors
carry a stable `code`. Implemented:

- `GET  /version`
- `POST /hive/create` `/hive/load` `/hive/save` `/hive/close`
- `GET  /hive/checksum` `/hive/dump` `/hive/validate`
- `POST /key/create` `/key/delete` `/key/rename`
- `GET  /key/list` `/key/info`
- `POST /value/set` `/value/delete`, `GET /value/get`
- `GET/POST /key/security` (write when the body carries `sddl`, else read)

## Notes

- offreg does not write transaction logs. Log-behavior questions are answered
  `not_supported` on this side; libreg is what the harness tests for log
  correctness.
- `/key/rename` is emulated (offreg has no native rename); see `STATE.md`.
