# Deployment

RESI is a local tool: a skill folder, a Python package and a state directory. The MCP server runs over stdio, started by the agent — there is no daemon to operate.

## Requirements

Python 3.11+ · ~50 MB disk for the runtime · state grows with evidence (`$RESI_HOME`). RE tools are optional and detected at runtime.

## macOS (Apple Silicon)

```bash
git clone https://github.com/kavioioai-svg/RE-Super-Intelligence.git && cd RE-Super-Intelligence
skills/re-super-intelligence/scripts/install.sh --target <your agent's skills folder> \
    --with-runtime --venv ~/.resi/venv
python3 skills/re-super-intelligence/scripts/discover_environment.py
```

Optional tools (install only what your work needs, with approval): JDK 21 + Ghidra, Rizin, LLDB (Xcode command-line tools — GDB does not support Apple Silicon), binwalk, QEMU, JADX, apktool, Wireshark/TShark, Kaitai Struct compiler; for vision `pip install open3d trimesh opencv-python` inside the venv (check wheel availability for your Python version).

## Ubuntu VPS (x86_64)

```bash
sudo apt-get update && sudo apt-get install -y python3 python3-venv git
git clone https://github.com/kavioioai-svg/RE-Super-Intelligence.git && cd RE-Super-Intelligence
skills/re-super-intelligence/scripts/install.sh --target <your agent's skills folder> \
    --with-runtime --venv ~/.resi/venv
```

Optional tools: `apt-get install openjdk-21-jdk gdb binwalk qemu-system-arm qemu-system-aarch64 tshark` plus Ghidra, Rizin, JADX and apktool from their releases. GUI tools (Cutter, ImHex) need a display; skip them on a headless server. Run unblob and MobSF in containers.

**Isolation on a VPS:** run dynamic analysis inside a separate VM or container with networking disabled by default; never on the host that holds `$RESI_HOME`.

## Register with your agent

Add an MCP server entry: command = absolute path to `~/.resi/venv/bin/resi`, args = `["mcp"]`, env `RESI_HOME`. Template: [`examples/mcp-config.json`](../skills/re-super-intelligence/examples/mcp-config.json). Then feed the registry the tool names your agent announces (`resi_refresh_registry`).

## State, backup and upgrade

| Path | Contents | Back up? |
|---|---|---|
| `$RESI_HOME/resi.db` (+ `-wal`, `-shm`) | Evidence, scope, memory, learning | Yes — use `sqlite3 resi.db ".backup backup.db"` for a consistent copy |
| `$RESI_HOME/registry.json` | Capability registry | Optional (rebuilt by refresh; verifications preserved) |
| `$RESI_HOME/audit.log` | Audit trail | Yes; ship off-host if tamper evidence matters |

Upgrade: `git pull`, then `~/.resi/venv/bin/pip install -e './orchestrator[vision]'`, then re-run the installer with `--force` to refresh the skill (the previous copy is kept as a timestamped backup). Run the test suite after upgrading.

Several machines or users can share evidence only through a shared database — implement the PostgreSQL adapter (see [`EVIDENCE_SCHEMA.md`](EVIDENCE_SCHEMA.md)) rather than sharing a SQLite file over a network filesystem.

## Troubleshooting

| Problem | Fix |
|---|---|
| `error: Python 3.11+ not found` | Install one (`brew install python@3.12` / `apt install python3.12-venv`) or run with `PYTHON=/path/to/python3.12` |
| Skill already installed, runtime missing | `install.sh --runtime-only` |
| `install.sh: … already exists` | Intentional; add `--force` (keeps a backup) |
| `install the vision extra` | `pip install -e './orchestrator[vision]'` |
| `database is locked` | Another RESI process holds a write; retry — WAL mode keeps readers unblocked |
| Agent can't start the MCP server | Use absolute paths; test with `echo '{"jsonrpc":"2.0","id":1,"method":"ping"}' \| resi mcp` |

## Private contribution ingestion (Kavio infrastructure)

The opt-in learning-contribution endpoint is the one networked component, and it runs only on Kavio's own servers: `resi ingest serve` with TLS and a bearer-token hash supplied through environment variables. User installations never run it. See [Learning contributions](LEARNING_CONTRIBUTIONS.md#accepting-uploads-private-team).
