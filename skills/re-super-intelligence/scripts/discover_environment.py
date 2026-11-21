#!/usr/bin/env python3
"""Read-only environment discovery for RESI (Phase 1 of the roadmap).

Reports OS, CPU, memory, disk, language runtimes, container tooling, reverse
engineering binaries, Python libraries, installed agent skills and configured
MCP server *names*. It never executes discovered RE tools, never modifies
anything, and never prints configuration values (they can contain secrets).

    python3 discover_environment.py            # Markdown report
    python3 discover_environment.py --json     # machine-readable
"""

from __future__ import annotations

import argparse
import importlib.util
import json
import os
import platform
import shutil
import subprocess
import sys
from pathlib import Path
from typing import Any

RE_BINARIES = {
    "binary": ["analyzeHeadless", "ghidraRun", "rizin", "rz-bin", "radare2", "cutter", "objdump"],
    "runtime": ["frida", "frida-trace", "gdb", "lldb"],
    "firmware": ["binwalk", "unblob", "qemu-system-arm", "qemu-system-aarch64", "qemu-arm"],
    "mobile": ["jadx", "apktool", "adb"],
    "protocol": ["tshark", "kaitai-struct-compiler", "imhex"],
    "web": ["semgrep", "node", "npx"],
    "vision": ["FreeCADCmd", "freecadcmd"],
}
PY_LIBS = {
    "binary": ["capstone", "angr", "lief"],
    "web": ["playwright", "httpx", "requests"],
    "vision": ["numpy", "scipy", "cv2", "open3d", "trimesh"],
}
# Version probes only for runtimes, never for analysis tools.
VERSION_PROBES = {
    "python3": ["python3", "--version"],
    "java": ["java", "-version"],
    "docker": ["docker", "--version"],
    "podman": ["podman", "--version"],
    "colima": ["colima", "version"],
    "git": ["git", "--version"],
}
MAX_CONFIG_BYTES = 2_000_000


def run_version(cmd: list[str]) -> str | None:
    if not shutil.which(cmd[0]):
        return None
    try:
        out = subprocess.run(cmd, capture_output=True, text=True, timeout=10, check=False)
    except (OSError, subprocess.TimeoutExpired):
        return "present (version probe failed)"
    lines = [line for line in (out.stdout + out.stderr).splitlines()
             if line.strip() and not line.startswith("Picked up ")]  # JVM option banners
    return lines[0].strip()[:120] if lines else "present"


def memory_bytes() -> int | None:
    try:
        if sys.platform == "darwin":
            out = subprocess.run(["sysctl", "-n", "hw.memsize"], capture_output=True, text=True,
                                 timeout=5, check=False)
            return int(out.stdout.strip())
        pages, size = os.sysconf("SC_PHYS_PAGES"), os.sysconf("SC_PAGE_SIZE")
        return int(pages * size)
    except (OSError, ValueError, subprocess.TimeoutExpired):
        return None


def system_info() -> dict[str, Any]:
    disk = shutil.disk_usage(Path.home())
    mem = memory_bytes()
    return {
        "os": f"{platform.system()} {platform.release()}",
        "platform": platform.platform(),
        "arch": platform.machine(),
        "cpu_count": os.cpu_count(),
        "memory_gb": round(mem / 1e9, 1) if mem else None,
        "disk_free_gb": round(disk.free / 1e9, 1),
        "disk_total_gb": round(disk.total / 1e9, 1),
        "python": sys.version.split()[0],
    }


def skill_dirs() -> list[dict[str, Any]]:
    """Find SKILL.md files in conventional agent skill folders (home and project)."""
    roots = {*Path.home().glob(".*/skills"), Path.home() / "skills", Path.cwd() / "skills",
             *Path.cwd().glob(".*/skills")}
    found = []
    for root in sorted(r for r in roots if r.is_dir()):
        for skill_md in sorted(root.glob("*/SKILL.md")):
            name = skill_md.parent.name
            found.append({
                "name": name,
                "path": str(skill_md.parent),
                "re_related": any(k in name.lower() for k in ("rea", "ghidra", "reverse", "rizin",
                                                               "re-super")),
            })
    return found


def _mcp_names(data: Any, path: str) -> list[dict[str, str]]:
    """Collect server names under any 'mcpServers' / 'mcp_servers' key. Values are ignored."""
    names: list[dict[str, str]] = []
    if isinstance(data, dict):
        for key, value in data.items():
            if key in ("mcpServers", "mcp_servers") and isinstance(value, dict):
                names.extend({"server": str(n), "config": path} for n in value)
            else:
                names.extend(_mcp_names(value, path))
    elif isinstance(data, list):
        for item in data:
            names.extend(_mcp_names(item, path))
    return names


def mcp_servers() -> list[dict[str, str]]:
    candidates = {*Path.home().glob(".*.json"), *Path.home().glob(".*/*.json"),
                  *Path.home().glob(".config/*/*.json"), Path.cwd() / ".mcp.json",
                  *Path.cwd().glob(".*/*.json")}
    servers: list[dict[str, str]] = []
    for path in sorted(p for p in candidates if p.is_file()):
        try:
            if path.stat().st_size > MAX_CONFIG_BYTES:
                continue
            text = path.read_text(encoding="utf-8")
        except (OSError, UnicodeDecodeError):
            continue
        if "mcpServers" not in text and "mcp_servers" not in text:
            continue
        try:
            servers.extend(_mcp_names(json.loads(text), str(path)))
        except json.JSONDecodeError:
            continue
    unique = {(s["server"], s["config"]): s for s in servers}
    return sorted(unique.values(), key=lambda s: (s["server"], s["config"]))


def discover() -> dict[str, Any]:
    binaries = {m: {b: bool(shutil.which(b)) for b in bs} for m, bs in RE_BINARIES.items()}
    libs = {m: {lib: importlib.util.find_spec(lib) is not None for lib in ls}
            for m, ls in PY_LIBS.items()}
    skills = skill_dirs()
    servers = mcp_servers()
    risks = []
    if not any(s["server"] == "rea" for s in servers):
        risks.append("No 'rea' MCP server found in config files; confirm it is announced in "
                     "your agent session before planning REA-backed steps.")
    if not binaries["binary"]["analyzeHeadless"]:
        risks.append("Ghidra headless (analyzeHeadless) not on PATH; Ghidra results stay "
                     "unverified unless REA uses it as a backend.")
    if platform.machine().lower() in ("arm64", "aarch64"):
        risks.append("ARM64 host: x86 firmware/binaries need emulation for dynamic work; "
                     "check arm64 builds of Frida, angr and Open3D before installing.")
    if not (binaries["firmware"]["qemu-system-arm"] or binaries["firmware"]["qemu-system-aarch64"]):
        risks.append("No QEMU system emulator: firmware stays static-only (Phase 4 needs it).")
    return {
        "system": system_info(),
        "runtimes": {name: run_version(cmd) for name, cmd in VERSION_PROBES.items()},
        "re_binaries": binaries,
        "python_libraries": libs,
        "skills": skills,
        "mcp_servers": servers,
        "risks": risks,
    }


def to_markdown(report: dict[str, Any]) -> str:
    s = report["system"]
    lines = ["# RESI environment assessment", "",
             f"- **OS:** {s['os']} ({s['arch']}), Python {s['python']}",
             (f"- **CPU:** {s['cpu_count']} cores · **RAM:** {s['memory_gb']} GB · "
              f"**Disk free:** {s['disk_free_gb']} / {s['disk_total_gb']} GB"), "",
             "## Runtimes", ""]
    lines += [f"- {k}: {v or 'not found'}" for k, v in report["runtimes"].items()]
    lines += ["", "## Reverse engineering tools", "", "| Module | Present | Missing |",
              "|---|---|---|"]
    for module, tools in report["re_binaries"].items():
        libs = report["python_libraries"].get(module, {})
        present = [t for t, ok in {**tools, **libs}.items() if ok]
        missing = [t for t, ok in {**tools, **libs}.items() if not ok]
        lines.append(f"| {module} | {', '.join(present) or '-'} | {', '.join(missing) or '-'} |")
    lines += ["", "## Skills", ""]
    lines += [f"- {k['name']}{' (RE)' if k['re_related'] else ''} — `{k['path']}`"
              for k in report["skills"]] or ["- none found"]
    lines += ["", "## MCP servers (names only)", ""]
    lines += [f"- {m['server']} — `{m['config']}`" for m in report["mcp_servers"]] or ["- none found"]
    lines += ["", "## Risks and blockers", ""]
    lines += [f"- {r}" for r in report["risks"]] or ["- none detected"]
    return "\n".join(lines) + "\n"


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--json", action="store_true", help="emit JSON instead of Markdown")
    args = parser.parse_args()
    report = discover()
    print(json.dumps(report, indent=2) if args.json else to_markdown(report))
    return 0


if __name__ == "__main__":
    sys.exit(main())
