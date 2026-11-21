# Capability matrix

What each specialist module can do, through which tools, and how those tools behave on the two target platforms. Run `scripts/discover_environment.py` on your machine for its actual state; nothing below counts as verified until an execution proves it.

## Modules

REA tool counts come from the catalogue (207 tools in total).

| Module | Capabilities | Primary (REA MCP) | Fallbacks / external | Security classes |
|---|---|---|---|---|
| Binary | Classification, disassembly, decompilation, function map, call graph, xrefs, strings, symbols, format-specific (Mach-O, PE, Go, Rust, Swift/ObjC, Dart, WASM), diffing | 76 tools | Ghidra, Rizin, Cutter, Capstone, angr | R, L (annotation) |
| Runtime | Process observation, call tracing, value tracing, crash inspection, static↔runtime correlation | 26 tools | Frida, GDB, LLDB | D (enumeration R) |
| Firmware | Identification, region map, extraction, component inventory | 4 tools | binwalk, unblob, QEMU | R, L, D (emulation) |
| Mobile | Android/iOS/managed/Harmony app graphs, manifests, resources, classes, JEB; ADB device work | 50 tools | JADX, apktool, ADB | R, D (device read), M (device change) |
| Protocol | PCAP dissection, field mapping, signal decoding, SQLite schemas | 7 tools | TShark, Kaitai Struct, ImHex | R |
| Web & API | Bundle analysis, source recovery, module graphs, WASM, Electron, live page observation | 30 tools | Playwright, Semgrep | R, D (live) |
| 3D Vision | Calibration, point clouds, meshes, measurement with uncertainty, CAD | — | numpy, SciPy, OpenCV, Open3D, trimesh, FreeCAD | R, L |
| Evidence | Unknowns ledger, evidence bundles, reconstruction coverage | 14 tools | RESI evidence store | R, L |

## RESI-run tools

| Tool | Capability | Status |
|---|---|---|
| `resi.reconstruction_score` | Byte-level scorecard for Mach-O (thin/fat), ELF, PE; build-volatile regions excluded | Built in; always available |
| `cli.rizin` | Independent second engine for corroboration (info, sections, imports, strings, functions, disassembly) | Needs Rizin on PATH (`brew install rizin` / package manager) |

## Platform compatibility

| Tool | macOS (Apple Silicon) | Ubuntu (x86_64 VPS) | Notes |
|---|---|---|---|
| Ghidra (headless) | Yes (Java 21) | Yes (Java 21) | Install a JDK first; `analyzeHeadless` on PATH |
| Rizin | Yes | Yes | Package manager or release build |
| Cutter | Yes (GUI) | GUI only with a display | Skip on a headless VPS |
| Capstone | Yes (pip) | Yes (pip) | |
| angr | Check wheel for your Python | Yes (pip) | Heavy; install in its own venv |
| Frida | Yes | Yes | Target must be a VM, emulator or test device |
| GDB | Not supported on Apple Silicon | Yes | Use LLDB on macOS |
| LLDB | Yes (Xcode tools) | Yes | |
| binwalk (v3) | Yes | Yes | |
| unblob | Linux-first | Yes | On macOS run it in a container |
| QEMU | Yes | Yes | Isolated guest, networking off by default |
| JADX, apktool | Yes (Java) | Yes (Java) | |
| MobSF | Container | Container | Run as a service only with approval |
| TShark | Yes | Yes | Analyse existing captures only |
| Kaitai Struct compiler | Yes (Java) | Yes (Java) | |
| ImHex | Yes (GUI) | GUI only with a display | |
| Semgrep | Yes | Yes | |
| Playwright | Yes | Yes | Live pages are class D |
| numpy, SciPy, OpenCV, trimesh | Yes | Yes | |
| Open3D | Check wheel for your Python | Yes | Wheels lag new Python releases |
| FreeCAD (`FreeCADCmd`) | Yes | Yes | Headless command for scripting |

Architecture notes: on an ARM64 host, x86 binaries and firmware need emulation for any dynamic work, and some Python wheels arrive later for new Python versions — pin Python 3.11 or 3.12 for the vision stack if a wheel is missing.

## Status vocabulary

| Status | Meaning |
|---|---|
| `verified` | Exercised on an approved sample; evidence id on file |
| `discovered` | Announced by an MCP server or found on PATH; never exercised |
| `unverified` | Named by the catalogue but not found |
| `incompatible` | Present but unusable on this platform |

The full tool list with groups and classes is in [`references/tool-registry.md`](../skills/re-super-intelligence/references/tool-registry.md).
