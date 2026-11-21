# Tool Registry

What RESI may call. The catalogue lives in code (`orchestrator/resi/domain/catalog.py`); the *status* of each tool comes from discovery in the running environment. Rebuild after any install:

```bash
resi registry refresh --announced announced-tools.txt   # one MCP tool name per line
```

Any agent's MCP naming is accepted (`mcp__rea__x`, `mcp__remote-devices__rea__x`, `rea.x`). Tools from other MCP servers are kept: unknown ones default to class **D** until a human classifies them with `--overlay` (see `mcp-integration.md`).

## Status values

| Status | Meaning | May RESI use it? |
|---|---|---|
| `verified` | Exercised on an approved sample; output matched expectations; evidence on file | Yes |
| `discovered` | Announced by an MCP server / found on PATH, never exercised | Yes, but first use must be recorded and checked |
| `unverified` | Referenced by the spec but not found | No — report as missing |
| `incompatible` | Present but unusable on this platform | No |

**Rule:** a tool is never reported as "integrated" until it is `verified`. Every entry below is `discovered` unless noted.

## Security classes

| Class | Meaning | Gate |
|---|---|---|
| `R` read-only | Inspects a file already on disk | None, if artifact is in scope |
| `L` local-write | Writes to the local analysis DB (names, comments, bookmarks) | None; logged |
| `D` dynamic | Executes or attaches to code (Frida, GDB, emulation, browser automation) | **Explicit per-target approval** |
| `M` device-mutating | Changes a connected device (install, push, start, stop) | **Explicit per-action approval** |

---

## A. Binary Intelligence — server `rea`

| Group | Tools | Class |
|---|---|---|
| Session | `open_binary`, `close_binary`, `binary_session`, `binary_overview`, `list_documents`, `current_document` | R |
| Functions | `list_procedures`, `search_procedures`, `procedure_info`, `procedure_address`, `procedure_pseudo_code`, `procedure_assembly`, `batch_decompile`, `analyze_function`, `read_function_instructions`, `resolve_containing_procedure` | R |
| Graphs | `procedure_callers`, `procedure_callees`, `procedure_references`, `get_call_graph`, `build_call_path`, `trace_call_path`, `xrefs`, `find_xrefs_to_name` | R |
| Data | `list_strings`, `search_strings`, `list_names`, `address_name`, `list_segments`, `read_bytes`, `search_bytes`, `address_to_file_offset`, `inspect_address_context` | R |
| Native detail | `inspect_binary_layout`, `inspect_native_instruction`, `inspect_native_data_type`, `inspect_native_api`, `inspect_native_load_image`, `inspect_native_dispatch_metadata`, `resolve_native_call_targets`, `list_architectures` | R |
| Format-specific | `inspect_macho`, `inspect_pe_resources`, `inspect_signature`, `inspect_go_binary`, `inspect_rust_binary`, `inspect_dart_aot`, `identify_flutter_build`, `inspect_wasm_artifact` | R |
| Swift / ObjC | `demangle_swift`, `analyze_swift_types`, `get_objc_classes`, `get_objc_protocols` | R |
| Backends | `execute_rizin_command`, `cutter_command`, `list_cutter_sessions`, `inspect_with_objdump` | R* |
| Comparison | `compare_functions`, `compare_artifacts` | R |
| Navigation | `goto_address`, `next_address`, `prev_address`, `current_address`, `current_procedure`, `get_navigation_context`, `inspect_analysis_view` | R |
| Annotation | `set_address_name`, `set_addresses_names`, `set_comment`, `set_inline_comment`, `comment`, `inline_comment`, `annotate_native_function`, `set_bookmark`, `unset_bookmark`, `list_bookmarks` | L |

\* `execute_rizin_command` / `cutter_command` accept free-form commands. Restrict to analysis commands; reject `!` (shell escape), `o+`/`w*` (write), and `dc`/`ood` (execution) — see `references/mcp-integration.md` §Command filtering.

**Ghidra:** no standalone Ghidra MCP server was announced. Status `unverified`. REA may use Ghidra as a backend; confirm with `binary_overview` output metadata before claiming Ghidra results. **Capstone, angr:** not discovered — `unverified`; install only with approval (Phase 3).

## B. Runtime Intelligence — server `rea` — **all class D**

| Group | Tools |
|---|---|
| Frida | `list_frida_devices`, `list_frida_processes`, `start_frida_session`, `frida_session_status`, `resume_frida_session`, `instrument_with_frida`, `load_frida_script`, `unload_frida_script`, `close_frida_session` |
| GDB | `start_gdb_session`, `gdb_console`, `gdb_session_status`, `close_gdb_session` |
| Rizin debug | `start_rizin_debug_session`, `rizin_debug_command`, `rizin_debug_session_status`, `close_rizin_debug_session` |
| Observation | `observe_native_calls`, `trace_native_values`, `capture_process_scenario`, `compare_process_captures`, `inspect_recorded_crash` |
| Correlation | `correlate_static_and_runtime` |

`list_frida_devices` / `list_frida_processes` / `*_status` are enumeration only and may run without approval. Everything that attaches, spawns, or loads a script needs approval naming the exact process or binary. **LLDB:** not discovered.

## C. Firmware Intelligence — server `rea`

| Tools | Class |
|---|---|
| `inspect_artifact`, `inspect_firmware_regions` | R |
| `extract_firmware`, `extract_artifact` | L (writes extracted files to a working dir) |

Extraction output goes to an isolated working directory per artifact. **Never execute extracted binaries.** **Binwalk, Unblob, QEMU:** not discovered as standalone — `unverified`. QEMU-based emulation is Phase 4 and class D.

## D. Mobile Intelligence — server `rea`

| Group | Tools | Class |
|---|---|---|
| Android static | `inspect_android_package`, `inspect_android_class`, `inspect_android_method`, `search_android_classes`, `trace_android_references`, `decode_android_resources`, `project_android_application_graph`, `inspect_apktool_client` | R |
| JEB | `inspect_jeb_client`, `open_jeb_project`, `list_jeb_units`, `decompile_jeb_item` | R |
| Apple static | `project_apple_application_graph`, `inspect_plist`, `inspect_keyed_archive`, `decode_interface_builder`, `inspect_asset_catalog`, `trace_dylib_resolution` | R |
| Managed (.NET/JVM) | `inspect_managed_artifact`, `inspect_managed_members`, `compare_managed_members`, `inspect_managed_native_boundaries`, `verify_managed_native_boundaries`, `project_managed_application_graph`, `import_managed_reconstruction` | R |
| Other platforms | `project_harmony_application_graph` | R |
| ADB read | `list_adb_devices`, `inspect_adb_client`, `inspect_adb_device`, `inspect_adb_package`, `list_adb_packages`, `resolve_adb_packages`, `list_adb_directory`, `list_adb_processes`, `list_adb_services`, `list_adb_features`, `read_adb_logcat`, `read_adb_setting`, `inspect_adb_display`, `inspect_adb_window`, `capture_adb_screen`, `collect_adb_bugreport` | D (touches a live device) |
| ADB pull | `pull_adb_package`, `pull_adb_file` | D |
| **ADB mutate** | `install_adb_package`, `uninstall_adb_package`, `push_adb_file`, `start_adb_app`, `start_adb_activity`, `stop_adb_app` | **M** |

`read_adb_logcat` and `collect_adb_bugreport` can surface personal data — redact before logging. **JADX, apktool, MobSF:** apktool is reachable via REA's apktool client; JADX/MobSF standalone not discovered.

## E. Protocol Intelligence — server `rea`

| Tools | Class |
|---|---|
| `inspect_pcap_client`, `inspect_pcap_capture`, `inspect_packet_capture`, `inspect_packet_fields` | R |
| `decode_signal_recording`, `inspect_signal_decoders` | R |
| `inspect_sqlite_database` | R |

Analysis of **existing** captures only. RESI does not start live capture. Redact credentials and tokens from any field output. **TShark, Kaitai Struct, ImHex:** not discovered — `unverified`. Kaitai is the Phase 4 format-spec tool.

## F. Web & API Intelligence — server `rea` (+ `playwright` plugin)

| Group | Tools | Class |
|---|---|---|
| Static bundle | `analyze_web_bundle`, `analyze_javascript_application`, `recover_javascript_sources`, `export_web_scripts`, `trace_web_module_imports`, `trace_web_source_location`, `trace_javascript_semantics` | R |
| Comparison | `compare_bundles`, `compare_source_to_bundle`, `compare_javascript_export_shapes`, `compare_wasm_interfaces`, `compare_web_captures`, `compare_web_screenshots` | R |
| Live page | `inspect_web_page`, `inspect_web_event_listeners`, `inspect_web_network_capture`, `capture_web_screenshot`, `capture_browser_scenario`, `observe_web_execution`, `observe_web_session`, `observe_javascript_runtime`, `reconcile_javascript_runtime`, `list_browser_targets`, `list_javascript_runtime_targets`, `discover_webmcp_tools` | D |
| Electron | `list_electron_targets`, `inspect_electron_page`, `inspect_electron_fuses`, `capture_electron_scenario` | D (`inspect_electron_fuses` is R) |
| Contracts | `inspect_evm_interface` | R |

Live-page tools run against a URL the user names, within its auth and rate limits. **Semgrep, OpenAPI tooling:** not discovered.

## G. 3D Vision Intelligence — local Python (no MCP)

| Library | Status | Class |
|---|---|---|
| NumPy, SciPy | check on target | R |
| OpenCV (`cv2`) | check on target | R |
| Open3D | check on target; arm64 wheels exist for recent versions | R |
| trimesh | check on target | R |
| FreeCAD | check on target; GUI app, scriptable via `FreeCADCmd` | L |

Run `scripts/discover_environment.py --vision` on the target machine to fill in status.

## Cross-cutting — REA evidence & reconstruction

RESI's evidence model **wraps** these rather than duplicating them:

| Tool | RESI use |
|---|---|
| `record_unknown`, `list_unknowns`, `update_unknown`, `verify_unknown_resolution` | Backing store for open questions and hypothesis status |
| `export_evidence_bundle`, `get_evidence_bundle`, `import_evidence_bundle` | Portable evidence packages per project |
| `build_reconstruction_obligation_ledger`, `evaluate_reconstruction_coverage`, `verify_reconstruction` | Clean-room spec coverage checks |
| `trace_feature`, `trace_application_feature`, `find_changed_behavior`, `compare_application_versions` | Feature-level research questions |
| Native UI: `observe_native_ui`, `trace_native_ui_action`, `capture_native_ui_scenario` | Class D — UI-driven behaviour tracing |

## Entry schema (`ToolDescriptor`)

```yaml
id: rea.procedure_pseudo_code        # server.tool
server: rea
module: binary
group: functions
version: discovered-2026-11-21       # replaced by the real version once verified
input_types: [elf, pe, macho, macho-fat, wasm, dos-mz, unknown-binary]
operations: [decompile, disassemble, function_map]
permissions: [read_artifact]
environment: mcp                     # mcp | cli | python
timeout_s: 120
output_schema: recorded from first execution
failure_conditions: [timeout, transport_error, unexpected_output]
security_class: R                    # R | L | D | M
status: discovered                   # verified | discovered | unverified | incompatible
evidence_ids: []                     # required before status can be verified
```
