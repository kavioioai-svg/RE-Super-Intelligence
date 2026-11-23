"""Static catalogue of known tools, grouped by specialist module.

Catalogue membership asserts nothing about whether a tool works. Status is
decided by discovery (``discovered``/``unverified``) and only becomes
``verified`` through recorded evidence.
"""

from __future__ import annotations

from dataclasses import dataclass

from .enums import Module, SecurityClass

R, L, D, M = (
    SecurityClass.READ_ONLY,
    SecurityClass.LOCAL_WRITE,
    SecurityClass.DYNAMIC,
    SecurityClass.DEVICE_MUTATING,
)

BIN = ("elf", "pe", "macho", "macho-fat", "wasm", "dos-mz", "unknown-binary")
WEB = ("javascript", "wasm", "openapi", "url")
FIRMWARE_KINDS = ("uimage", "squashfs", "gzip", "high-entropy-blob", "zip-corrupt", "unknown-binary")


@dataclass(frozen=True, slots=True)
class CatalogGroup:
    module: Module
    group: str
    security_class: SecurityClass
    input_types: tuple[str, ...]
    operations: tuple[str, ...]
    tools: tuple[str, ...]


@dataclass(frozen=True, slots=True)
class ExternalTool:
    """A CLI binary or Python library probed outside MCP."""

    id: str
    module: Module
    security_class: SecurityClass
    executables: tuple[str, ...] = ()
    python_import: str | None = None


def _g(module: Module, group: str, sec: SecurityClass, inputs: tuple[str, ...],
       ops: tuple[str, ...], tools: str) -> CatalogGroup:
    return CatalogGroup(module, group, sec, inputs, ops, tuple(tools.split()))


REA_CATALOGUE: tuple[CatalogGroup, ...] = (
    # A. Binary intelligence
    _g(Module.BINARY, "session", R, BIN, ("open", "overview"),
       "open_binary close_binary binary_session binary_overview list_documents current_document"),
    _g(Module.BINARY, "functions", R, BIN, ("decompile", "disassemble", "function_map"),
       "list_procedures search_procedures procedure_info procedure_address procedure_pseudo_code "
       "procedure_assembly batch_decompile analyze_function read_function_instructions "
       "resolve_containing_procedure"),
    _g(Module.BINARY, "graphs", R, BIN, ("call_graph", "xrefs", "control_flow"),
       "procedure_callers procedure_callees procedure_references get_call_graph build_call_path "
       "trace_call_path xrefs find_xrefs_to_name"),
    _g(Module.BINARY, "data", R, BIN, ("strings", "symbols", "bytes"),
       "list_strings search_strings list_names address_name list_segments read_bytes search_bytes "
       "address_to_file_offset inspect_address_context"),
    _g(Module.BINARY, "native", R, BIN, ("layout", "types", "dispatch"),
       "inspect_binary_layout inspect_native_instruction inspect_native_data_type "
       "inspect_native_api inspect_native_load_image inspect_native_dispatch_metadata "
       "resolve_native_call_targets list_architectures"),
    _g(Module.BINARY, "format", R, (*BIN, "apk", "ipa"), ("format_inspection",),
       "inspect_macho inspect_pe_resources inspect_signature inspect_go_binary inspect_rust_binary "
       "inspect_dart_aot identify_flutter_build inspect_wasm_artifact"),
    _g(Module.BINARY, "swift-objc", R, ("macho", "macho-fat", "ipa"), ("type_recovery",),
       "demangle_swift analyze_swift_types get_objc_classes get_objc_protocols"),
    _g(Module.BINARY, "backends", R, BIN, ("raw_command",),
       "execute_rizin_command cutter_command list_cutter_sessions inspect_with_objdump"),
    _g(Module.BINARY, "comparison", R, BIN, ("diff",), "compare_functions compare_artifacts"),
    _g(Module.BINARY, "navigation", R, BIN, ("navigate",),
       "goto_address next_address prev_address current_address current_procedure "
       "get_navigation_context inspect_analysis_view"),
    _g(Module.BINARY, "annotation", L, BIN, ("annotate",),
       "set_address_name set_addresses_names set_comment set_inline_comment comment "
       "inline_comment annotate_native_function set_bookmark unset_bookmark list_bookmarks"),
    # B. Runtime intelligence
    _g(Module.RUNTIME, "frida-enum", R, ("process",), ("enumerate",),
       "list_frida_devices list_frida_processes frida_session_status"),
    _g(Module.RUNTIME, "frida", D, ("process",), ("trace", "instrument"),
       "start_frida_session resume_frida_session instrument_with_frida load_frida_script "
       "unload_frida_script close_frida_session"),
    _g(Module.RUNTIME, "gdb", D, ("process", *BIN), ("debug",),
       "start_gdb_session gdb_console gdb_session_status close_gdb_session"),
    _g(Module.RUNTIME, "rizin-debug", D, ("process", *BIN), ("debug",),
       "start_rizin_debug_session rizin_debug_command rizin_debug_session_status "
       "close_rizin_debug_session"),
    _g(Module.RUNTIME, "observation", D, ("process", *BIN), ("trace", "capture"),
       "observe_native_calls trace_native_values capture_process_scenario "
       "compare_process_captures inspect_recorded_crash correlate_static_and_runtime"),
    _g(Module.RUNTIME, "native-ui", D, ("process",), ("ui_trace",),
       "observe_native_ui trace_native_ui_action capture_native_ui_scenario"),
    # C. Firmware intelligence
    _g(Module.FIRMWARE, "inspect", R, FIRMWARE_KINDS, ("identify", "regions"),
       "inspect_artifact inspect_firmware_regions"),
    _g(Module.FIRMWARE, "extract", L, (*FIRMWARE_KINDS, "zip"), ("extract",),
       "extract_firmware extract_artifact"),
    # D. Mobile intelligence
    _g(Module.MOBILE, "android", R, ("apk", "aab"), ("manifest", "classes", "resources", "graph"),
       "inspect_android_package inspect_android_class inspect_android_method "
       "search_android_classes trace_android_references decode_android_resources "
       "project_android_application_graph inspect_apktool_client"),
    _g(Module.MOBILE, "jeb", R, ("apk", "aab", "jar"), ("decompile",),
       "inspect_jeb_client open_jeb_project list_jeb_units decompile_jeb_item"),
    _g(Module.MOBILE, "apple", R, ("ipa", "macho", "macho-fat"), ("plist", "ui", "graph"),
       "project_apple_application_graph inspect_plist inspect_keyed_archive "
       "decode_interface_builder inspect_asset_catalog trace_dylib_resolution"),
    _g(Module.MOBILE, "managed", R, ("jar", "java-class", "pe"), ("members", "graph"),
       "inspect_managed_artifact inspect_managed_members compare_managed_members "
       "inspect_managed_native_boundaries verify_managed_native_boundaries "
       "project_managed_application_graph import_managed_reconstruction"),
    _g(Module.MOBILE, "harmony", R, ("app",), ("graph",), "project_harmony_application_graph"),
    _g(Module.MOBILE, "adb-read", D, ("device",), ("device_inspect",),
       "list_adb_devices inspect_adb_client inspect_adb_device inspect_adb_package "
       "list_adb_packages resolve_adb_packages list_adb_directory list_adb_processes "
       "list_adb_services list_adb_features read_adb_logcat read_adb_setting inspect_adb_display "
       "inspect_adb_window capture_adb_screen collect_adb_bugreport pull_adb_package pull_adb_file"),
    _g(Module.MOBILE, "adb-mutate", M, ("device",), ("device_change",),
       "install_adb_package uninstall_adb_package push_adb_file start_adb_app "
       "start_adb_activity stop_adb_app"),
    # E. Protocol intelligence
    _g(Module.PROTOCOL, "pcap", R, ("pcap", "pcapng"), ("packets", "fields"),
       "inspect_pcap_client inspect_pcap_capture inspect_packet_capture inspect_packet_fields"),
    _g(Module.PROTOCOL, "signals", R, ("signal",), ("decode",),
       "decode_signal_recording inspect_signal_decoders"),
    _g(Module.PROTOCOL, "storage", R, ("sqlite",), ("schema",), "inspect_sqlite_database"),
    # F. Web and API intelligence
    _g(Module.WEB, "bundle", R, WEB, ("bundle", "sources", "modules"),
       "analyze_web_bundle analyze_javascript_application recover_javascript_sources "
       "export_web_scripts trace_web_module_imports trace_web_source_location "
       "trace_javascript_semantics inspect_evm_interface inspect_electron_fuses"),
    _g(Module.WEB, "comparison", R, WEB, ("diff",),
       "compare_bundles compare_source_to_bundle compare_javascript_export_shapes "
       "compare_wasm_interfaces compare_web_captures compare_web_screenshots"),
    _g(Module.WEB, "live", D, ("url",), ("observe", "capture"),
       "inspect_web_page inspect_web_event_listeners inspect_web_network_capture "
       "capture_web_screenshot capture_browser_scenario observe_web_execution observe_web_session "
       "observe_javascript_runtime reconcile_javascript_runtime list_browser_targets "
       "list_javascript_runtime_targets discover_webmcp_tools list_electron_targets "
       "inspect_electron_page capture_electron_scenario"),
    # Cross-cutting: REA's own evidence and reconstruction ledger
    _g(Module.EVIDENCE, "unknowns", L, ("any",), ("unknowns",),
       "record_unknown list_unknowns update_unknown verify_unknown_resolution"),
    _g(Module.EVIDENCE, "bundles", L, ("any",), ("evidence_bundle",),
       "export_evidence_bundle get_evidence_bundle import_evidence_bundle"),
    _g(Module.EVIDENCE, "reconstruction", R, ("any",), ("coverage",),
       "build_reconstruction_obligation_ledger evaluate_reconstruction_coverage "
       "verify_reconstruction trace_feature trace_application_feature find_changed_behavior "
       "compare_application_versions"),
)


def _x(tool_id: str, module: Module, sec: SecurityClass, exe: str = "",
       imp: str | None = None) -> ExternalTool:
    return ExternalTool(tool_id, module, sec, tuple(exe.split()), imp)


EXTERNAL_TOOLS: tuple[ExternalTool, ...] = (
    _x("cli.ghidra", Module.BINARY, R, "analyzeHeadless ghidraRun"),
    _x("cli.rizin", Module.BINARY, R, "rizin rz-bin"),
    _x("cli.cutter", Module.BINARY, R, "cutter Cutter"),
    _x("py.capstone", Module.BINARY, R, imp="capstone"),
    _x("py.angr", Module.BINARY, R, imp="angr"),
    _x("cli.frida", Module.RUNTIME, D, "frida frida-trace"),
    _x("cli.gdb", Module.RUNTIME, D, "gdb"),
    _x("cli.lldb", Module.RUNTIME, D, "lldb"),
    _x("cli.binwalk", Module.FIRMWARE, R, "binwalk"),
    _x("cli.unblob", Module.FIRMWARE, L, "unblob"),
    _x("cli.qemu", Module.FIRMWARE, D,
       "qemu-system-arm qemu-system-aarch64 qemu-arm qemu-system-mips"),
    _x("cli.jadx", Module.MOBILE, R, "jadx"),
    _x("cli.apktool", Module.MOBILE, R, "apktool"),
    _x("cli.adb", Module.MOBILE, D, "adb"),
    _x("cli.tshark", Module.PROTOCOL, R, "tshark"),
    _x("cli.kaitai", Module.PROTOCOL, R, "kaitai-struct-compiler ksc"),
    _x("cli.imhex", Module.PROTOCOL, R, "imhex"),
    _x("cli.semgrep", Module.WEB, R, "semgrep"),
    _x("py.playwright", Module.WEB, D, imp="playwright"),
    _x("py.numpy", Module.VISION, R, imp="numpy"),
    _x("py.scipy", Module.VISION, R, imp="scipy"),
    _x("py.opencv", Module.VISION, R, imp="cv2"),
    _x("py.open3d", Module.VISION, R, imp="open3d"),
    _x("py.trimesh", Module.VISION, R, imp="trimesh"),
    _x("cli.freecad", Module.VISION, L, "FreeCADCmd freecadcmd"),
)

BUILTIN_TOOLS: tuple[CatalogGroup, ...] = (
    _g(Module.BINARY, "builtin", R, (*BIN, "macho-fat", "raw"), ("reconstruction_score",),
       "reconstruction_score"),
)
"""Tools RESI implements itself (server ``resi``); always available."""

LOCAL_ENGINES = frozenset({"cli.rizin"})
"""External tools RESI can run itself, confined to the authorized artifact file."""

DEFAULT_TIMEOUTS = {"batch_decompile": 600, "extract_firmware": 600, "extract_artifact": 600}


def builtin_tool_ids() -> frozenset[str]:
    """Every tool id the built-in catalogue knows: REA tools, RESI's own, external engines.

    Tools announced by other servers (uncatalogued or overlay entries) are not
    included: their names are chosen by third parties and may be private.
    """
    ids = {f"rea.{name}" for group in REA_CATALOGUE for name in group.tools}
    ids |= {f"resi.{name}" for group in BUILTIN_TOOLS for name in group.tools}
    ids |= {ext.id for ext in EXTERNAL_TOOLS}
    return frozenset(ids)
