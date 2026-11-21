# Expert playbooks

Field-tested procedures for each kind of target. Each one ends in evidence: claims tied to executions, and hypotheses with a falsification test. Import them into memory with `resi_import_playbooks` so they're recalled automatically; this file is the source.

Every playbook assumes the target is authorized and work is static unless a human has approved dynamic steps.

## Triage: any unknown file (first ten minutes)

1. `resi_classify`: trust content, not the extension. Note magic bytes, size and entropy.
2. `resi_recall` the kind and goal. Past findings and lessons change the plan.
3. `resi_plan`. Read `missing`, `recommended`, `needs_approval`, and pass `plan.target` (the SHA-256) as `target` in every later call.
4. Orientation before depth: format, architecture, sections or segments, imports and exports, strings, signing. Decompile nothing yet.
5. Write 2–5 research questions that evidence can answer.
6. Run the cheapest high-information step for each question. Record every call, including failures.

## Native binaries: finding the code that matters

| Lead | How | Why it works |
|---|---|---|
| Strings → cross-references | `list_strings` / `search_strings`, then `xrefs` on the address | Error messages, URLs, format strings and file paths sit next to the logic that uses them |
| Imports | `inspect_native_api`, imports in `inspect_macho` / PE / ELF | Crypto, network, file and process APIs reveal capabilities |
| Entry points | `main`, initializers (`__mod_init_func`, `.init_array`, TLS callbacks), exports | Code runs from here; initializers run before `main` |
| Call graph | `get_call_graph`, `procedure_callers` / `procedure_callees` | Distance from an entry point and fan-in show importance |
| Second engine | `resi_run_local` with `cli.rizin` (`ij`, `iSj`, `iij`, `aaa;aflj`) | Independent agreement promotes claims to `supported` |

Decompile narrowly: one function, then its callees. Decompiler output is `tool_derived`; confirm important reads against `procedure_assembly`.

## Fingerprinting language, compiler and runtime

| Signal | Indicates |
|---|---|
| `runtime.`/`main.` symbols, `.gopclntab` / `__gopclntab`, `Go build ID:` string | Go: use `inspect_go_binary`; function names survive stripping via pclntab |
| `core::panicking`, `rust_panic`, `_ZN…17h<16 hex>E` or `_R` symbols | Rust: use `inspect_rust_binary` |
| `_$s` mangled names, `__swift5_*` sections | Swift: use `analyze_swift_types`, `demangle_swift` |
| `__objc_classlist`, `__objc_selrefs` | Objective-C: use `get_objc_classes`, `get_objc_protocols` |
| `_ZN`, `_ZTV` (vtables), `__cxa_throw` | C++ (Itanium ABI) |
| CLR header / `mscoree.dll` import | .NET: use `inspect_managed_artifact` |
| `libapp.so` + `libflutter.so`, `Flutter` framework | Flutter (Dart AOT): use `identify_flutter_build`, `inspect_dart_aot` |
| `MEI`, `pyi-` strings, `PYZ` archive | PyInstaller-packed Python |
| `app.asar`, Electron framework | Electron: use `inspect_electron_fuses`, `analyze_web_bundle` |
| ELF `.comment` section, e.g. `GCC: (…) 13.2.0` | Exact compiler and version (vital for byte-matching) |
| Mach-O `LC_BUILD_VERSION` / `LC_VERSION_MIN_*` | SDK, minimum OS and linker tool versions |
| PE Rich header, linker version in the optional header | MSVC toolchain build numbers |

## Recognising algorithms by their constants

Search for the constant in both byte orders (`search_bytes`), take the cross-reference to the function, confirm the structure, then prove it with a test-vector experiment.

| Algorithm | Distinctive constants |
|---|---|
| AES | S-box begins `63 7c 77 7b f2 6b 6f c5`; inverse S-box begins `52 09 6a d5`; T-table Te0 starts `c66363a5` (byte order varies) |
| SHA-256 | K: `428a2f98 71374491 b5c0fbcf e9b5dba5`; initial H: `6a09e667 bb67ae85` |
| SHA-512 | K starts `428a2f98d728ae22 7137449123ef65cd`; initial H starts `6a09e667f3bcc908` |
| SHA-1 | initial state `67452301 efcdab89 98badcfe 10325476 c3d2e1f0`; round constants `5a827999 6ed9eba1 8f1bbcdc ca62c1d6` |
| MD5 | initial state as SHA-1's first four; T table starts `d76aa478 e8c7b756 242070db` |
| ChaCha20 / Salsa20 | `expand 32-byte k` = words `61707865 3320646e 79622d32 6b206574` |
| Blowfish | P-array starts `243f6a88 85a308d3` (digits of π) |
| TEA / XTEA | delta `9e3779b9` |
| CRC-32 | reflected polynomial `edb88320` (normal `04c11db7`); table starts `00000000 77073096` |
| CRC-32C | reflected polynomial `82f63b78` |
| MurmurHash3 (32-bit) | `cc9e2d51 1b873593`, finaliser `85ebca6b c2b2ae35` |
| xxHash32 | primes `9e3779b1 85ebca77 c2b2ae3d` |
| FNV-1a (32-bit) | offset basis `811c9dc5`, prime `01000193` |
| zlib / DEFLATE | stream header `78 01`, `78 5e`, `78 9c` or `78 da` |
| Base64 | alphabet string `ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/` |
| RC4 | no constants: a 256-iteration key-scheduling loop that swaps a byte array |

A constant alone is a hypothesis. Constants plus the expected round structure make a `tool_derived` claim. A matching test vector makes it `verified`.

## Strings that don't appear in the string list

- **Stack strings:** characters moved into a stack buffer one immediate at a time. Look for runs of byte or word stores of printable values.
- **Encoded strings:** a loop XOR-ing or adding a constant, run just before the string is used. Decode statically by re-implementing the loop on the bytes, and record the decoder as a hypothesis until the output is readable and consistent.
- **Encrypted string tables:** one decrypt routine with very high fan-in. Find it via `procedure_callers` counts.
- If static decoding fails, the runtime option is a class D experiment: trace the decoder's return values (`trace_native_values`) in an isolated environment, after a human approves it.

## Packing, obfuscation and anti-analysis: recognise and report

| Indicator | What it suggests |
|---|---|
| Section entropy above ~7.2 bits per byte | Compressed or encrypted payload |
| Tiny import table plus dynamic resolution (`LoadLibrary`/`GetProcAddress`, `dlopen`/`dlsym`) | Packed or loader stub |
| `UPX!` marker, `UPX0`/`UPX1` sections | UPX packing |
| Writable and executable section, or data after the last section (overlay) | Self-modifying code or an appended payload |
| One large function with a state variable driving a `switch` dispatcher | Control-flow flattening |
| Conditions that always resolve one way | Opaque predicates |
| `ptrace(PT_DENY_ATTACH)`, `sysctl` `P_TRACED`, `IsDebuggerPresent`, timing checks | Anti-debugging |

Record these as findings. RESI does not bypass protections. For authorized work, ask the owner for an unprotected build, or analyse an approved dynamic dump in an isolated VM.

## Protocol and file-format inference

1. Gather many samples or messages: field boundaries show up as what varies against what stays constant.
2. Magic and version: constant leading bytes across all samples.
3. Length fields: test "value equals the bytes that follow" on every sample, in both endiannesses and widths.
4. Type-length-value: a small set of type codes, each followed by a length that fits.
5. Counters and sequence numbers rise monotonically across messages. Timestamps fall in a plausible epoch range.
6. Checksums: try CRC-32, CRC-16, Adler-32 and simple sums over candidate ranges until one matches every sample.
7. Compressed payloads have a zlib header or high entropy. Encrypted payloads have uniform entropy, often in lengths that are multiples of 16.
8. Write the format as a Kaitai Struct spec or a field table, and validate it parses every sample. Each field is a claim with offsets and evidence.

Credentials, tokens and cookies are redacted automatically. Describe their position and role, never their value.

## Firmware

1. Identify the container (vendor header, uImage, TRX, FIT, SquashFS, UBI) and build an entropy map (`inspect_firmware_regions`).
2. Extract into the isolated store (`extract_firmware`). Re-classify every member.
3. Map the system: bootloader and its environment, kernel, root filesystem, init scripts, services, web root, configuration, update mechanism (is the image signature checked?).
4. Find the CPU architecture from the ELF headers of extracted binaries.
5. Build a component inventory (an SBOM) with versions from strings and package metadata. A known-vulnerable version is a hypothesis until the vulnerable code path is confirmed.
6. Keys and certificates found are reported by location and type, never by value.
7. Emulation (QEMU, networking off) only with approval, after static work narrows what to observe.

## Mobile applications

**Android:** manifest first (exported components, permissions, `networkSecurityConfig`, backup flags), then resources, native libraries per ABI, and framework:

| Framework | Marker | Next step |
|---|---|---|
| Flutter | `libapp.so` + `libflutter.so` | `inspect_dart_aot` |
| React Native | `assets/index.android.bundle`; Hermes bytecode starts `c6 1f bc 03 c1 03 19 1f` | JavaScript or Hermes bundle analysis |
| Unity (IL2CPP) | `libil2cpp.so` + `global-metadata.dat` | metadata-driven symbol recovery |
| .NET MAUI / Xamarin | `assemblies.blob` or `assemblies/*.dll` | `inspect_managed_artifact` |
| Native Kotlin/Java | `classes*.dex` | `inspect_android_class`, `search_android_classes` |

**iOS:** `Info.plist` and entitlements, App Transport Security settings, embedded frameworks, Swift and Objective-C class inventory, then the main executable as a native binary.

## Web applications and bundles

- `//# sourceMappingURL=` comments and `.map` files: `recover_javascript_sources` restores original module structure.
- The webpack or Vite chunk map and runtime give module boundaries: `trace_web_module_imports`.
- Search bundles for API base URLs, route tables, feature flags and GraphQL operations to map the API surface.
- WebAssembly: `inspect_wasm_artifact` for imports and exports. The import list is the module's whole interface to the page.
- Electron: `inspect_electron_fuses`, preload scripts, `contextIsolation` and `nodeIntegration` settings.

## Patch and version diffing

1. `compare_artifacts` on two versions, then `compare_functions` on changed candidates.
2. Match functions by symbols, then unique strings, then call-graph position and size.
3. Small changes in input validation or bounds checks usually mark a fix. Describe the behavioural change and its risk, with both versions' evidence.
4. `find_changed_behavior` and `compare_application_versions` cover application-level changes.

## Byte-matching reconstruction (authorized targets only)

Use this for binaries you own, open-source projects and lost-source recovery. Never use it as input to a clean-room implementation.

1. Identify the toolchain exactly: compiler and version (ELF `.comment`, Mach-O `LC_BUILD_VERSION`, PE Rich header), flags, linker and link order.
2. Reproduce one function first. Get its file range from the decompiler or `aflj`, rebuild, then score it with `resi_reconstruction_score` using `functions: [{name, original_offset, size, rebuilt_offset}]`.
3. Iterate function by function until each is `identical`. The whole file then reaches `identical-except-volatile`, where only build ids, UUIDs, timestamps and signatures differ.
4. Record each scorecard as evidence. Progress is measured, not claimed.

## Clean-room specifications

1. Use only `verified` and `supported` claims.
2. Describe behaviour as inputs, outputs, states and error handling, in your own words.
3. Include test vectors derived from observed behaviour.
4. Exclude function names, offsets, variable names and code structure from decompilation.
5. Gate with `resi_cleanroom_check` (no findings) before anything reaches implementers.

## Writing claims that survive validation

- One fact per claim. The observation is what the tool returned; the interpretation is what it means.
- Always set `subject` with a stable key so independent tools can corroborate: `fn@<addr>:<what>`, `crypto:<algorithm>`, `proto:<message>:<field>`, `format:<kind>`, `component:<name>@<version>`.
- High confidence needs two independent tools, or a passing experiment.
- Put what would change your mind in `limitations`.
