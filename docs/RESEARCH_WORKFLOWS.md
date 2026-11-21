# Research workflows

The universal loop is in [`SKILL.md`](../skills/re-super-intelligence/SKILL.md) and the methodology in [`references/research-methodology.md`](../skills/re-super-intelligence/references/research-methodology.md). Below: what changes per target type. Every workflow starts with `resi_recall` and ends with validate → audit → report → refresh lessons.

## Native binary (`general`)

1. Human: `project init`, `project authorize <binary>`.
2. Plan → `binary_overview` → strings and imports → function inventory → call graph.
3. Decompile only functions tied to a research question.
4. Corroborate key findings with a second view (assembly or another backend), same `subject`.
5. Optional runtime confirmation: hypothesis → human approval → Frida/LLDB in a VM.

## Firmware (`firmware`)

1. Classify and map regions (entropy shows compressed/encrypted areas).
2. Extract into the isolated store; re-classify every member.
3. Inventory: bootloader, kernel, filesystem, configuration, update mechanism, third-party versions.
4. Route executables to the binary workflow, formats to the protocol workflow.
5. Emulation (QEMU, networking off) only with approval, after static work.

## Mobile app (`mobile`)

1. Use builds you own or are authorized to test.
2. Manifest, permissions, components → resources → application graph → framework detection (Flutter, React Native…).
3. API contract discovery from code and your own test traffic.
4. Device work (install, start, logcat) is class D/M — each needs approval; prefer an emulator.

## Protocol or file format (`web-api` / `general`)

1. Captures of your own traffic, or sample files you may analyse.
2. Conversations → messages → fields; test each field hypothesis across all samples.
3. Write a Kaitai Struct spec or a field table; validate it parses every sample.

## Web application and API (`web-api`)

1. Static first: bundle analysis, source-map recovery, module graph.
2. Live observation (Playwright, network capture) only on targets you are authorized to test, respecting auth and rate limits.
3. Document request/response schemas; draft an OpenAPI description from observed behaviour.

## 3D vision (`vision-3d`)

1. `resi vision-demo` proves the pipeline on a synthetic phantom with known truth.
2. Calibrate the sensor; process clouds; reconstruct; measure with uncertainty.
3. Physical phantoms before any human data; human data only de-identified, under protocol.
Profile rules: [`references/profiles.md`](../skills/re-super-intelligence/references/profiles.md).

## Clean-room reimplementation (any profile)

1. Systems Architect writes the functional spec from verified/supported claims only.
2. `resi cleanroom spec.md` must exit 0.
3. Implementers receive the spec and test vectors — never the research workspace.

## Handling a missing tool

`resi_plan` lists it under `missing` and uses a fallback when one exists. Install it (with approval), refresh the registry, and re-plan. Never route around a missing tool by guessing its output.
