# Reconstruction scoring

`resi_reconstruction_score` (CLI: `resi score --project ID ORIGINAL REBUILT`) measures how close a rebuilt binary is to the authorized original, byte by byte. Every score is recorded as an execution, so progress toward a match is evidence, not a claim.

## What it compares

| Level | How |
|---|---|
| Whole file | Position by position, skipping volatile regions in either file |
| Sections | Matched **by name**, so a section that moved in the rebuilt layout still scores against its counterpart |
| Functions (optional) | Ranges you supply: `[{name, original_offset, size, rebuilt_offset?}]`, e.g. from a decompiler's function list or Rizin `aflj` |

Formats: Mach-O (thin and fat; the slice matching the original's CPU is chosen), ELF (32/64-bit, both endiannesses), PE (PE32 and PE32+). Anything else is compared as one raw region.

## Volatile regions (excluded automatically)

| Format | Region | Why it changes on every build |
|---|---|---|
| Mach-O | `LC_UUID` payload | Per-link UUID |
| Mach-O | `LC_CODE_SIGNATURE` data | Signature hashes the build |
| ELF | `.note.gnu.build-id`, `.gnu_debuglink` | Build id, debug-file CRC |
| PE | COFF `TimeDateStamp`, optional-header `CheckSum` | Link time, image checksum |
| PE | Debug directory timestamps, CodeView record | PDB GUID, age and path |
| PE | Authenticode certificate table | Signature |

## Verdicts

| Verdict | Meaning |
|---|---|
| `identical` | Same SHA-256 |
| `identical-except-volatile` | Every compared byte matches; only build noise differs |
| `near` | At least 99 % of compared bytes match |
| `partial` | At least 50 % |
| `different` | Below 50 % |

The output also lists `differing_sections` with each one's `first_difference` offset, `missing_sections` / `extra_sections`, and the excluded volatile regions. A mismatch never rounds up to 100 %.

## Reading results

- One section differs at a small offset: usually one instruction or constant. Disassemble that range in both files.
- `.strtab` / symbol tables differ: often just the source file name or path embedded by the compiler. Build from the same path.
- Many sections shifted: a size change early in the file moved everything after it. Fix the first differing section first.
- Code matches but the whole file doesn't: compare toolchain metadata (ELF `.comment`, Mach-O `LC_BUILD_VERSION`, PE Rich header).

## Matching workflow

See `playbooks.md` › *Byte-matching reconstruction*. Byte-matching is for binaries you own, open-source work and lost-source recovery with permission; it is never input to a clean-room implementation.
