from __future__ import annotations

import shutil
import struct
import subprocess
from pathlib import Path

import pytest

from resi.domain.binary_layout import parse_layout
from resi.domain.reconstruction import FunctionRange, score_reconstruction

# --- synthetic binary builders -------------------------------------------------


def macho64(text: bytes, uuid: bytes = b"\x11" * 16, signature: bytes = b"\xaa" * 16,
            cpu: int = 0x0100000C) -> bytes:
    """Minimal thin arm64 Mach-O: one __TEXT segment with __text, LC_UUID, LC_CODE_SIGNATURE."""
    header_size, seg_size, uuid_size, sig_size = 32, 72 + 80, 24, 16
    cmds = seg_size + uuid_size + sig_size
    text_off = header_size + cmds
    sig_off = text_off + len(text)
    header = struct.pack("<IiIIIIII", 0xFEEDFACF, cpu, 0, 2, 3, cmds, 0, 0)
    segment = struct.pack("<II16sQQQQiiII", 0x19, seg_size, b"__TEXT", 0, 0x4000, 0, sig_off, 5, 5, 1, 0)
    section = struct.pack("<16s16sQQIIIIIIII", b"__text", b"__TEXT", 0, len(text), text_off,
                          2, 0, 0, 0x80000400, 0, 0, 0)
    lc_uuid = struct.pack("<II", 0x1B, uuid_size) + uuid
    lc_sig = struct.pack("<IIII", 0x1D, sig_size, sig_off, len(signature))
    return header + segment + section + lc_uuid + lc_sig + text + signature


def fat(*slices: tuple[int, bytes]) -> bytes:
    header = struct.pack(">II", 0xCAFEBABE, len(slices))
    offset = 8 + 20 * len(slices)
    offset = (offset + 0xFFF) & ~0xFFF
    entries, body, cursor = b"", b"", offset
    for cpu, data in slices:
        entries += struct.pack(">iIIII", cpu, 0, cursor, len(data), 12)
        pad = (-len(data)) % 0x1000
        body += data + b"\0" * pad
        cursor += len(data) + pad
    return header + entries + b"\0" * (offset - len(header) - len(entries)) + body


def pe64(text: bytes, timestamp: int = 1, checksum: int = 2) -> bytes:
    """Minimal PE32+: one .text section, a debug directory with a CodeView entry."""
    pe_off, opt_size = 0x40, 240
    sect_table = pe_off + 24 + opt_size
    text_raw = 0x200
    dbg_rva, dbg_raw = 0x1000 + len(text), text_raw + len(text)
    cv_raw = dbg_raw + 28
    cv = b"RSDS" + b"\x42" * 16 + struct.pack("<I", 1) + b"x.pdb\0"
    image = bytearray(cv_raw + len(cv))
    image[0:2] = b"MZ"
    struct.pack_into("<I", image, 0x3C, pe_off)
    image[pe_off:pe_off + 4] = b"PE\0\0"
    struct.pack_into("<HHIIIHH", image, pe_off + 4, 0x8664, 1, timestamp, 0, 0, opt_size, 0x22)
    opt = pe_off + 24
    struct.pack_into("<H", image, opt, 0x20B)
    struct.pack_into("<I", image, opt + 64, checksum)
    struct.pack_into("<I", image, opt + 108, 16)  # NumberOfRvaAndSizes
    struct.pack_into("<II", image, opt + 112 + 8 * 6, dbg_rva, 28)
    struct.pack_into("<8sIIII", image, sect_table, b".text", len(text) + 28 + len(cv), 0x1000,
                     len(text) + 28 + len(cv), text_raw)
    image[text_raw:text_raw + len(text)] = text
    struct.pack_into("<IIHHIIII", image, dbg_raw, 0, timestamp, 0, 0, 2, len(cv), 0, cv_raw)
    image[cv_raw:cv_raw + len(cv)] = cv
    return bytes(image)


TEXT_A = bytes(range(64))
TEXT_B = TEXT_A[:10] + b"\xff" + TEXT_A[11:]


class TestLayout:
    def test_macho_sections_and_volatile_regions(self) -> None:
        layout = parse_layout(macho64(TEXT_A))
        assert (layout.format, layout.architecture) == ("macho", "arm64")
        assert [s.name for s in layout.sections] == ["__TEXT,__text"]
        assert {v.name for v in layout.volatile} == {"LC_UUID", "code signature"}

    def test_fat_selects_the_requested_slice(self) -> None:
        image = fat((0x01000007, macho64(TEXT_B, cpu=0x01000007)), (0x0100000C, macho64(TEXT_A)))
        assert parse_layout(image, prefer_cpu="arm64").architecture == "arm64"
        assert parse_layout(image).architecture == "x86_64"

    def test_pe_volatile_regions(self) -> None:
        layout = parse_layout(pe64(TEXT_A))
        assert layout.format == "pe" and [s.name for s in layout.sections] == [".text"]
        names = {v.name for v in layout.volatile}
        assert {"COFF TimeDateStamp", "optional header CheckSum", "debug[0] TimeDateStamp",
                "debug[0] CodeView"} <= names

    def test_unknown_format_is_one_raw_section(self) -> None:
        layout = parse_layout(b"\x00" * 100)
        assert layout.format == "raw" and layout.sections[0].size == 100


class TestScorecard:
    def test_identical(self) -> None:
        card = score_reconstruction(macho64(TEXT_A), macho64(TEXT_A))
        assert card.verdict == "identical" and card.match_pct == 100.0

    def test_build_noise_is_excluded(self) -> None:
        card = score_reconstruction(macho64(TEXT_A), macho64(TEXT_A, b"\x22" * 16, b"\xbb" * 16))
        assert card.verdict == "identical-except-volatile"
        assert card.overall.excluded_bytes == 32

    def test_pe_timestamps_and_pdb_guid_are_excluded(self) -> None:
        card = score_reconstruction(pe64(TEXT_A, 1, 2), pe64(TEXT_A, 999, 777))
        assert card.verdict == "identical-except-volatile"

    def test_one_byte_change_is_located(self) -> None:
        card = score_reconstruction(macho64(TEXT_A), macho64(TEXT_B))
        assert card.verdict == "near" and card.match_pct < 100.0
        text = next(s for s in card.sections if s.name == "__TEXT,__text")
        assert text.first_difference == 10 and not text.identical

    def test_functions_and_size_changes(self) -> None:
        a, b = macho64(TEXT_A), macho64(TEXT_A + b"\x90" * 8)
        text = parse_layout(a).sections[0]
        card = score_reconstruction(a, b, [FunctionRange("f", text.offset, 16)])
        assert card.functions[0].identical
        assert card.original_size != card.rebuilt_size and card.verdict != "identical"

    def test_completely_different(self) -> None:
        assert score_reconstruction(b"\x00" * 64, b"\xff" * 64).verdict == "different"

    def test_large_inputs_are_fast(self) -> None:
        blob = bytes(range(256)) * 40_000  # ~10 MB
        card = score_reconstruction(blob, blob[:-1] + b"\x01")
        assert card.verdict == "near" and card.match_pct == 99.9999


@pytest.mark.skipif(not shutil.which("cc"), reason="no C compiler on this machine")
def test_real_compiler_builds(tmp_path: Path) -> None:
    """Same source twice must match; a changed constant must be located in code."""
    src = tmp_path / "prog.c"  # one source path: compilers embed the file name in symbols

    def build(name: str, value: int) -> bytes:
        src.write_text(f"int main(void){{return {value};}}\n")
        out = tmp_path / name
        subprocess.run(["cc", "-O2", "-o", str(out), str(src)], check=True, capture_output=True)
        return out.read_bytes()

    first, second, other = build("a1", 42), build("a2", 42), build("b1", 43)
    assert score_reconstruction(first, second).verdict in ("identical", "identical-except-volatile")
    changed = score_reconstruction(first, other)
    assert changed.verdict in ("near", "partial")
    code = [s for s in changed.sections if s.name in (".text", "__TEXT,__text")]
    assert code and not code[0].identical
