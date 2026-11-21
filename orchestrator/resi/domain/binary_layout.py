"""Pure section-table parsing for Mach-O (thin and fat), ELF and PE images.

Produces file-offset ranges for every section that occupies bytes on disk, plus
the *volatile* regions a build legitimately changes on every link (build ids,
UUIDs, timestamps, signatures, checksums). Reconstruction scoring excludes
volatile regions so "identical apart from build noise" can be measured.
"""

from __future__ import annotations

import struct
from dataclasses import dataclass

from .errors import ClassificationError

MACHO_64_LE = b"\xcf\xfa\xed\xfe"
MACHO_32_LE = b"\xce\xfa\xed\xfe"
FAT_MAGIC = b"\xca\xfe\xba\xbe"
LC_SEGMENT = 0x1
LC_SEGMENT_64 = 0x19
LC_UUID = 0x1B
LC_CODE_SIGNATURE = 0x1D
ZEROFILL_TYPES = frozenset({0x1, 0xC, 0x12})
SHT_NOBITS = 8
ELF_VOLATILE_SECTIONS = {".note.gnu.build-id": "GNU build id", ".gnu_debuglink": "debug link CRC"}
PE_CERTIFICATE_DIRECTORY = 4
PE_DEBUG_DIRECTORY = 6
PE_DEBUG_CODEVIEW = 2


@dataclass(frozen=True, slots=True)
class Section:
    name: str
    offset: int
    size: int

    @property
    def end(self) -> int:
        return self.offset + self.size


@dataclass(frozen=True, slots=True)
class VolatileRegion:
    name: str
    offset: int
    size: int
    reason: str

    @property
    def end(self) -> int:
        return self.offset + self.size


@dataclass(frozen=True, slots=True)
class BinaryLayout:
    format: str  # macho | elf | pe | raw
    architecture: str
    sections: tuple[Section, ...]
    volatile: tuple[VolatileRegion, ...]


def _cstr(raw: bytes) -> str:
    return raw.split(b"\0", 1)[0].decode("ascii", errors="replace")


def _need(data: bytes, end: int, what: str) -> None:
    if end > len(data):
        raise ClassificationError(f"truncated {what}")


# --- Mach-O --------------------------------------------------------------------

_MACHO_CPUS = {7: "x86", 0x01000007: "x86_64", 12: "arm", 0x0100000C: "arm64"}


def _parse_macho(data: bytes, base: int = 0) -> BinaryLayout:
    magic = data[base:base + 4]
    is64 = magic == MACHO_64_LE
    header_size = 32 if is64 else 28
    _need(data, base + header_size, "Mach-O header")
    cputype, _sub, _ftype, ncmds, _sizeofcmds = struct.unpack_from("<iIIII", data, base + 4)
    sections: list[Section] = []
    volatile: list[VolatileRegion] = []
    cursor = base + header_size
    for _ in range(ncmds):
        _need(data, cursor + 8, "load command")
        cmd, cmdsize = struct.unpack_from("<II", data, cursor)
        if cmdsize < 8:
            raise ClassificationError("malformed Mach-O load command size")
        _need(data, cursor + cmdsize, "load command body")
        if cmd in (LC_SEGMENT_64, LC_SEGMENT):
            seg64 = cmd == LC_SEGMENT_64
            nsects = struct.unpack_from("<I", data, cursor + (64 if seg64 else 48))[0]
            sect = cursor + (72 if seg64 else 56)
            for _s in range(nsects):
                name = _cstr(data[sect:sect + 16])
                segname = _cstr(data[sect + 16:sect + 32])
                if seg64:
                    size = struct.unpack_from("<Q", data, sect + 40)[0]
                    offset, _align, _reloff, _nreloc, flags = struct.unpack_from("<IIIII", data, sect + 48)
                else:
                    size = struct.unpack_from("<I", data, sect + 36)[0]
                    offset, _align, _reloff, _nreloc, flags = struct.unpack_from("<IIIII", data, sect + 40)
                if offset and size and (flags & 0xFF) not in ZEROFILL_TYPES:
                    sections.append(Section(f"{segname},{name}", base + offset, size))
                sect += 80 if seg64 else 68
        elif cmd == LC_UUID:
            volatile.append(VolatileRegion("LC_UUID", cursor + 8, 16, "per-link UUID"))
        elif cmd == LC_CODE_SIGNATURE:
            dataoff, datasize = struct.unpack_from("<II", data, cursor + 8)
            volatile.append(VolatileRegion("code signature", base + dataoff, datasize,
                                           "signature covers build-specific hashes"))
        cursor += cmdsize
    return BinaryLayout("macho", _MACHO_CPUS.get(cputype, f"cpu({cputype:#x})"),
                        tuple(sections), tuple(volatile))


def _fat_slices(data: bytes) -> list[tuple[int, int, int]]:
    _need(data, 8, "fat header")
    (count,) = struct.unpack_from(">I", data, 4)
    slices = []
    for i in range(count):
        entry = 8 + i * 20
        _need(data, entry + 20, "fat arch entry")
        cputype, _sub, offset, size, _align = struct.unpack_from(">iIIII", data, entry)
        slices.append((cputype, offset, size))
    return slices


# --- ELF -----------------------------------------------------------------------

_ELF_MACHINES = {0x03: "x86", 0x28: "arm", 0x3E: "x86_64", 0xB7: "aarch64", 0xF3: "riscv"}


def _parse_elf(data: bytes) -> BinaryLayout:
    _need(data, 52, "ELF header")
    is64, little = data[4] == 2, data[5] == 1
    e = "<" if little else ">"
    machine = struct.unpack_from(e + "H", data, 18)[0]
    if is64:
        _need(data, 64, "ELF64 header")
        shoff = struct.unpack_from(e + "Q", data, 40)[0]
        shentsize, shnum, shstrndx = struct.unpack_from(e + "HHH", data, 58)
    else:
        shoff = struct.unpack_from(e + "I", data, 32)[0]
        shentsize, shnum, shstrndx = struct.unpack_from(e + "HHH", data, 46)
    raw: list[tuple[int, int, int, int]] = []  # name_off, type, offset, size
    for i in range(shnum):
        hdr = shoff + i * shentsize
        _need(data, hdr + shentsize, "ELF section header")
        if is64:
            name, stype = struct.unpack_from(e + "II", data, hdr)
            offset, size = struct.unpack_from(e + "QQ", data, hdr + 24)
        else:
            name, stype = struct.unpack_from(e + "II", data, hdr)
            offset, size = struct.unpack_from(e + "II", data, hdr + 16)
        raw.append((name, stype, offset, size))
    strtab = raw[shstrndx] if 0 <= shstrndx < len(raw) else None
    sections: list[Section] = []
    volatile: list[VolatileRegion] = []
    for name_off, stype, offset, size in raw:
        if stype == SHT_NOBITS or size == 0 or offset == 0:
            continue
        name = ""
        if strtab is not None:
            start = strtab[2] + name_off
            name = _cstr(data[start:start + 256])
        sections.append(Section(name or f"section@{offset:#x}", offset, size))
        if name in ELF_VOLATILE_SECTIONS:
            volatile.append(VolatileRegion(name, offset, size, ELF_VOLATILE_SECTIONS[name]))
    return BinaryLayout("elf", _ELF_MACHINES.get(machine, f"machine({machine:#x})"),
                        tuple(sections), tuple(volatile))


# --- PE ------------------------------------------------------------------------

_PE_MACHINES = {0x14C: "x86", 0x8664: "x86_64", 0xAA64: "arm64", 0x1C4: "arm"}


def _parse_pe(data: bytes) -> BinaryLayout:
    _need(data, 0x40, "DOS header")
    pe = struct.unpack_from("<I", data, 0x3C)[0]
    _need(data, pe + 24, "COFF header")
    machine, nsections, _ts = struct.unpack_from("<HHI", data, pe + 4)
    opt_size = struct.unpack_from("<H", data, pe + 20)[0]
    opt = pe + 24
    _need(data, opt + opt_size, "optional header")
    volatile = [VolatileRegion("COFF TimeDateStamp", pe + 8, 4, "link timestamp")]
    magic = struct.unpack_from("<H", data, opt)[0]
    plus = magic == 0x20B
    volatile.append(VolatileRegion("optional header CheckSum", opt + 64, 4, "image checksum"))
    dirs = opt + (112 if plus else 96)
    ndirs = struct.unpack_from("<I", data, dirs - 4)[0]
    table = opt + opt_size
    sections: list[Section] = []
    rva_map: list[tuple[int, int, int]] = []  # va, vsize, raw pointer
    for i in range(nsections):
        sh = table + i * 40
        _need(data, sh + 40, "PE section header")
        name = _cstr(data[sh:sh + 8])
        vsize, va, raw_size, raw_ptr = struct.unpack_from("<IIII", data, sh + 8)
        if raw_size and raw_ptr:
            sections.append(Section(name, raw_ptr, raw_size))
        rva_map.append((va, max(vsize, raw_size), raw_ptr))

    def rva_to_offset(rva: int) -> int | None:
        for va, size, ptr in rva_map:
            if va <= rva < va + size:
                return ptr + (rva - va)
        return None

    if ndirs > PE_CERTIFICATE_DIRECTORY:
        cert_off, cert_size = struct.unpack_from("<II", data, dirs + 8 * PE_CERTIFICATE_DIRECTORY)
        if cert_off and cert_size:  # this directory holds a file offset, not an RVA
            volatile.append(VolatileRegion("Authenticode certificate", cert_off, cert_size,
                                           "signature"))
    if ndirs > PE_DEBUG_DIRECTORY:
        dbg_rva, dbg_size = struct.unpack_from("<II", data, dirs + 8 * PE_DEBUG_DIRECTORY)
        dbg_off = rva_to_offset(dbg_rva) if dbg_rva else None
        if dbg_off is not None:
            for j in range(dbg_size // 28):
                entry = dbg_off + j * 28
                if entry + 28 > len(data):
                    break
                volatile.append(VolatileRegion(f"debug[{j}] TimeDateStamp", entry + 4, 4,
                                               "debug timestamp"))
                dtype, dsize, _rva, dptr = struct.unpack_from("<IIII", data, entry + 12)
                if dtype == PE_DEBUG_CODEVIEW and dptr and dsize:
                    volatile.append(VolatileRegion(f"debug[{j}] CodeView", dptr, dsize,
                                                   "PDB GUID, age and path"))
    return BinaryLayout("pe", _PE_MACHINES.get(machine, f"machine({machine:#x})"),
                        tuple(sections), tuple(volatile))


# --- entry point ---------------------------------------------------------------


def parse_layout(data: bytes, prefer_cpu: str | None = None) -> BinaryLayout:
    """Parse a binary's on-disk layout. Unknown formats yield a single raw section.

    For fat Mach-O files the slice matching ``prefer_cpu`` is used (first slice
    otherwise); offsets stay absolute within the fat file.
    """
    magic = data[:4]
    if magic in (MACHO_64_LE, MACHO_32_LE):
        return _parse_macho(data)
    if magic == FAT_MAGIC and len(data) >= 8 and struct.unpack_from(">I", data, 4)[0] < 30:
        slices = _fat_slices(data)
        if not slices:
            raise ClassificationError("fat Mach-O without slices")
        chosen = slices[0]
        for cputype, offset, size in slices:
            if _MACHO_CPUS.get(cputype) == prefer_cpu:
                chosen = (cputype, offset, size)
                break
        layout = _parse_macho(data, base=chosen[1])
        return BinaryLayout("macho-fat", layout.architecture, layout.sections, layout.volatile)
    if magic == b"\x7fELF":
        return _parse_elf(data)
    if data[:2] == b"MZ" and len(data) >= 0x40:
        pe = struct.unpack_from("<I", data, 0x3C)[0]
        if data[pe:pe + 4] == b"PE\0\0":
            return _parse_pe(data)
    return BinaryLayout("raw", "unknown", (Section("<whole file>", 0, len(data)),), ())
