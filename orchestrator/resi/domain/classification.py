"""Content-based artifact classification and documented-format header parsing.

Pure functions over an ``ArtifactSample``. Classification never trusts the file
extension; every result names the evidence it used so it can be recorded as an
Observed fact.
"""

from __future__ import annotations

import math
import struct
from collections.abc import Callable
from typing import Any

from .enums import Module
from .errors import ClassificationError
from .models import Artifact, ArtifactSample

HIGH_ENTROPY_BITS = 7.5

ELF_MACHINES = {
    0x03: "x86",
    0x08: "mips",
    0x14: "powerpc",
    0x28: "arm",
    0x3E: "x86_64",
    0xB7: "aarch64",
    0xF3: "riscv",
}
ELF_TYPES = {1: "relocatable", 2: "executable", 3: "shared", 4: "core"}
PCAP_MAGICS = {
    b"\xd4\xc3\xb2\xa1": ("<", "microsecond"),
    b"\xa1\xb2\xc3\xd4": (">", "microsecond"),
    b"\x4d\x3c\xb2\xa1": ("<", "nanosecond"),
    b"\xa1\xb2\x3c\x4d": (">", "nanosecond"),
}
MACHO_MAGICS = frozenset(
    {b"\xfe\xed\xfa\xce", b"\xfe\xed\xfa\xcf", b"\xce\xfa\xed\xfe", b"\xcf\xfa\xed\xfe"}
)


def shannon_entropy(data: bytes) -> float:
    """Shannon entropy in bits per byte (0.0 for empty input)."""
    if not data:
        return 0.0
    counts = [0] * 256
    for byte in data:
        counts[byte] += 1
    total = len(data)
    return -sum((c / total) * math.log2(c / total) for c in counts if c)


def parse_elf_header(data: bytes) -> dict[str, Any]:
    """Parse ELF identification and header fields (System V ABI, ELF v1.2)."""
    if len(data) < 52 or data[:4] != b"\x7fELF":
        raise ClassificationError("not an ELF header")
    ei_class, ei_data = data[4], data[5]
    if ei_class not in (1, 2) or ei_data not in (1, 2):
        raise ClassificationError("invalid ELF class or data encoding")
    endian = "<" if ei_data == 1 else ">"
    e_type, e_machine, e_version = struct.unpack_from(endian + "HHI", data, 16)
    if ei_class == 2:
        if len(data) < 64:
            raise ClassificationError("truncated ELF64 header")
        (entry,) = struct.unpack_from(endian + "Q", data, 24)
    else:
        (entry,) = struct.unpack_from(endian + "I", data, 24)
    return {
        "bits": 64 if ei_class == 2 else 32,
        "endianness": "little" if ei_data == 1 else "big",
        "type": ELF_TYPES.get(e_type, f"unknown({e_type})"),
        "machine": ELF_MACHINES.get(e_machine, f"unknown(0x{e_machine:x})"),
        "version": e_version,
        "entry": hex(entry),
    }


def parse_pcap_header(data: bytes) -> dict[str, Any]:
    """Parse the 24-byte libpcap global header."""
    if len(data) < 24:
        raise ClassificationError("truncated pcap header")
    if data[:4] not in PCAP_MAGICS:
        raise ClassificationError("not a libpcap header")
    endian, resolution = PCAP_MAGICS[data[:4]]
    major, minor, _tz, _sigfigs, snaplen, linktype = struct.unpack_from(endian + "HHiIII", data, 4)
    return {
        "format": "pcap",
        "version": f"{major}.{minor}",
        "endianness": "little" if endian == "<" else "big",
        "timestamp_resolution": resolution,
        "snaplen": snaplen,
        "linktype": linktype,
    }


_Result = tuple[str, Module, str]


def _classify_archive(members: tuple[str, ...] | None) -> _Result:
    if members is None:
        return "zip-corrupt", Module.FIRMWARE, "PK magic but unreadable central directory"
    names = set(members)
    if "AndroidManifest.xml" in names:
        return "apk", Module.MOBILE, "ZIP containing AndroidManifest.xml"
    if "base/manifest/AndroidManifest.xml" in names:
        return "aab", Module.MOBILE, "ZIP containing base/manifest/AndroidManifest.xml"
    if any(n.startswith("Payload/") and ".app/" in n for n in names):
        return "ipa", Module.MOBILE, "ZIP containing Payload/*.app"
    if "META-INF/MANIFEST.MF" in names:
        return "jar", Module.MOBILE, "ZIP containing META-INF/MANIFEST.MF"
    return "zip", Module.BINARY, "generic ZIP container - classify members individually"


def _classify_text(head: bytes) -> _Result | None:
    try:
        text = head.decode("utf-8")
    except UnicodeDecodeError:
        return None
    stripped = text.lstrip()
    if stripped.startswith(("ply\n", "ply\r\n")):
        return "ply", Module.VISION, "PLY header"
    if stripped.startswith("solid "):
        return "stl-ascii", Module.VISION, "ASCII STL 'solid' header"
    if stripped.startswith("OFF"):
        return "off-mesh", Module.VISION, "OFF mesh header"
    if "# .PCD" in text[:200] or stripped.startswith("VERSION .7"):
        return "pcd", Module.VISION, "PCD point cloud header"
    if stripped.startswith("{") and '"openapi"' in text[:2000]:
        return "openapi", Module.WEB, "JSON document with an openapi key"
    if any(m in text for m in ("webpackChunk", "__webpack_require__", "require(", "export ")):
        return "javascript", Module.WEB, "JavaScript module markers"
    return "text", Module.PROTOCOL, "UTF-8 text without a known signature"


def _binary_stl(sample: ArtifactSample, details: dict[str, Any]) -> _Result | None:
    if sample.size < 84 or len(sample.head) < 84:
        return None
    (triangles,) = struct.unpack_from("<I", sample.head, 80)
    if 84 + triangles * 50 != sample.size:
        return None
    details["triangles"] = triangles
    return "stl-binary", Module.VISION, "binary STL size matches triangle count"


def _with_parser(
    details: dict[str, Any], parser: Callable[[bytes], dict[str, Any]], head: bytes
) -> None:
    try:
        details.update(parser(head))
    except ClassificationError as exc:
        details["parse_error"] = str(exc)


def classify(sample: ArtifactSample) -> Artifact:
    """Classify an artifact from its leading bytes and (for ZIPs) member names."""
    head = sample.head
    magic = head[:4]
    details: dict[str, Any] = {}

    def build(result: _Result) -> Artifact:
        kind, module, evidence = result
        return Artifact(sample.path, sample.sha256, sample.size, kind, module, evidence, details)

    if magic == b"\x7fELF":
        _with_parser(details, parse_elf_header, head)
        return build(("elf", Module.BINARY, "magic 7F 45 4C 46 at offset 0"))
    if head[:2] == b"MZ":
        if len(head) >= 0x40:
            (pe_offset,) = struct.unpack_from("<I", head, 0x3C)
            if head[pe_offset : pe_offset + 4] == b"PE\x00\x00":
                details["pe_header_offset"] = hex(pe_offset)
                return build(("pe", Module.BINARY, f"MZ at 0 and PE signature at {pe_offset:#x}"))
        return build(("dos-mz", Module.BINARY, "MZ at offset 0 without a PE signature"))
    if magic in MACHO_MAGICS:
        return build(("macho", Module.BINARY, f"Mach-O magic {magic.hex()} at offset 0"))
    if magic == b"\xca\xfe\xba\xbe" and len(head) >= 8:
        (count,) = struct.unpack_from(">I", head, 4)
        if count < 30:  # fat headers hold a small arch count; class files hold a version
            details["fat_arch_count"] = count
            return build(("macho-fat", Module.BINARY, f"CAFEBABE with {count} architectures"))
        return build(("java-class", Module.MOBILE, "CAFEBABE followed by a class-file version"))
    if magic == b"\x00asm":
        return build(("wasm", Module.BINARY, "magic 00 61 73 6D at offset 0"))
    if magic == b"PK\x03\x04":
        return build(_classify_archive(sample.archive_members))
    if magic in PCAP_MAGICS:
        _with_parser(details, parse_pcap_header, head)
        return build(("pcap", Module.PROTOCOL, f"libpcap magic {magic.hex()}"))
    if magic == b"\x0a\x0d\x0d\x0a":
        return build(("pcapng", Module.PROTOCOL, "pcapng section header block 0A0D0D0A"))
    if magic == b"\x27\x05\x19\x56":
        return build(("uimage", Module.FIRMWARE, "U-Boot uImage magic 27051956"))
    if magic in (b"hsqs", b"sqsh"):
        return build(("squashfs", Module.FIRMWARE, "SquashFS superblock magic"))
    if head[:16] == b"SQLite format 3\x00":
        return build(("sqlite", Module.PROTOCOL, "SQLite format 3 header"))
    if head[:2] == b"\x1f\x8b":
        return build(("gzip", Module.FIRMWARE, "gzip magic 1F 8B - extract then re-classify"))
    stl = _binary_stl(sample, details)
    if stl:
        return build(stl)
    text = _classify_text(head)
    if text:
        return build(text)
    entropy = shannon_entropy(head)
    details["head_entropy"] = round(entropy, 3)
    if entropy > HIGH_ENTROPY_BITS:
        return build(
            ("high-entropy-blob", Module.FIRMWARE, f"no magic, entropy {entropy:.2f} bits/byte")
        )
    return build(("unknown-binary", Module.BINARY, "no known magic - run inspect_artifact"))
