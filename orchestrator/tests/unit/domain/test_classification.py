from __future__ import annotations

import os
import struct

import pytest

from resi.domain.classification import (
    classify,
    parse_elf_header,
    parse_pcap_header,
    shannon_entropy,
)
from resi.domain.enums import Module
from resi.domain.errors import ClassificationError
from resi.domain.models import ArtifactSample
from tests.support import elf_bytes

SHA = "a" * 64


def sample(head: bytes, size: int | None = None, members: tuple[str, ...] | None = None) -> ArtifactSample:
    return ArtifactSample("x", len(head) if size is None else size, SHA, head, members)


class TestDocumentedFormats:
    def test_parses_elf64_aarch64_header(self) -> None:
        info = parse_elf_header(elf_bytes(0xB7, 64))
        assert info == {"bits": 64, "endianness": "little", "type": "executable",
                        "machine": "aarch64", "version": 1, "entry": "0x400080"}

    def test_parses_elf32_arm_header(self) -> None:
        info = parse_elf_header(elf_bytes(0x28, 32))
        assert (info["bits"], info["machine"], info["entry"]) == (32, "arm", "0x8048000")

    @pytest.mark.parametrize("data", [b"", b"\x7fELF", b"MZ" + b"\x00" * 60,
                                      b"\x7fELF" + bytes([9, 9]) + b"\x00" * 60])
    def test_rejects_malformed_elf(self, data: bytes) -> None:
        with pytest.raises(ClassificationError):
            parse_elf_header(data)

    def test_parses_pcap_global_header(self) -> None:
        header = struct.pack("<IHHiIII", 0xA1B2C3D4, 2, 4, 0, 0, 65535, 1)
        assert parse_pcap_header(header) == {
            "format": "pcap", "version": "2.4", "endianness": "little",
            "timestamp_resolution": "microsecond", "snaplen": 65535, "linktype": 1}


class TestClassify:
    def test_elf_includes_parsed_details(self) -> None:
        artifact = classify(sample(elf_bytes()))
        assert (artifact.kind, artifact.module) == ("elf", Module.BINARY)
        assert artifact.details["machine"] == "aarch64"
        assert artifact.artifact_id == f"art-{SHA[:12]}"

    def test_pe_requires_pe_signature(self) -> None:
        head = bytearray(b"MZ" + b"\x00" * 0x7E)
        head[0x3C:0x40] = struct.pack("<I", 0x40)
        head[0x40:0x44] = b"PE\x00\x00"
        assert classify(sample(bytes(head))).kind == "pe"
        assert classify(sample(b"MZ" + b"\x00" * 0x7E)).kind == "dos-mz"

    @pytest.mark.parametrize(("members", "kind", "module"), [
        (("AndroidManifest.xml", "classes.dex"), "apk", Module.MOBILE),
        (("Payload/App.app/Info.plist",), "ipa", Module.MOBILE),
        (("META-INF/MANIFEST.MF", "a/B.class"), "jar", Module.MOBILE),
        (("readme.txt",), "zip", Module.BINARY),
        (None, "zip-corrupt", Module.FIRMWARE),
    ])
    def test_zip_containers_by_content(self, members: tuple[str, ...] | None, kind: str,
                                       module: Module) -> None:
        artifact = classify(sample(b"PK\x03\x04" + b"\x00" * 40, members=members))
        assert (artifact.kind, artifact.module) == (kind, module)

    @pytest.mark.parametrize(("head", "kind"), [
        (b"\xcf\xfa\xed\xfe" + b"\x00" * 28, "macho"),
        (b"\xca\xfe\xba\xbe\x00\x00\x00\x02" + b"\x00" * 24, "macho-fat"),
        (b"\xca\xfe\xba\xbe\x00\x00\x00\x34" + b"\x00" * 24, "java-class"),
        (b"\x00asm\x01\x00\x00\x00", "wasm"),
        (b"\x0a\x0d\x0d\x0a" + b"\x00" * 24, "pcapng"),
        (b"\x27\x05\x19\x56" + b"\x00" * 60, "uimage"),
        (b"hsqs" + b"\x00" * 60, "squashfs"),
        (b"SQLite format 3\x00" + b"\x00" * 84, "sqlite"),
        (b"\x1f\x8b\x08" + b"\x00" * 20, "gzip"),
        (b"ply\nformat ascii 1.0\nelement vertex 3\n", "ply"),
        (b"solid phantom\nfacet normal 0 0 1\n", "stl-ascii"),
        (b"# .PCD v0.7\nVERSION .7\n", "pcd"),
        (b'{"openapi": "3.1.0", "info": {}}', "openapi"),
        (b"(self.webpackChunk=self.webpackChunk||[]).push([[1],{}])", "javascript"),
    ])
    def test_magic_table(self, head: bytes, kind: str) -> None:
        assert classify(sample(head)).kind == kind

    def test_binary_stl_detected_by_size_arithmetic(self) -> None:
        head = b"\x00" * 80 + struct.pack("<I", 2) + b"\x00" * 100
        assert classify(sample(head, size=84 + 2 * 50)).kind == "stl-binary"

    def test_extension_is_never_trusted(self) -> None:
        disguised = ArtifactSample("photo.jpg", 300, SHA, elf_bytes())
        assert classify(disguised).kind == "elf"

    def test_high_entropy_blob_routes_to_firmware(self) -> None:
        artifact = classify(sample(os.urandom(4096)))
        assert (artifact.kind, artifact.module) == ("high-entropy-blob", Module.FIRMWARE)
        assert artifact.details["head_entropy"] > 7.5

    def test_low_entropy_unknown_binary(self) -> None:
        assert classify(sample(b"\x01\x02" * 100 + b"\xff")).kind == "unknown-binary"


def test_entropy_bounds() -> None:
    assert shannon_entropy(b"") == 0.0
    assert shannon_entropy(b"\x00" * 64) == 0.0
    assert shannon_entropy(bytes(range(256))) == pytest.approx(8.0)
