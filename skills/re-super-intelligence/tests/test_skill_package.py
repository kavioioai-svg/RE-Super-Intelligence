"""Structural tests for the skill package itself (any coding agent must be able to load it)."""

from __future__ import annotations

import codecs
import json
import re
import subprocess
import sys
from pathlib import Path

import pytest

SKILL = Path(__file__).resolve().parents[1]
SKILL_MD = SKILL / "SKILL.md"
# Vendor names are ROT13-encoded so this guard file itself stays vendor-neutral.
VENDOR_WORDS = re.compile(rf"\b({codecs.decode('pynhqr|naguebcvp|bcranv|pungtcg|trzvav|pbcvybg|phefbe', 'rot13')})\b", re.IGNORECASE)
ROLES = ["research-planner", "binary-analyst", "runtime-analyst", "firmware-analyst",
         "protocol-analyst", "vision-researcher", "evidence-validator", "security-auditor",
         "systems-architect", "technical-reporter"]


def frontmatter() -> dict[str, str]:
    text = SKILL_MD.read_text()
    match = re.match(r"^---\n(.*?)\n---\n", text, re.DOTALL)
    assert match, "SKILL.md must start with YAML frontmatter"
    fields = {}
    for line in match.group(1).splitlines():
        key, _, value = line.partition(":")
        fields[key.strip()] = value.strip()
    return fields


def test_frontmatter_is_valid() -> None:
    fm = frontmatter()
    assert fm["name"] == SKILL.name == "re-super-intelligence"
    assert re.fullmatch(r"[a-z0-9-]{1,64}", fm["name"])
    assert 50 < len(fm["description"]) <= 1024
    assert "<" not in fm["description"] and ">" not in fm["description"]


def test_skill_md_stays_concise() -> None:
    assert len(SKILL_MD.read_text().splitlines()) < 150


def test_every_referenced_file_exists() -> None:
    text = SKILL_MD.read_text()
    for ref in re.findall(r"`((?:references|agents|scripts)/[\w./-]+)`", text):
        assert (SKILL / ref).exists(), f"SKILL.md references missing file {ref}"


@pytest.mark.parametrize("role", ROLES)
def test_every_role_is_defined(role: str) -> None:
    doc = (SKILL / "agents" / f"{role}.md").read_text()
    assert doc.startswith("# ") and "**Mission:**" in doc


def test_package_is_agent_neutral() -> None:
    offenders = []
    for path in SKILL.rglob("*"):
        if path.is_file() and path.suffix in {".md", ".py", ".sh", ".json", ".txt"}:
            for number, line in enumerate(path.read_text().splitlines(), 1):
                if VENDOR_WORDS.search(line):
                    offenders.append(f"{path.relative_to(SKILL)}:{number}")
    assert offenders == [], f"vendor-specific mentions: {offenders}"


def test_examples_are_valid_json() -> None:
    for path in (SKILL / "examples").glob("*.json"):
        json.loads(path.read_text())


def test_discovery_script_runs_read_only() -> None:
    out = subprocess.run([sys.executable, str(SKILL / "scripts" / "discover_environment.py"),
                          "--json"], capture_output=True, text=True, timeout=120, check=True)
    report = json.loads(out.stdout)
    assert {"system", "runtimes", "re_binaries", "python_libraries", "skills", "mcp_servers",
            "risks"} <= set(report)


def test_installer_never_overwrites(tmp_path: Path) -> None:
    script = SKILL / "scripts" / "install.sh"
    first = subprocess.run(["bash", str(script), "--target", str(tmp_path)], capture_output=True,
                           text=True, timeout=60, check=False)
    assert first.returncode == 0, first.stderr
    assert (tmp_path / SKILL.name / "SKILL.md").is_file()
    second = subprocess.run(["bash", str(script), "--target", str(tmp_path)], capture_output=True,
                            text=True, timeout=60, check=False)
    assert second.returncode == 1 and "already exists" in second.stdout
    forced = subprocess.run(["bash", str(script), "--target", str(tmp_path), "--force"],
                            capture_output=True, text=True, timeout=60, check=False)
    assert forced.returncode == 0
    assert list(tmp_path.glob(f"{SKILL.name}.backup-*")), "--force must keep a backup"
