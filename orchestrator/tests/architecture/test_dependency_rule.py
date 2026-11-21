"""Enforce the hexagonal dependency rule mechanically.

    domain       -> stdlib + domain only (no third-party, no I/O layers)
    application  -> domain + application (never adapters or bootstrap)
    outbound     -> domain + application ports (never inbound or bootstrap)
    inbound      -> anything except other inbound-incompatible internals
    bootstrap    -> the only module allowed to import outbound adapters for wiring
"""

from __future__ import annotations

import ast
import sys
from pathlib import Path

import pytest

PACKAGE_ROOT = Path(__file__).resolve().parents[2] / "resi"
STDLIB = set(sys.stdlib_module_names) | {"__future__"}


def module_name(path: Path) -> str:
    relative = path.relative_to(PACKAGE_ROOT.parent).with_suffix("")
    parts = list(relative.parts)
    if parts[-1] == "__init__":
        parts.pop()
    return ".".join(parts)


def imports_of(path: Path) -> set[str]:
    tree = ast.parse(path.read_text(), filename=str(path))
    package = module_name(path).rsplit(".", 0 if path.name == "__init__.py" else 1)[0]
    found: set[str] = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            found.update(alias.name for alias in node.names)
        elif isinstance(node, ast.ImportFrom):
            if node.level:
                base = package.split(".")
                base = base[: len(base) - (node.level - 1)]
                found.add(".".join([*base, node.module] if node.module else base))
            elif node.module:
                found.add(node.module)
    return found


SOURCES = sorted(PACKAGE_ROOT.rglob("*.py"))


def layer(module: str) -> str:
    for prefix in ("resi.domain", "resi.application", "resi.adapters.outbound",
                   "resi.adapters.inbound", "resi.bootstrap"):
        if module == prefix or module.startswith(prefix + "."):
            return prefix
    return "resi"


FORBIDDEN = {
    "resi.domain": ("resi.application", "resi.adapters", "resi.bootstrap"),
    "resi.application": ("resi.adapters", "resi.bootstrap"),
    "resi.adapters.outbound": ("resi.adapters.inbound", "resi.bootstrap"),
}


@pytest.mark.parametrize("path", SOURCES, ids=lambda p: module_name(p))
def test_layer_boundaries(path: Path) -> None:
    mod = module_name(path)
    banned = FORBIDDEN.get(layer(mod), ())
    violations = sorted(i for i in imports_of(path) if i.startswith(banned))
    assert not violations, f"{mod} must not import {violations}"


@pytest.mark.parametrize("path", [p for p in SOURCES if layer(module_name(p)) == "resi.domain"],
                         ids=lambda p: module_name(p))
def test_domain_is_pure_python(path: Path) -> None:
    third_party = sorted(i for i in imports_of(path)
                         if not i.startswith("resi") and i.split(".")[0] not in STDLIB)
    assert not third_party, f"domain module imports third-party code: {third_party}"


@pytest.mark.parametrize("path", [p for p in SOURCES if layer(module_name(p)) == "resi.domain"],
                         ids=lambda p: module_name(p))
def test_domain_does_no_io(path: Path) -> None:
    banned = {"os", "sqlite3", "subprocess", "socket", "shutil", "pathlib", "urllib", "http"}
    used = {i.split(".")[0] for i in imports_of(path)} & banned
    assert not used, f"domain module performs I/O via {sorted(used)}"


def test_only_composition_root_and_inbound_import_bootstrap() -> None:
    offenders = [module_name(p) for p in SOURCES
                 if "resi.bootstrap" in imports_of(p)
                 and layer(module_name(p)) not in ("resi.adapters.inbound", "resi.bootstrap")]
    assert offenders == []
