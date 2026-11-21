"""Research profiles bias routing, evidence requirements and safety rules."""

from __future__ import annotations

from dataclasses import dataclass

from .enums import Confidence, Module
from .errors import UnknownProfile

_MEDICAL_RULES = (
    "No patient data in prompts, logs or memory - synthetic or de-identified data only.",
    "All outputs are research outputs until clinically validated.",
    "Clinical decisions require qualified professional review.",
)


@dataclass(frozen=True, slots=True)
class Profile:
    name: str
    description: str
    modules: tuple[Module, ...]
    min_report_confidence: Confidence
    rules: tuple[str, ...]
    medical: bool = False


PROFILES: dict[str, Profile] = {
    p.name: p
    for p in (
        Profile("general", "General software research",
                (Module.BINARY, Module.WEB, Module.PROTOCOL), Confidence.MEDIUM, ()),
        Profile("firmware", "Firmware and embedded systems research",
                (Module.FIRMWARE, Module.BINARY, Module.PROTOCOL), Confidence.MEDIUM,
                ("Never execute extracted binaries on the host; emulate in isolation only.",)),
        Profile("mobile", "Authorized mobile application research",
                (Module.MOBILE, Module.BINARY, Module.WEB, Module.PROTOCOL), Confidence.MEDIUM,
                ("Use test builds or apps you own; device actions need per-action approval.",)),
        Profile("web-api", "API and web application research",
                (Module.WEB, Module.PROTOCOL), Confidence.MEDIUM,
                ("Respect authentication, rate limits and the named target scope.",)),
        Profile("vision-3d", "3D computer vision and reconstruction research",
                (Module.VISION,), Confidence.MEDIUM,
                ("Prove the pipeline on synthetic data with known ground truth first.",
                 "Report measurement uncertainty with every dimension.")),
        Profile("medical-device", "Medical device research",
                (Module.FIRMWARE, Module.BINARY, Module.PROTOCOL, Module.VISION),
                Confidence.HIGH, _MEDICAL_RULES, medical=True),
    )
}


def get_profile(name: str) -> Profile:
    try:
        return PROFILES[name]
    except KeyError:
        raise UnknownProfile(f"unknown profile {name!r}; choose from {sorted(PROFILES)}") from None
