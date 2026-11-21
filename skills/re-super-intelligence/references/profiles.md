# Research profiles

A profile is chosen when a human creates a project (`resi project init --profile <name>`). It biases routing toward the relevant modules, sets the minimum confidence for reporting, and attaches rules to every plan (`resi_plan` returns them in `rules`). Code: `orchestrator/resi/domain/profiles.py`.

| Profile | For | Modules favoured | Report bar | Rules added to every plan |
|---|---|---|---|---|
| `general` | Software research | binary, web, protocol | medium | — |
| `firmware` | Firmware and embedded systems | firmware, binary, protocol | medium | Never execute extracted binaries on the host; emulate in isolation |
| `mobile` | Authorized mobile apps | mobile, binary, web, protocol | medium | Test builds or apps you own; device actions need per-action approval |
| `web-api` | Web applications and APIs | web, protocol | medium | Respect authentication, rate limits and the named scope |
| `vision-3d` | 3D computer vision and reconstruction | vision | medium | Prove the pipeline on synthetic data first; report uncertainty with every dimension |
| `medical-device` | Medical device research | firmware, binary, protocol, vision | **high** | No patient data anywhere; research output until clinically validated; clinical decisions need qualified review |

## What `medical-device` changes beyond rules

- Memory **blocks** text containing personal data instead of quarantining it.
- The Security Auditor raises personal data in claims to a **high** finding (RESI-S004).

## Validation discipline for measurement work (`vision-3d`, `medical-device`)

1. **Synthetic first.** `resi vision-demo --seed N` generates a seeded elliptic-cylinder point cloud with known dimensions and 1 mm noise, recovers the semi-axes with bootstrap uncertainty and reports the error against ground truth. Same seed, same SHA-256 — fully reproducible.
2. **Calibrate** the sensor and record its parameters as evidence.
3. **Physical references** with known dimensions before any real-world data.
4. **Report** every dimension as value ± uncertainty, with the calibration it depends on.
5. **Real-world data** only when authorized; personal data only de-identified.

```text
claim: subject=meas:section-perimeter-z200
       kind=tool_derived, confidence=medium
       observation="ellipse fit at z=200 mm: a=160.0±0.02 mm, b=110.0±0.02 mm"
       interpretation="perimeter 855.6 mm (Ramanujan approximation)"
       limitations="synthetic phantom; real objects are rarely elliptical"
```

## Adding a profile

Add a `Profile` to `PROFILES` (name, description, modules, minimum report confidence, rules, `medical` flag) and a row to this table. Profiles are policy only — no code changes elsewhere are needed.
