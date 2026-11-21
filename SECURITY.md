# Security policy

## Reporting a vulnerability

Please **do not** open a public issue for security problems.

Report privately through GitHub: **Security → Report a vulnerability** on this repository. Include:

- what you found and its impact (for example a guardrail bypass, secret leakage, or an agent being able to widen its own permissions);
- steps to reproduce, ideally with a synthetic sample;
- the RESI version (`resi --version`) and your platform.

We aim to acknowledge reports within 5 business days and to agree a disclosure timeline with you.

## Supported versions

| Version | Supported |
|---|---|
| 0.2.x | Yes |
| < 0.2 | No |

## Scope

In scope: the RESI runtime (`orchestrator/`), the skill (`skills/re-super-intelligence/`) and its scripts.

Out of scope: vulnerabilities in third-party tools RESI integrates with but does not ship (REA, Ghidra, Rizin, Frida and others) — report those to their maintainers.

The threat model and the guardrails RESI enforces are documented in [`docs/SECURITY.md`](docs/SECURITY.md).
