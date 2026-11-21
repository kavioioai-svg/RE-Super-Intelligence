# Research methodology

## The loop

```
Recall → Observation → Hypothesis → Experiment plan → Authorized execution
   ▲                                                         │
Lessons ← Learning ← Validation ← Evidence collection ◄──────┘
```

Each pass produces records. Nothing becomes `verified` without an experiment whose result could have come out the other way.

## Role hand-offs

| Step | Role | Output |
|---|---|---|
| Frame questions, pick sequence | research-planner | Research questions, plan from `resi_plan` |
| Run and interpret tools | binary / runtime / firmware / protocol analyst, vision-researcher | Executions + claims |
| Check every claim | evidence-validator | Downgrades, corroborations |
| Check every guardrail held | security-auditor | Audit result |
| Write the clean-room spec | systems-architect | Functional spec, passed `resi_cleanroom_check` |
| Write the report | technical-reporter | `resi_report` + open questions |

## Writing a hypothesis

Falsifiable, and it names what would falsify it.

- Weak: "This function handles encryption."
- Strong: "`sub_4012a0` implements AES-128-CBC. Falsified if the pseudo-code has no S-box constant (0x63 0x7c 0x77 0x7b…) or no 10-round loop, or if runtime output for a known key/IV/plaintext differs from a reference AES."

## Prioritising experiments

```
priority = (information_gain × relevance) / (cost × risk)     each 1–5
```

Risk comes from the security class: R = 1, L = 3, D/M = 5. Static before dynamic, cheap before expensive. Ask for approval for a class D experiment only after static work has narrowed what it must observe. `HypothesisService.ranked_experiments` returns pending experiments in priority order.

## Rejecting your own hypotheses

One contradicting experiment sets the hypothesis to `rejected`. Keep the record and the evidence; do not rewrite the hypothesis to fit. Two independent supporting experiments are needed for `verified`.

## Cross-tool verification

A claim backed by one tool is `tool_derived`. Promote it by:

- a second, independent tool asserting the same `subject` (the validator promotes the pair to `supported`);
- a static prediction matching a runtime observation (`correlate_static_and_runtime`);
- a re-implementation from the spec producing identical outputs on test vectors.

## Clean room

| Research workspace may contain | Implementation workspace receives |
|---|---|
| Decompiled code, disassembly, raw captures | Functional requirements |
| Function names, offsets, call graphs | Input/output contracts |
| Evidence records | Independently verified behaviour |
| | Performance targets and test vectors |
| | Interface specs that may be reused (published protocols, public formats) |

Never copy decompiled code, recovered identifiers or proprietary source into the implementation workspace. The systems-architect writes the spec in its own words, and the spec must pass `resi_cleanroom_check` (exit 3 on leak). REA's `build_reconstruction_obligation_ledger` and `evaluate_reconstruction_coverage` check that the spec covers the observed behaviour.

Clean-room process reduces but does not remove IP risk; rights differ by jurisdiction and licence. This is not legal advice — get counsel before commercial reimplementation.
