# Evidence model

Every research claim is a traceable record. Code: `domain/models.py` (`Claim`), rules in `domain/evidence_rules.py`.

## Claim fields

| Field | Meaning |
|---|---|
| `claim_id` | Generated id |
| `project_id`, `artifact_id` | Where it belongs |
| `source_hash` | SHA-256 of the artifact (lowercase hex) |
| `tool_id`, `tool_version` | Tool that produced the evidence (version copied from the execution) |
| `execution_id` | The recorded execution backing the claim |
| `kind` | `observed` · `tool_derived` · `hypothesis` · `verified` |
| `observation` | What the tool literally returned |
| `interpretation` | What it means |
| `confidence` | `low` · `medium` · `high` |
| `verification` | `unverified` · `supported` · `verified` · `rejected` · `downgraded` |
| `reproduction` | Steps to reproduce |
| `limitations` | Known gaps (the validator appends its reasons here) |
| `subject` | Normalised key for corroboration, e.g. `fn@0x4012a0:aes128`, `proto:update-url` |

## The four categories — never mixed

| Kind | Is | Needs |
|---|---|---|
| `observed` | Literal tool output | A successful execution |
| `tool_derived` | A tool's interpretation (decompiler, dissector) | A successful execution |
| `hypothesis` | An inference not yet tested | A falsification condition if tracked as a hypothesis |
| `verified` | Confirmed by an experiment that could have failed | Execution, reproduction steps, confidence ≥ medium |

Reports render each category in its own section, so a hypothesis can never read as fact.

## Rejected at write time

- Empty observation.
- `source_hash` that isn't a lowercase SHA-256.
- `observed` / `tool_derived` / `verified` without a successful execution.
- `verified` without reproduction steps, or with low confidence.
- A `hypothesis` marked `verified` (promote it through an experiment instead).

## Validator pass (`resi_validate_evidence`)

1. Re-checks every claim against the stored executions (evidence can disappear or turn out to be a failed run).
2. **Downgrades** failing claims to `hypothesis` / `downgraded`, appending the reasons to `limitations`. Nothing is deleted.
3. **Promotes** to `supported` any claim whose `subject` is asserted by two or more distinct tools.
4. Marks well-formed `verified` claims as `verified`.
5. Emits one learning signal per state change (calibration point + claim-yield feedback). This keeps re-validation idempotent.
6. Ingests promoted claims into memory as `finding` documents.

## Hypotheses and experiments

`Hypothesis(statement, prediction, falsified_if, status)` · `Experiment(plan, security_class, priority, execution_id, outcome, supports)`.

Status from outcomes: none → `open`; all supporting, one → `supported`; all supporting, two or more → `verified`; any contradiction → `rejected`. An outcome must cite a successful execution.

## Storage

SQLite tables `claims`, `executions`, `hypotheses`, `experiments`, `artifacts`, `projects`, `scopes`, `documents`, `episodes`, `calibration`, each holding a JSON body plus indexed keys. Portable to PostgreSQL `JSONB`.
