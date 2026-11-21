# Learning engine

Agent-facing guide: [`references/learning-and-memory.md`](../skills/re-super-intelligence/references/learning-and-memory.md). This page covers the model, the data flow and how to evaluate it.

## Data flow

```
execution ──► Episode(kind=execution, success, latency, failure_reason)
validator ──► Episode(kind=claim_feedback, validated|downgraded) + CalibrationPoint
                         │
          aggregate() ───┼──► ToolStats per (tool, artifact kind) ──► plan re-ranking, demotion
          calibrate() ───┼──► accuracy per confidence level, Brier score, overconfidence
   extract_lessons() ────┴──► Lesson ──► memory (kind=lesson) ──► recalled next engagement
```

## Models

**Tool-outcome bandit.** Beta(1, 1) prior; posterior Beta(1 + s, 1 + f) over execution episodes only — guardrail rejections and claim feedback are excluded from trials.

| Quantity | Formula |
|---|---|
| Posterior mean | α / (α + β) |
| Lower bound (exploit) | max(0, mean − sd) |
| Thompson sample (explore) | draw from Beta(α, β), seeded |
| Claim yield | validated / (validated + downgraded), 0.5 when unknown |
| Utility | reliability × (0.5 + yield) ÷ (1 + ln(1 + latency_ms/1000)) |
| Demoted | trials ≥ 5 and mean < 0.25 |

Without history for an artifact kind, statistics pool across kinds. Plans keep the anchor step first and only reorder the rest.

**Calibration.** Stated probabilities: low 0.35, medium 0.65, high 0.9. Brier score = mean of (stated − outcome)². A level is overconfident with ≥ 10 points and accuracy more than 15 points below its stated probability.

**Lessons.** Per tool, from execution episodes: timeouts ≥ 30 % of calls with ≥ 3 failures; ≥ 3 guardrail rejections. Keyed and idempotent.

## Why not a neural model

The data is small (tens to thousands of episodes per tool), the decisions must be explainable to a reviewer, and the results must reproduce. A Bayesian bandit fits all three. The ports leave room for richer models later: an `Embedder` adapter for neural embeddings, or a new learner behind the same `EpisodeRepository`.

## Evaluating it

```bash
resi learn                      # tool insights, calibration, guidance
resi learn --context elf        # one artifact kind
resi learn --refresh-lessons    # write lessons to memory
```

Healthy signs: demoted tools match ones you know are flaky in your setup; Brier score falls over time; recalled lessons change plans. Unit tests cover posterior maths, demotion thresholds, seeded exploration, rejection exclusion, calibration and lesson extraction (`tests/unit/domain/test_learning_retrieval_rules.py`, `tests/unit/application/test_evidence_knowledge_learning.py`).

## Resetting

Learning lives in the `episodes` and `calibration` tables. Back up `resi.db`, then delete rows from those tables to start fresh; lessons can be removed from `documents` where `kind='lesson'`.
