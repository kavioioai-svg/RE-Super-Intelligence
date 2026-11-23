# Learning contributions

RESI learns from your own runs on your own machine. **Learning contributions** let you choose to share a small file of aggregate counters from that learning, so tool rankings and confidence calibration can improve across many installations. Sharing is opt-in, manual and inspectable: nothing is sent unless you export a file and upload it yourself.

- Users: [what you share](#what-you-share) · [preview and export](#preview-and-export) · [uploading](#uploading-a-contribution)
- Private team: [accepting uploads](#accepting-uploads-private-team) · [ranking job](#the-ranking-job) · [reproducing it locally](#reproducing-the-ranking-job-locally)

## What you share

A contribution is one JSON document, schema `resi.contribution` version 1. Validation uses an explicit field allowlist on both sides: the exporter can only emit these fields, and the ingestion endpoint rejects anything else.

| Field | Meaning |
|---|---|
| `schema`, `schema_version` | `"resi.contribution"`, `1` |
| `contribution_id` | 32 random hex characters, **new for every export**; used only to make uploads idempotent |
| `tools[]` | one row per (tool, version, artifact kind) |
| `tools[].tool_id` | a tool id from RESI's built-in catalogue (for example `rea.list_procedures`, `cli.rizin`). Tools announced by other servers are never included |
| `tools[].tool_version` | the tool's version when RESI knows one (for example `ghidra-12.1.4`); otherwise `unspecified`. Registry stamps such as `discovered-2026-11-21` record *when your installation* saw a tool, so they are reported as `unspecified` |
| `tools[].artifact_kind` | the classifier's coarse kind (`elf`, `macho`, `apk`, …); anything unrecognised becomes `other` |
| `tools[].successes`, `failures` | execution outcomes, using the local learning engine's rules (below) |
| `tools[].latency_ms_buckets` | counts in `lt_1s`, `1s_10s`, `10s_60s`, `ge_60s`; they sum to successes + failures |
| `tools[].validated_claims`, `downgraded_claims` | Evidence Validator outcomes for claims made with that tool |
| `calibration.{low,medium,high}.{upheld,overturned}` | validator outcomes per stated confidence level |

Outcome rules are the same ones local ranking uses: guardrail rejections and other access denials (permission errors, "forbidden", "not authorized") are **not** tool failures; a setup failure (no provider, program not installed, not configured) stops counting once the same tool later succeeds.

**Never shared**, because the schema has no field for them: installation or user ids, paths and filenames, artifact hashes, project or claim ids, project names, prompts, commands and tool arguments, raw tool output, error messages, free text of any kind, and binary contents.

## Preview and export

Both commands are offline: they read your local learning store and write to stdout or a file. Neither opens a network connection, and nothing in analysis, install, startup or updates sends contributions. Agents cannot export on your behalf: the commands exist only in the CLI, not in RESI's MCP server.

```bash
resi contribute preview                          # the exact JSON export would write
resi contribute export --out contribution.json   # write it (refuses to overwrite without --force)
```

`preview` and `export` produce byte-identical text: the next export's id is held in `$RESI_HOME/contribution-pending.json` and deleted after the export, so the following export gets a new id and no id outlives one contribution.

## Uploading a contribution

Uploading is a separate, explicit step: you send the exported file to Kavio's private endpoint with the upload token you were given.

```bash
curl --fail -X POST https://<ingest-host>/v1/contributions \
  -H "Authorization: Bearer $RESI_UPLOAD_TOKEN" -H "Content-Type: application/json" \
  --data-binary @contribution.json
```

`201` means accepted, `200` means the same contribution was already accepted (safe to retry), `409` means the id was reused with different counters, and `400` lists what failed validation.

## Accepting uploads (private team)

The ingestion endpoint runs on Kavio's infrastructure, never on user machines. Configuration and credentials are supplied at deploy time:

| Variable | Purpose |
|---|---|
| `RESI_INGEST_DB` | contributions database (SQLite), separate from any user's RESI state |
| `RESI_INGEST_TOKEN_SHA256` | hex SHA-256 of the upload token; the token itself is never stored |
| `RESI_INGEST_CERT`, `RESI_INGEST_KEY` | TLS certificate chain and key (PEM); there is no plain-HTTP mode |
| `RESI_INGEST_HOST`, `RESI_INGEST_PORT` | bind address (default `127.0.0.1`) and port (default `8443`) |
| `RESI_INGEST_MAX_BYTES` | request size limit, at most the schema limit of 262,144 bytes |

```bash
export RESI_INGEST_TOKEN_SHA256=$(printf %s "$UPLOAD_TOKEN" | sha256sum | cut -d' ' -f1)
resi ingest serve                     # POST /v1/contributions, GET /v1/health
resi ingest accept --db contributions.db file1.json file2.json   # files received another way
```

Every upload is checked in this order: path and method, bearer token (before any body byte is read), content type, declared length against the size limit, then UTF-8 JSON without duplicate keys or non-finite numbers, then the schema: version, allowed fields at every level, built-in tool ids, allowed versions and kinds, counter ranges (0–10,000,000, booleans rejected), latency buckets summing to the trial count, no duplicate groups, at most 2,000 groups. Malformed payloads and unknown fields are rejected with the reasons.

Retries are idempotent: the same contribution id with the same counters returns `200` and is stored once, even if the JSON is formatted differently. The same id with different counters is rejected with `409`.

What is stored: the contribution id, a digest of the counters, the schema version, the UTC acceptance date and the validated payload, re-serialised from the parsed allowlisted fields. Request bodies, tokens and network addresses are not stored, and the server logs only method, path and status. Put a reverse proxy in front only if it is also configured not to log client addresses.

## The ranking job

`resi ingest rank` reads accepted contributions and writes a versioned, data-only JSON artifact (`resi.ranking` version 1) for review. It is deterministic: the output depends only on the set of contributions and the parameters, never on input order or the clock, and it records the input count and a digest of the contribution set. Clients do not download it and RESI does not activate it automatically; both are outside this MVP.

For each (tool, version, artifact kind) group:

| Output | Definition |
|---|---|
| `sample` | trials, successes, failures, number of contributions, claims |
| `raw_success_rate` | successes / trials |
| `smoothed_success_rate`, `smoothed_lower_bound` | mean and mean − 1 sd of Beta(1 + s + m·p, 1 + f + m·(1 − p)), where p is the tool's success rate pooled over all its versions and kinds and m is `prior_strength` (default 10). Small groups are pulled toward their tool's overall rate |
| `claim_yield` | validated / (validated + downgraded) |
| `status`, `use_local_ranking` | `ranked` only with at least `min_samples` trials (default 30) **and** at least `min_contributions` contributions (default 3). Otherwise `insufficient_data` and `use_local_ranking: true`: the group must keep RESI's existing local ranking |
| `rank` | position within its artifact kind among ranked groups, by smoothed lower bound |

Calibration is computed separately, per confidence level: points, upheld rate, stated probability (low 0.35, medium 0.65, high 0.9, the same values the local engine uses), an `overconfident` flag (upheld rate more than 15 points below stated, with at least `min_calibration_points`, default 30), and a pooled Brier score.

### What validator outcomes measure

`upheld` and `overturned` come from the Evidence Validator, not from ground truth, so treat them as a **proxy for correctness**:

- **Upheld**: a claim was corroborated by two or more independent tools, a verified claim (backed by a successful execution and reproduction steps) was confirmed, or a verified claim explicitly settled a hypothesis as supported.
- **Overturned**: a claim was downgraded because its evidence was missing or failed (for example its execution later turned out to have failed, or a verified claim lacked reproduction steps), or a verified claim refuted a hypothesis.

Two tools agreeing is evidence, not proof. Agreement can come from a shared bug, and a downgrade can reflect bookkeeping rather than a wrong conclusion.

## Reproducing the ranking job locally

With synthetic data only. The whole flow (seed users, preview and export, a local HTTPS endpoint with a self-signed certificate, uploads including a retry, a conflicting id, an unknown field and a wrong token, then the ranking job) is one script:

```bash
bash docs/examples/run_contributions_demo.sh
```

It uses RESI's own interpreter (`~/.resi/venv/bin/python`; set `RESI_PY` to use another) and keeps everything in `/tmp/resi-demo`, never in your real RESI state. The individual steps, without the HTTPS part:

```bash
PY=~/.resi/venv/bin/python
$PY docs/examples/synthetic_contributions.py --out /tmp/resi-demo --users 5 --seed 7
for u in 1 2 3 4 5; do resi --home /tmp/resi-demo/user$u contribute export --out /tmp/resi-demo/upload$u.json; done
resi ingest accept --db /tmp/resi-demo/private.db /tmp/resi-demo/upload*.json
resi ingest rank --db /tmp/resi-demo/private.db --out /tmp/resi-demo/ranking.json
resi ingest rank --db /tmp/resi-demo/private.db --min-samples 1000
```

The last command shows sparse data: every group reports `insufficient_data` and `use_local_ranking: true`. Running `rank` twice over the same database produces byte-identical output.

## Tests

`orchestrator/tests/unit/domain/test_contributions.py` covers schema building, outcome rules, allowlisting, version and kind coarsening, validation and ranking maths. `orchestrator/tests/integration/test_contributions_end_to_end.py` covers preview/export equality, fresh ids per export, offline operation with the network blocked, sensitive data never reaching an export, no network code in client modules, no MCP exposure, idempotent retries that cannot double-count, conflicting id reuse, malformed and oversized payloads, HTTP status codes, authentication before body reads, a real TLS round trip, logs without addresses or secrets, and deterministic ranking with sparse data preserving local ranking.
