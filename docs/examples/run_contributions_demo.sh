#!/usr/bin/env bash
# End-to-end Learning Contributions demo with synthetic data only.
#   bash docs/examples/run_contributions_demo.sh
# Uses RESI's own interpreter (default ~/.resi/venv/bin/python; override with RESI_PY=...).
# Never touches your real RESI state: every user home and the private database live in DEMO_DIR.
set -euo pipefail

RESI_PY="${RESI_PY:-$HOME/.resi/venv/bin/python}"
RESI="$(dirname "$RESI_PY")/resi"
DEMO_DIR="${DEMO_DIR:-/tmp/resi-demo}"
PORT="${PORT:-18443}"
TOKEN="demo-upload-token"
HERE="$(cd "$(dirname "$0")" && pwd)"

[ -x "$RESI_PY" ] || { echo "RESI Python not found at $RESI_PY (set RESI_PY=...)"; exit 1; }
sha256() { if command -v sha256sum >/dev/null; then sha256sum; else shasum -a 256; fi; }

rm -rf "$DEMO_DIR"
mkdir -p "$DEMO_DIR"

echo "== 1. Seed 5 synthetic users"
"$RESI_PY" "$HERE/synthetic_contributions.py" --out "$DEMO_DIR" --users 5 --seed 7

echo "== 2. Preview and export, then compare"
for u in 1 2 3 4 5; do
  "$RESI" --home "$DEMO_DIR/user$u" contribute preview > "$DEMO_DIR/preview$u.json"
  "$RESI" --home "$DEMO_DIR/user$u" contribute export --out "$DEMO_DIR/upload$u.json" 2>/dev/null
  groups=$("$RESI_PY" -c "import json,sys; print(len(json.load(open(sys.argv[1]))['tools']))" \
           "$DEMO_DIR/upload$u.json")
  if cmp -s "$DEMO_DIR/preview$u.json" "$DEMO_DIR/upload$u.json"; then
    echo "user$u: preview == export, $groups tool groups"
  else
    echo "user$u: MISMATCH"; exit 1
  fi
done

echo "== 3. Start the private HTTPS endpoint"
openssl req -x509 -newkey rsa:2048 -nodes -days 1 -subj /CN=localhost \
  -addext subjectAltName=DNS:localhost \
  -keyout "$DEMO_DIR/key.pem" -out "$DEMO_DIR/cert.pem" 2>/dev/null
export RESI_INGEST_DB="$DEMO_DIR/private/contributions.db"
export RESI_INGEST_CERT="$DEMO_DIR/cert.pem" RESI_INGEST_KEY="$DEMO_DIR/key.pem"
export RESI_INGEST_PORT="$PORT"
RESI_INGEST_TOKEN_SHA256="$(printf %s "$TOKEN" | sha256 | cut -d' ' -f1)"
export RESI_INGEST_TOKEN_SHA256
"$RESI" ingest serve > "$DEMO_DIR/server.log" 2>&1 &
SERVER=$!
trap 'kill "$SERVER" 2>/dev/null || true' EXIT
for _ in $(seq 1 50); do
  curl -s --cacert "$DEMO_DIR/cert.pem" "https://localhost:$PORT/v1/health" >/dev/null && break
  sleep 0.2
done

upload() {  # file [token]
  local code
  code=$(curl -s --cacert "$DEMO_DIR/cert.pem" -o "$DEMO_DIR/response.json" -w "%{http_code}" \
    -X POST -H "Authorization: Bearer ${2:-$TOKEN}" -H "Content-Type: application/json" \
    --data-binary @"$1" "https://localhost:$PORT/v1/contributions")
  echo "HTTP $code $(cat "$DEMO_DIR/response.json")"
}

echo "== 4. Uploads"
for u in 1 2 3 4 5; do printf "upload%s: " "$u"; upload "$DEMO_DIR/upload$u.json"; done
printf "retry of upload1: "; upload "$DEMO_DIR/upload1.json"
"$RESI_PY" - "$DEMO_DIR" <<'PY'
import json, sys
d = sys.argv[1]
p = json.load(open(f"{d}/upload2.json"))
p["tools"][0]["successes"] += 1
p["tools"][0]["latency_ms_buckets"]["lt_1s"] += 1
json.dump(p, open(f"{d}/tampered.json", "w"))
q = json.load(open(f"{d}/upload3.json"))
q["hostname"] = "alice-mbp"
json.dump(q, open(f"{d}/extra-field.json", "w"))
PY
printf "same id, different counters: "; upload "$DEMO_DIR/tampered.json"
printf "unknown field: "; upload "$DEMO_DIR/extra-field.json"
printf "wrong token: "; upload "$DEMO_DIR/upload4.json" not-the-token
kill "$SERVER"; wait "$SERVER" 2>/dev/null || true
trap - EXIT

echo "== 5. Server log: method, path and status only"
cat "$DEMO_DIR/server.log"

echo "== 6. Ranking job, run twice"
"$RESI" ingest rank --db "$RESI_INGEST_DB" --out "$DEMO_DIR/ranking.json" >/dev/null
"$RESI" ingest rank --db "$RESI_INGEST_DB" --out "$DEMO_DIR/ranking2.json" >/dev/null
cmp -s "$DEMO_DIR/ranking.json" "$DEMO_DIR/ranking2.json" && echo "deterministic: identical output"
"$RESI" ingest rank --db "$RESI_INGEST_DB" --min-samples 1000 > "$DEMO_DIR/ranking-sparse.json"
"$RESI_PY" - "$DEMO_DIR" <<'PY'
import json, sys
d = sys.argv[1]
for name in ("ranking", "ranking-sparse"):
    r = json.load(open(f"{d}/{name}.json"))
    print(f"-- {name}.json: {r['input']['contributions']} contributions, "
          f"min_samples={r['parameters']['min_samples']}")
    for t in r["tools"]:
        print(f"   {t['tool_id']:22} {t['artifact_kind']:6} trials={t['sample']['trials']:3} "
              f"smoothed={t['smoothed_success_rate']:.3f} status={t['status']:17} rank={t['rank']}")
cal = json.load(open(f"{d}/ranking.json"))["calibration"]
print("-- calibration:", {k: (v["points"], v["upheld_rate"], v["status"])
                         for k, v in cal["levels"].items()}, "brier", cal["brier_score"])
PY
echo "Done. Files are in $DEMO_DIR"
