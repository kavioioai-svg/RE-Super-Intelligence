#!/usr/bin/env bash
# Install the RESI skill into any coding agent's skills folder, and optionally
# the Python runtime into a virtual environment.
#
# Safe by design: never overwrites an existing skill directory (use --force to
# replace it, which first moves the old copy to a timestamped backup), and
# never touches other skills.
#
#   scripts/install.sh --target ~/.agents/skills               # copy the skill
#   scripts/install.sh --target ./.agents/skills --link        # symlink (dev)
#   scripts/install.sh --target ~/.agents/skills --with-runtime --venv ~/.resi/venv
#   scripts/install.sh --target ~/.agents/skills --dry-run
set -euo pipefail

SKILL_NAME="re-super-intelligence"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
SKILL_SRC="$(cd "${SCRIPT_DIR}/.." && pwd)"
REPO_ROOT="$(cd "${SKILL_SRC}/../.." && pwd)"

TARGET="" LINK=0 FORCE=0 DRY=0 WITH_RUNTIME=0 VENV="${HOME}/.resi/venv"

usage() { sed -n '2,13p' "$0" | sed 's/^# \{0,1\}//'; exit "${1:-0}"; }
say() { printf '%s\n' "$*"; }
run() { if [[ $DRY -eq 1 ]]; then say "[dry-run] $*"; else "$@"; fi; }

while [[ $# -gt 0 ]]; do
  case "$1" in
    --target) TARGET="${2:?--target needs a directory}"; shift 2 ;;
    --link) LINK=1; shift ;;
    --force) FORCE=1; shift ;;
    --dry-run) DRY=1; shift ;;
    --with-runtime) WITH_RUNTIME=1; shift ;;
    --venv) VENV="${2:?--venv needs a directory}"; shift 2 ;;
    -h|--help) usage 0 ;;
    *) say "unknown option: $1"; usage 2 ;;
  esac
done

[[ -n "$TARGET" ]] || { say "error: --target is required (your agent's skills folder)"; usage 2; }
TARGET="${TARGET/#\~/$HOME}"
DEST="${TARGET%/}/${SKILL_NAME}"

say "RESI skill source : ${SKILL_SRC}"
say "Install target    : ${DEST}"

run mkdir -p "$TARGET"
if [[ -e "$DEST" || -L "$DEST" ]]; then
  if [[ $FORCE -eq 0 ]]; then
    say "error: ${DEST} already exists. Re-run with --force to replace it (a backup is kept)."
    exit 1
  fi
  BACKUP="${DEST}.backup-$(date +%Y%m%d-%H%M%S)"
  say "Existing install moved to ${BACKUP}"
  run mv "$DEST" "$BACKUP"
fi

if [[ $LINK -eq 1 ]]; then
  run ln -s "$SKILL_SRC" "$DEST"
else
  run cp -R "$SKILL_SRC" "$DEST"
  run find "$DEST" -name '__pycache__' -type d -prune -exec rm -rf {} +
fi
say "Skill installed."

if [[ $WITH_RUNTIME -eq 1 ]]; then
  command -v python3 >/dev/null || { say "error: python3 not found"; exit 1; }
  python3 - <<'PY' || { echo "error: Python 3.11+ required"; exit 1; }
import sys; sys.exit(0 if sys.version_info >= (3, 11) else 1)
PY
  run python3 -m venv "$VENV"
  run "$VENV/bin/python" -m pip install --quiet --upgrade pip
  run "$VENV/bin/python" -m pip install --quiet -e "${REPO_ROOT}/orchestrator[vision]"
  say "Runtime installed: ${VENV}/bin/resi"
  say "Register the MCP server with command \"${VENV}/bin/resi\" and args [\"mcp\"]."
fi

say "Next: python3 ${DEST}/scripts/discover_environment.py"
