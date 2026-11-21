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
#   scripts/install.sh --runtime-only                          # runtime only, skill untouched
#
# The runtime needs Python 3.11+. The installer picks the first suitable one
# from $PYTHON, python3.13, python3.12, python3.11, python3.
set -euo pipefail

SKILL_NAME="re-super-intelligence"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
SKILL_SRC="$(cd "${SCRIPT_DIR}/.." && pwd)"
REPO_ROOT="$(cd "${SKILL_SRC}/../.." && pwd)"

TARGET="" LINK=0 FORCE=0 DRY=0 WITH_RUNTIME=0 RUNTIME_ONLY=0 VENV="${HOME}/.resi/venv"

usage() { awk 'NR > 1 && /^#/ { sub(/^# ?/, ""); print; next } NR > 1 { exit }' "$0"; exit "${1:-0}"; }
say() { printf '%s\n' "$*"; }

find_python() {
  local candidate
  for candidate in "${PYTHON:-}" python3.13 python3.12 python3.11 python3; do
    [[ -n "$candidate" ]] || continue
    command -v "$candidate" >/dev/null 2>&1 || continue
    if "$candidate" -c 'import sys; sys.exit(0 if sys.version_info >= (3, 11) else 1)' 2>/dev/null; then
      command -v "$candidate"
      return 0
    fi
  done
  return 1
}
run() { if [[ $DRY -eq 1 ]]; then say "[dry-run] $*"; else "$@"; fi; }

while [[ $# -gt 0 ]]; do
  case "$1" in
    --target) TARGET="${2:?--target needs a directory}"; shift 2 ;;
    --link) LINK=1; shift ;;
    --force) FORCE=1; shift ;;
    --dry-run) DRY=1; shift ;;
    --with-runtime) WITH_RUNTIME=1; shift ;;
    --runtime-only) RUNTIME_ONLY=1; WITH_RUNTIME=1; shift ;;
    --venv) VENV="${2:?--venv needs a directory}"; shift 2 ;;
    -h|--help) usage 0 ;;
    *) say "unknown option: $1"; usage 2 ;;
  esac
done

install_skill() {
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
}

if [[ $RUNTIME_ONLY -eq 0 ]]; then
  install_skill
fi

if [[ $WITH_RUNTIME -eq 1 ]]; then
  if ! PY="$(find_python)"; then
    say "error: Python 3.11+ not found (python3 is $(python3 --version 2>&1 || echo missing))."
    say "Install one (macOS: brew install python@3.12; Ubuntu: apt install python3.12-venv)"
    say "or point the installer at it: PYTHON=/path/to/python3.12 $0 ..."
    exit 1
  fi
  say "Using Python      : ${PY} ($("$PY" --version 2>&1))"
  run "$PY" -m venv "$VENV"
  run "$VENV/bin/python" -m pip install --quiet --upgrade pip
  run "$VENV/bin/python" -m pip install --quiet -e "${REPO_ROOT}/orchestrator[vision]"
  if [[ $DRY -eq 1 ]]; then say "Dry run complete: nothing was installed."; else say "Runtime installed: ${VENV}/bin/resi"; fi
  say "Register the MCP server with command \"${VENV}/bin/resi\" and args [\"mcp\"]."
fi

if [[ $RUNTIME_ONLY -eq 0 ]]; then
  say "Next: python3 ${DEST}/scripts/discover_environment.py"
fi
