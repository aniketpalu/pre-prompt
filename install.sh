#!/usr/bin/env bash
set -euo pipefail

# pre-prompt installer
# Installs the credential scanner as Cursor hooks (user-level or project-level).

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
SRC_DIR="$SCRIPT_DIR/src"

usage() {
    echo "Usage: ./install.sh [--global | --project]"
    echo ""
    echo "  --global   Install to ~/.cursor/ (protects all projects)"
    echo "  --project  Install to .cursor/ in the current directory"
    echo ""
    echo "If no flag is given, defaults to --global."
    exit 1
}

MODE="${1:---global}"

case "$MODE" in
    --global)
        DEST_DIR="$HOME/.cursor/hooks"
        HOOKS_JSON="$HOME/.cursor/hooks.json"
        CMD_PREFIX="./hooks"
        ;;
    --project)
        DEST_DIR=".cursor/hooks"
        HOOKS_JSON=".cursor/hooks.json"
        CMD_PREFIX=".cursor/hooks"
        ;;
    *)
        usage
        ;;
esac

echo "Installing pre-prompt scanner ($MODE)..."

mkdir -p "$DEST_DIR"
cp "$SRC_DIR/patterns.py" "$DEST_DIR/"
cp "$SRC_DIR/scan-secrets.py" "$DEST_DIR/"
cp "$SRC_DIR/scan-file-read.py" "$DEST_DIR/"
chmod +x "$DEST_DIR/scan-secrets.py" "$DEST_DIR/scan-file-read.py"

if [ -f "$HOOKS_JSON" ]; then
    echo ""
    echo "WARNING: $HOOKS_JSON already exists."
    echo "Please merge the following hooks into your existing config:"
    echo ""
    echo "  \"beforeSubmitPrompt\": [{\"command\": \"python3 $CMD_PREFIX/scan-secrets.py\", \"failClosed\": true}]"
    echo "  \"beforeReadFile\":    [{\"command\": \"python3 $CMD_PREFIX/scan-file-read.py\", \"failClosed\": true}]"
    echo "  \"beforeTabFileRead\": [{\"command\": \"python3 $CMD_PREFIX/scan-file-read.py\", \"failClosed\": true}]"
    echo ""
else
    cat > "$HOOKS_JSON" << HOOKEOF
{
  "version": 1,
  "hooks": {
    "beforeSubmitPrompt": [
      {
        "command": "python3 $CMD_PREFIX/scan-secrets.py",
        "failClosed": true
      }
    ],
    "beforeReadFile": [
      {
        "command": "python3 $CMD_PREFIX/scan-file-read.py",
        "failClosed": true
      }
    ],
    "beforeTabFileRead": [
      {
        "command": "python3 $CMD_PREFIX/scan-file-read.py",
        "failClosed": true
      }
    ]
  }
}
HOOKEOF
    echo "Created $HOOKS_JSON"
fi

echo ""
echo "Done. Files installed to $DEST_DIR"
echo "Restart Cursor or run 'Developer: Reload Window' to activate."
