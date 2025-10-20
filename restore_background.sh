#!/usr/bin/env bash
set -e
BACKUP="$1"
if [ -z "$BACKUP" ]; then
  echo "Usage: restore_background.sh <backup-file>"
  exit 1
fi
cp -v "$BACKUP" "menuscript/engine/background.py"
echo "Restored menuscript/engine/background.py from $BACKUP"
