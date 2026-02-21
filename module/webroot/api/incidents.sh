#!/system/bin/sh
MODDIR=${0%/*}/../..
INCIDENT_DIR="$MODDIR/runtime/incidents"
PENDING_DIR="$MODDIR/runtime/pending_actions"
ESCALATE_DIR="$MODDIR/runtime/escalations"

echo "# Recent incidents"
if [ -d "$INCIDENT_DIR" ]; then
  ls -1t "$INCIDENT_DIR" 2>/dev/null | head -n 40 | while read -r f; do
    [ -n "$f" ] || continue
    cat "$INCIDENT_DIR/$f"
    echo
  done
else
  echo "no incident directory"
fi

echo
echo "# Pending actions"
if [ -d "$PENDING_DIR" ]; then
  ls -1t "$PENDING_DIR" 2>/dev/null | head -n 40 | while read -r f; do
    [ -n "$f" ] || continue
    cat "$PENDING_DIR/$f"
    echo
  done
else
  echo "no pending actions"
fi

echo
echo "# Escalation prompts"
if [ -d "$ESCALATE_DIR" ]; then
  ls -1t "$ESCALATE_DIR" 2>/dev/null | head -n 40
else
  echo "no escalation prompts"
fi
