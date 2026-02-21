#!/system/bin/sh
MODDIR=${0%/*}/../..
STATE="$MODDIR/runtime/state.json"
UPDATE_STATE="$MODDIR/runtime/update_state.json"
PENDING_DIR="$MODDIR/runtime/pending_actions"
ESCALATE_DIR="$MODDIR/runtime/escalations"
NATIVE="$MODDIR/bin/native/infer_runner_native"

pending_count=0
escalate_count=0
backend="none"

[ -d "$PENDING_DIR" ] && pending_count=$(ls -1 "$PENDING_DIR" 2>/dev/null | wc -l | tr -d ' ')
[ -d "$ESCALATE_DIR" ] && escalate_count=$(ls -1 "$ESCALATE_DIR" 2>/dev/null | wc -l | tr -d ' ')

if [ -x "$NATIVE" ]; then
  backend="native"
elif command -v python3 >/dev/null 2>&1; then
  backend="python_fallback"
fi

if [ -f "$STATE" ]; then
  if [ -f "$UPDATE_STATE" ]; then
    echo "{"
    echo "  \"runtime\": $(cat "$STATE"),"
    echo "  \"updater\": $(cat "$UPDATE_STATE"),"
    echo "  \"onnx_backend\": \"$backend\","
    echo "  \"pending_actions\": $pending_count,"
    echo "  \"escalation_prompts\": $escalate_count"
    echo "}"
  else
    echo "{"
    echo "  \"runtime\": $(cat "$STATE"),"
    echo "  \"onnx_backend\": \"$backend\","
    echo "  \"pending_actions\": $pending_count,"
    echo "  \"escalation_prompts\": $escalate_count"
    echo "}"
  fi
else
  echo '{"service":"unknown","mode":"unknown","updated_at":"-"}'
fi
