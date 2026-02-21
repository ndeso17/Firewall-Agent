#!/system/bin/sh
# Publish runtime state as static JSON for KSUWebUI (no CGI required).

MODDIR=${0%/*}/..
RUNDIR="$MODDIR/runtime"
WDATA="$MODDIR/webroot/data"
STATE="$RUNDIR/state.json"
UPDATE_STATE="$RUNDIR/update_state.json"
SELFTEST="$RUNDIR/onnx_selftest.json"
NATIVE="$MODDIR/bin/native/infer_runner_native"
LIB="$MODDIR/bin/native/lib/libonnxruntime.so"
MODEL="$RUNDIR/model.onnx"
PENDING_DIR="$RUNDIR/pending_actions"
ESCALATE_DIR="$RUNDIR/escalations"

mkdir -p "$WDATA"

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

{
  echo "{"
  if [ -f "$STATE" ]; then
    echo "  \"runtime\": $(cat "$STATE"),"
  else
    echo "  \"runtime\": {\"service\":\"unknown\",\"mode\":\"unknown\",\"updated_at\":\"-\"},"
  fi
  if [ -f "$UPDATE_STATE" ]; then
    echo "  \"updater\": $(cat "$UPDATE_STATE"),"
  else
    echo "  \"updater\": {\"status\":\"idle\",\"message\":\"no_update_state\"},"
  fi
  echo "  \"onnx_backend\": \"$backend\","
  echo "  \"pending_actions\": $pending_count,"
  echo "  \"escalation_prompts\": $escalate_count"
  echo "}"
} > "$WDATA/status.json"

{
  echo "{"
  [ -f "$MODEL" ] && echo "  \"model_present\": true," || echo "  \"model_present\": false,"
  [ -f "$NATIVE" ] && echo "  \"native_present\": true," || echo "  \"native_present\": false,"
  [ -x "$NATIVE" ] && echo "  \"native_executable\": true," || echo "  \"native_executable\": false,"
  [ -f "$LIB" ] && echo "  \"native_lib_present\": true," || echo "  \"native_lib_present\": false,"
  if [ -f "$SELFTEST" ]; then
    echo "  \"selftest\": $(cat "$SELFTEST")"
  else
    echo "  \"selftest\": {\"status\":\"unknown\",\"reason\":\"selftest_unavailable\"}"
  fi
  echo "}"
} > "$WDATA/onnx_health.json"
