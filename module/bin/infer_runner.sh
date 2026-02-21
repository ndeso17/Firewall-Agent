#!/system/bin/sh
# Wrapper for ONNX inference runner.
# Order:
# 1) Native binary (preferred)
# 2) Python fallback using onnxruntime

MODDIR=${0%/*}/..
NATIVE="$MODDIR/bin/native/infer_runner_native"
PYHELPER="$MODDIR/bin/python_infer.py"
MODEL="$MODDIR/runtime/model.onnx"
FEATURES_JSON="$MODDIR/runtime/features.json"

# Allow override model path for easier testing.
if [ -n "$1" ]; then
  MODEL="$1"
fi
if [ -n "$2" ]; then
  FEATURES_JSON="$2"
fi

if [ ! -f "$MODEL" ]; then
  echo '{"score":0.00,"uid":"-","reason":"model_missing"}'
  exit 0
fi

if [ ! -f "$FEATURES_JSON" ]; then
  echo '{"score":0.00,"uid":"-","reason":"features_missing"}'
  exit 0
fi

if [ -x "$NATIVE" ]; then
  export LD_LIBRARY_PATH="$MODDIR/bin/native/lib:${LD_LIBRARY_PATH}"
  native_out=$("$NATIVE" --model "$MODEL" --input "$FEATURES_JSON" 2>/dev/null)
  native_rc=$?
  if [ "$native_rc" -eq 0 ] && [ -n "$native_out" ]; then
    echo "$native_out"
    exit 0
  fi
elif [ -f "$NATIVE" ]; then
  chmod 0755 "$NATIVE" 2>/dev/null || true
  if [ -x "$NATIVE" ]; then
    export LD_LIBRARY_PATH="$MODDIR/bin/native/lib:${LD_LIBRARY_PATH}"
    native_out=$("$NATIVE" --model "$MODEL" --input "$FEATURES_JSON" 2>/dev/null)
    native_rc=$?
    if [ "$native_rc" -eq 0 ] && [ -n "$native_out" ]; then
      echo "$native_out"
      exit 0
    fi
  fi
fi

PYBIN=""
if command -v python3 >/dev/null 2>&1; then
  PYBIN="python3"
elif [ -x /system/bin/python3 ]; then
  PYBIN="/system/bin/python3"
elif command -v python >/dev/null 2>&1; then
  PYBIN="python"
fi

if [ -n "$PYBIN" ] && [ -f "$PYHELPER" ]; then
  "$PYBIN" "$PYHELPER" --model "$MODEL" --input "$FEATURES_JSON"
  rc=$?
  if [ "$rc" -eq 0 ]; then
    exit 0
  fi
  echo '{"score":0.00,"uid":"-","reason":"python_runner_failed"}'
  exit 0
fi

if [ -f "$NATIVE" ] && [ ! -x "$NATIVE" ]; then
  echo '{"score":0.00,"uid":"-","reason":"native_runner_not_executable"}'
else
  echo '{"score":0.00,"uid":"-","reason":"native_runner_missing"}'
fi
