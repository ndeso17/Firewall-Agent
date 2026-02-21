#!/system/bin/sh
MODDIR=${0%/*}/../..
SELFTEST="$MODDIR/bin/selftest_onnx.sh"
TEST_JSON="$MODDIR/runtime/onnx_selftest.json"
MODEL="$MODDIR/runtime/model.onnx"
NATIVE="$MODDIR/bin/native/infer_runner_native"
LIB="$MODDIR/bin/native/lib/libonnxruntime.so"

if [ ! -f "$TEST_JSON" ]; then
  sh "$SELFTEST" >/dev/null 2>&1
fi

echo "{"
if [ -f "$MODEL" ]; then
  echo "  \"model_present\": true,"
else
  echo "  \"model_present\": false,"
fi
if [ -f "$NATIVE" ]; then
  echo "  \"native_present\": true,"
else
  echo "  \"native_present\": false,"
fi
if [ -x "$NATIVE" ]; then
  echo "  \"native_executable\": true,"
else
  echo "  \"native_executable\": false,"
fi
if [ -f "$LIB" ]; then
  echo "  \"native_lib_present\": true,"
else
  echo "  \"native_lib_present\": false,"
fi
if [ -f "$TEST_JSON" ]; then
  echo "  \"selftest\": $(cat "$TEST_JSON")"
else
  echo "  \"selftest\": {\"status\":\"unknown\",\"reason\":\"selftest_unavailable\"}"
fi
echo "}"
