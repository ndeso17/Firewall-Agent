#!/system/bin/sh
# Lightweight ONNX self-test for runtime diagnostics.

MODDIR=${0%/*}/..
RUNDIR="$MODDIR/runtime"
TEST_JSON="$RUNDIR/onnx_selftest.json"
TMP_INPUT="$RUNDIR/.onnx_selftest_features.json"
MODEL="$RUNDIR/model.onnx"
CONTRACT="$RUNDIR/config/features_contract.json"
FALLBACK_CONTRACT="$MODDIR/assets/default_features_contract.json"
INFER="$MODDIR/bin/infer_runner.sh"

mkdir -p "$RUNDIR/config"

feature_count=$(sed -n 's/.*"feature_count"[[:space:]]*:[[:space:]]*\([0-9][0-9]*\).*/\1/p' "$CONTRACT" | head -n1)
if [ -z "$feature_count" ] && [ -f "$FALLBACK_CONTRACT" ]; then
  feature_count=$(sed -n 's/.*"feature_count"[[:space:]]*:[[:space:]]*\([0-9][0-9]*\).*/\1/p' "$FALLBACK_CONTRACT" | head -n1)
fi
[ -z "$feature_count" ] && feature_count=117
[ "$feature_count" -lt 1 ] && feature_count=117

i=0
features_csv=""
while [ "$i" -lt "$feature_count" ]; do
  [ -z "$features_csv" ] && features_csv="0" || features_csv="$features_csv,0"
  i=$((i + 1))
done

cat > "$TMP_INPUT" <<EOF
{"version":"v1","uid":"selftest","features":[${features_csv}]}
EOF

out=$(sh "$INFER" "$MODEL" "$TMP_INPUT")
score=$(echo "$out" | sed -n 's/.*"score":[[:space:]]*\([0-9.]*\).*/\1/p' | head -n1)
uid=$(echo "$out" | sed -n 's/.*"uid":[[:space:]]*"\?\([^",}]*\)"\?.*/\1/p' | head -n1)
reason=$(echo "$out" | sed -n 's/.*"reason":[[:space:]]*"\([^"]*\)".*/\1/p' | head -n1)

[ -z "$score" ] && score="0.00"
[ -z "$uid" ] && uid="-"
[ -z "$reason" ] && reason="selftest_parse_error"

status="ok"
case "$reason" in
  native_runner_missing|model_missing|features_missing|python_dep_missing|python_runner_failed|native_inference_error)
    status="degraded"
    ;;
esac

cat > "$TEST_JSON" <<EOF
{"status":"$status","reason":"$reason","score":"$score","uid":"$uid","updated_at":"$(date -u +%Y-%m-%dT%H:%M:%SZ)"}
EOF

rm -f "$TMP_INPUT"
echo "$status:$reason"
