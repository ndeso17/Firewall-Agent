#!/system/bin/sh
# Periodic ONNX updater for Magisk/KSU module.

MODDIR=${0%/*}/..
CFG="$MODDIR/config/model_update.json"
RUNDIR="$MODDIR/runtime"
STATE="$RUNDIR/update_state.json"
LOG="$RUNDIR/logs/update.log"
MODEL_DST="$RUNDIR/model.onnx"

mkdir -p "$RUNDIR/logs"
touch "$LOG"

json_get_string() {
  key="$1"
  file="$2"
  sed -n "s/.*\"$key\"[[:space:]]*:[[:space:]]*\"\([^\"]*\)\".*/\1/p" "$file" | head -n1
}

json_get_number() {
  key="$1"
  file="$2"
  sed -n "s/.*\"$key\"[[:space:]]*:[[:space:]]*\([0-9][0-9]*\).*/\1/p" "$file" | head -n1
}

json_get_bool() {
  key="$1"
  file="$2"
  sed -n "s/.*\"$key\"[[:space:]]*:[[:space:]]*\(true\|false\).*/\1/p" "$file" | head -n1
}

download_file() {
  url="$1"
  out="$2"
  if command -v curl >/dev/null 2>&1; then
    curl -LfsS "$url" -o "$out"
    return $?
  fi
  if command -v wget >/dev/null 2>&1; then
    wget -qO "$out" "$url"
    return $?
  fi
  return 127
}

write_state() {
  status="$1"
  msg="$2"
  now_iso="$(date -u +%Y-%m-%dT%H:%M:%SZ)"
  cat > "$STATE" <<EOF
{"status":"$status","message":"$msg","updated_at":"$now_iso","last_check_epoch":$NOW_EPOCH,"last_update_epoch":$LAST_UPDATE_EPOCH}
EOF
}

NOW_EPOCH="$(date +%s)"
LAST_CHECK_EPOCH=0
LAST_UPDATE_EPOCH=0
if [ -f "$STATE" ]; then
  LAST_CHECK_EPOCH="$(json_get_number last_check_epoch "$STATE")"
  LAST_UPDATE_EPOCH="$(json_get_number last_update_epoch "$STATE")"
  [ -z "$LAST_CHECK_EPOCH" ] && LAST_CHECK_EPOCH=0
  [ -z "$LAST_UPDATE_EPOCH" ] && LAST_UPDATE_EPOCH=0
fi

if [ ! -f "$CFG" ]; then
  write_state "idle" "model_update config missing"
  exit 0
fi

AUTO_UPDATE="$(json_get_bool auto_update "$CFG")"
[ -z "$AUTO_UPDATE" ] && AUTO_UPDATE="false"
if [ "$AUTO_UPDATE" != "true" ]; then
  write_state "idle" "auto_update disabled"
  exit 0
fi

INTERVAL_MINUTES="$(json_get_number check_interval_minutes "$CFG")"
[ -z "$INTERVAL_MINUTES" ] && INTERVAL_MINUTES=60
INTERVAL_SECONDS=$((INTERVAL_MINUTES * 60))
NEXT_DUE=$((LAST_CHECK_EPOCH + INTERVAL_SECONDS))
if [ "$NOW_EPOCH" -lt "$NEXT_DUE" ]; then
  write_state "idle" "next check pending"
  exit 0
fi

ONNX_URL="$(json_get_string onnx_url "$CFG")"
MANIFEST_URL="$(json_get_string manifest_url "$CFG")"
TMP_MANIFEST="$RUNDIR/.manifest.tmp.json"
TMP_ONNX="$RUNDIR/.model.tmp.onnx"
EXPECTED_SHA=""

if [ -z "$ONNX_URL" ] && [ -n "$MANIFEST_URL" ]; then
  if ! download_file "$MANIFEST_URL" "$TMP_MANIFEST"; then
    write_state "error" "failed download manifest"
    echo "[update] failed download manifest: $MANIFEST_URL" >> "$LOG"
    exit 0
  fi
  ONNX_URL="$(json_get_string onnx_url "$TMP_MANIFEST")"
  if [ -z "$ONNX_URL" ]; then
    ONNX_URL="$(sed -n 's/.*"url"[[:space:]]*:[[:space:]]*"\([^"]*onnx\)".*/\1/p' "$TMP_MANIFEST" | head -n1)"
  fi
  EXPECTED_SHA="$(json_get_string onnx_sha256 "$TMP_MANIFEST")"
  [ -z "$EXPECTED_SHA" ] && EXPECTED_SHA="$(sed -n 's/.*"sha256"[[:space:]]*:[[:space:]]*"\([a-fA-F0-9]\{64\}\)".*/\1/p' "$TMP_MANIFEST" | head -n1)"
fi

if [ -z "$ONNX_URL" ]; then
  write_state "error" "no onnx_url configured"
  echo "[update] no onnx source configured" >> "$LOG"
  exit 0
fi

if ! download_file "$ONNX_URL" "$TMP_ONNX"; then
  write_state "error" "failed download onnx"
  echo "[update] failed download onnx: $ONNX_URL" >> "$LOG"
  exit 0
fi

SIZE="$(wc -c < "$TMP_ONNX" | tr -d ' ')"
if [ -z "$SIZE" ] || [ "$SIZE" -le 0 ]; then
  write_state "error" "downloaded onnx empty"
  echo "[update] downloaded onnx empty" >> "$LOG"
  rm -f "$TMP_ONNX"
  exit 0
fi

if [ -n "$EXPECTED_SHA" ] && command -v sha256sum >/dev/null 2>&1; then
  ACTUAL_SHA="$(sha256sum "$TMP_ONNX" | awk '{print $1}')"
  if [ "$ACTUAL_SHA" != "$EXPECTED_SHA" ]; then
    write_state "error" "onnx checksum mismatch"
    echo "[update] checksum mismatch expected=$EXPECTED_SHA actual=$ACTUAL_SHA" >> "$LOG"
    rm -f "$TMP_ONNX"
    exit 0
  fi
fi

mv "$TMP_ONNX" "$MODEL_DST"
LAST_UPDATE_EPOCH="$NOW_EPOCH"
write_state "ok" "model updated"
cat > "$STATE" <<EOF
{"status":"ok","message":"model updated","updated_at":"$(date -u +%Y-%m-%dT%H:%M:%SZ)","last_check_epoch":$NOW_EPOCH,"last_update_epoch":$LAST_UPDATE_EPOCH}
EOF
echo "[update] model updated from $ONNX_URL size=$SIZE" >> "$LOG"

