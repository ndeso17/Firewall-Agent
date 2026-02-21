#!/system/bin/sh
MODDIR=${0%/*}/..
RUNDIR="$MODDIR/runtime"
INDIR="$RUNDIR/ims_ril"
OUT="$INDIR/adapter.json"
LOG="$RUNDIR/logs/ims_ril_adapter.log"
TS="$(date -u +%Y-%m-%dT%H:%M:%SZ)"

mkdir -p "$INDIR"
mkdir -p "$(dirname "$LOG")"

LATEST_PROPS="$(ls -1t "$INDIR"/props_*.txt 2>/dev/null | head -n 1)"
LATEST_SVC="$(ls -1t "$INDIR"/services_*.txt 2>/dev/null | head -n 1)"
LATEST_HAL="$(ls -1t "$INDIR"/hal_*.txt 2>/dev/null | head -n 1)"

vendor="unknown"
signals=""

if [ -n "$LATEST_PROPS" ]; then
  if grep -Eqi "mtk|mediatek" "$LATEST_PROPS"; then
    vendor="mtk"
  elif grep -Eqi "qcom|qti|qualcomm" "$LATEST_PROPS"; then
    vendor="qti"
  elif grep -Eqi "unisoc|sprd" "$LATEST_PROPS"; then
    vendor="unisoc"
  fi
fi

if [ "$vendor" = "unknown" ] && [ -n "$LATEST_SVC" ]; then
  if grep -Eqi "mtk|mediatek|ims.*mtk" "$LATEST_SVC"; then
    vendor="mtk"
  elif grep -Eqi "qti|qcril|qualcomm" "$LATEST_SVC"; then
    vendor="qti"
  elif grep -Eqi "unisoc|sprd" "$LATEST_SVC"; then
    vendor="unisoc"
  fi
fi

if [ -n "$LATEST_HAL" ]; then
  signals="$(grep -Ei "ims|radio|ril|telephony" "$LATEST_HAL" | head -n 20 | sed 's/"/\\"/g')"
fi

cat > "$OUT" <<EOF
{
  "updated_at":"$TS",
  "vendor":"$vendor",
  "props_file":"${LATEST_PROPS:-}",
  "services_file":"${LATEST_SVC:-}",
  "hal_file":"${LATEST_HAL:-}"
}
EOF

{
  echo "[adapter] ts=$TS vendor=$vendor"
  echo "[adapter] out=$OUT"
  [ -n "$signals" ] && echo "[adapter] sample_hal_signals: $signals"
} >> "$LOG"

# Best-effort vendor tune profile flag for downstream scripts.
setprop persist.firewallagent.ims.vendor "$vendor" >/dev/null 2>&1 || true
