#!/system/bin/sh
MODDIR=${0%/*}/..
OUTDIR="$MODDIR/runtime/ims_ril"
LOG="$MODDIR/runtime/logs/ims_ril_probe.log"
TS="$(date -u +%Y%m%dT%H%M%SZ)"

mkdir -p "$OUTDIR"
mkdir -p "$(dirname "$LOG")"

PROP="$OUTDIR/props_$TS.txt"
SVC="$OUTDIR/services_$TS.txt"
HAL="$OUTDIR/hal_$TS.txt"
IMS="$OUTDIR/ims_dump_$TS.txt"

{
  echo "[probe] ts=$TS"
  echo "[probe] collecting getprop (ims/ril/radio/telephony)..."
} >> "$LOG"

(
  getprop | grep -Ei "ims|ril|radio|telephony|volte|wfc|vt" || true
) > "$PROP" 2>&1

(
  service list | grep -Ei "ims|radio|phone|telephony|ril|mtk|qti|vendor" || true
) > "$SVC" 2>&1

(
  lshal | grep -Ei "ims|radio|ril|telephony|mtk|qti|vendor" || true
) > "$HAL" 2>&1

(
  dumpsys telephony.registry
  echo
  dumpsys telecom
  echo
  dumpsys phone
) > "$IMS" 2>&1

{
  echo "[probe] done ts=$TS"
  echo "[probe] files:"
  echo "  $PROP"
  echo "  $SVC"
  echo "  $HAL"
  echo "  $IMS"
} >> "$LOG"
