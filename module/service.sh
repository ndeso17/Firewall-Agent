#!/system/bin/sh
# Main background loop (safe by default).

MODDIR=${0%/*}
RUNDIR="$MODDIR/runtime"
LOGDIR="$RUNDIR/logs"
CFG="$MODDIR/config/policy.json"
RUNNER="$MODDIR/bin/edge_runner.sh"
UPDATER="$MODDIR/bin/model_updater.sh"
SELFTEST="$MODDIR/bin/selftest_onnx.sh"
PUBLISH="$MODDIR/bin/publish_web_data.sh"
PUBLISH_APPS="$MODDIR/bin/publish_apps.sh"
NOTIFY_STATUS="$MODDIR/bin/notify_status.sh"
IMS_RIL_PROBE="$MODDIR/bin/ims_ril_probe.sh"
IMS_RIL_ADAPTER="$MODDIR/bin/ims_ril_adapter.sh"
TELE_SETUP="$MODDIR/bin/telephony_priv_setup.sh"
tick=0

mkdir -p "$LOGDIR"
touch "$LOGDIR/service.log"

echo "[service] started $(date -u +%Y-%m-%dT%H:%M:%SZ)" >> "$LOGDIR/service.log"
sh "$SELFTEST" >> "$LOGDIR/service.log" 2>&1
sh "$PUBLISH" >> "$LOGDIR/service.log" 2>&1
sh "$PUBLISH_APPS" >> "$LOGDIR/service.log" 2>&1
sh "$NOTIFY_STATUS" >> "$LOGDIR/service.log" 2>&1
sh "$TELE_SETUP" >> "$LOGDIR/service.log" 2>&1
sh "$IMS_RIL_PROBE" >> "$LOGDIR/service.log" 2>&1
sh "$IMS_RIL_ADAPTER" >> "$LOGDIR/service.log" 2>&1

while true; do
  sh "$UPDATER" >> "$LOGDIR/service.log" 2>&1
  sh "$RUNNER" "$CFG" "$RUNDIR" >> "$LOGDIR/service.log" 2>&1
  sh "$PUBLISH" >> "$LOGDIR/service.log" 2>&1
  tick=$((tick + 1))
  if [ $((tick % 12)) -eq 0 ]; then
    sh "$PUBLISH_APPS" >> "$LOGDIR/service.log" 2>&1
  fi
  if [ $((tick % 3)) -eq 0 ]; then
    sh "$NOTIFY_STATUS" >> "$LOGDIR/service.log" 2>&1
  fi
  if [ $((tick % 36)) -eq 0 ]; then
    sh "$IMS_RIL_PROBE" >> "$LOGDIR/service.log" 2>&1
    sh "$IMS_RIL_ADAPTER" >> "$LOGDIR/service.log" 2>&1
  fi

  loop_interval=$(sed -n 's/.*"loop_interval_seconds":[[:space:]]*\([0-9][0-9]*\).*/\1/p' "$CFG" | head -n1)
  [ -z "$loop_interval" ] && loop_interval=10
  if [ "$loop_interval" -lt 5 ]; then
    loop_interval=5
  fi
  if [ "$loop_interval" -gt 300 ]; then
    loop_interval=300
  fi
  sleep "$loop_interval"
done
