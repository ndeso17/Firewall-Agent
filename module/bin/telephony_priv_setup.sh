#!/system/bin/sh
MODDIR=${0%/*}/..
LOG="$MODDIR/runtime/logs/telephony_priv_setup.log"
PKG="com.mrksvt.firewallagent"
ADAPTER_JSON="$MODDIR/runtime/ims_ril/adapter.json"
TS="$(date -u +%Y-%m-%dT%H:%M:%SZ)"

mkdir -p "$(dirname "$LOG")"

try_cmd() {
  # shellcheck disable=SC2068
  "$@" >> "$LOG" 2>&1 || true
}

get_vendor() {
  if [ -f "$ADAPTER_JSON" ]; then
    sed -n 's/.*"vendor":"\([^"]*\)".*/\1/p' "$ADAPTER_JSON" | head -n 1
    return
  fi
  getprop persist.firewallagent.ims.vendor 2>/dev/null
}

VENDOR="$(get_vendor)"
[ -z "$VENDOR" ] && VENDOR="unknown"

{
  echo "[setup] ts=$TS"
  echo "[setup] vendor=$VENDOR"
  echo "[setup] begin role/dialer/appops setup"
} >> "$LOG"

# Best-effort role setup; OEM ROM may reject service role.
try_cmd cmd role add-role-holder android.app.role.DIALER "$PKG" 0
try_cmd cmd role add-role-holder android.app.role.CALL_SCREENING "$PKG" 0
try_cmd cmd role add-role-holder --user 0 android.app.role.DIALER "$PKG"
try_cmd cmd role add-role-holder --user 0 android.app.role.CALL_SCREENING "$PKG"

# Extra fallback on ROMs where role service is unavailable.
try_cmd settings put secure dialer_default_application "$PKG"
try_cmd settings put secure call_screening_default_component "${PKG}/.FirewallCallScreeningService"
try_cmd settings --user 0 put secure dialer_default_application "$PKG"
try_cmd settings --user 0 put secure call_screening_default_component "${PKG}/.FirewallCallScreeningService"

# Optional telecom shell path (exists on some ROMs).
try_cmd cmd telecom set-default-dialer "$PKG"

# Best-effort appops/permission in case runtime prompt is blocked.
try_cmd appops set "$PKG" READ_CALL_LOG allow
try_cmd appops set "$PKG" READ_PHONE_STATE allow
try_cmd appops set "$PKG" ANSWER_PHONE_CALLS allow
try_cmd appops set "$PKG" CALL_PHONE allow
try_cmd appops set --user 0 "$PKG" READ_CALL_LOG allow
try_cmd appops set --user 0 "$PKG" READ_PHONE_STATE allow
try_cmd appops set --user 0 "$PKG" ANSWER_PHONE_CALLS allow
try_cmd appops set --user 0 "$PKG" CALL_PHONE allow

try_cmd pm grant "$PKG" android.permission.READ_CALL_LOG
try_cmd pm grant "$PKG" android.permission.READ_PHONE_STATE
try_cmd pm grant "$PKG" android.permission.ANSWER_PHONE_CALLS
try_cmd pm grant "$PKG" android.permission.CALL_PHONE

# MTK profile: perform a second pass; some MTK ROMs only stick values after repeated writes.
if [ "$VENDOR" = "mtk" ]; then
  {
    echo "[setup] mtk profile second pass"
  } >> "$LOG"
  try_cmd settings put secure dialer_default_application "$PKG"
  try_cmd settings put secure call_screening_default_component "${PKG}/.FirewallCallScreeningService"
  try_cmd appops set "$PKG" READ_CALL_LOG allow
  try_cmd appops set "$PKG" READ_PHONE_STATE allow
  try_cmd appops set "$PKG" ANSWER_PHONE_CALLS allow
  try_cmd appops set "$PKG" CALL_PHONE allow
fi

{
  echo "[setup] verify"
  echo "dialer_default_application=$(settings get secure dialer_default_application 2>/dev/null)"
  echo "call_screening_default_component=$(settings get secure call_screening_default_component 2>/dev/null)"
  appops get "$PKG" READ_CALL_LOG 2>/dev/null | head -n 1
  appops get "$PKG" READ_PHONE_STATE 2>/dev/null | head -n 1
  appops get "$PKG" ANSWER_PHONE_CALLS 2>/dev/null | head -n 1
  appops get "$PKG" CALL_PHONE 2>/dev/null | head -n 1
  echo "[setup] done"
} >> "$LOG"
