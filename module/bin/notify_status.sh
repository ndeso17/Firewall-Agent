#!/system/bin/sh
# Post lightweight status notification so user can see firewall is active.

MODDIR=${0%/*}/..
CFG="$MODDIR/config/policy.json"
RUNDIR="$MODDIR/runtime"
STATE="$RUNDIR/state.json"
STAMP="$RUNDIR/.notify_status.last"
LOG="$RUNDIR/logs/notify.log"

mkdir -p "$RUNDIR/logs"
touch "$LOG"

json_str() {
  key="$1"
  file="$2"
  sed -n "s/.*\"$key\"[[:space:]]*:[[:space:]]*\"\([^\"]*\)\".*/\1/p" "$file" | head -n1
}

json_bool() {
  key="$1"
  file="$2"
  sed -n "s/.*\"$key\"[[:space:]]*:[[:space:]]*\(true\|false\).*/\1/p" "$file" | head -n1
}

enabled="true"
if [ -f "$CFG" ]; then
  enabled="$(json_bool ui_enable_notification "$CFG")"
  [ -z "$enabled" ] && enabled="true"
fi

if [ "$enabled" != "true" ]; then
  exit 0
fi

mode="audit"
service="running"
reason="-"
if [ -f "$STATE" ]; then
  mode="$(json_str mode "$STATE")"
  service="$(json_str service "$STATE")"
  reason="$(json_str last_reason "$STATE")"
fi
[ -z "$mode" ] && mode="audit"
[ -z "$service" ] && service="running"
[ -z "$reason" ] && reason="-"

payload="service=$service mode=$mode reason=$reason"
now_epoch=$(date +%s)
last_epoch=0
last_payload=""
if [ -f "$STAMP" ]; then
  last_epoch="$(sed -n '1p' "$STAMP" 2>/dev/null)"
  last_payload="$(sed -n '2p' "$STAMP" 2>/dev/null)"
fi

case "$last_epoch" in
  ''|*[!0-9]*) last_epoch=0 ;;
esac

# Avoid spam if nothing changed within last 15 minutes.
if [ "$payload" = "$last_payload" ] && [ $((now_epoch - last_epoch)) -lt 900 ]; then
  exit 0
fi

{
  echo "$now_epoch"
  echo "$payload"
} > "$STAMP"

title="Firewall Agent Aktif"
msg="Status: $service | Mode: $mode | Last: $reason"

post_ok=0
if command -v cmd >/dev/null 2>&1; then
  cmd notification post -S bigtext -t "$title" "firewall.agent:status" "$msg" >/dev/null 2>&1
  if [ $? -eq 0 ]; then
    post_ok=1
  else
    cmd notification post -t "$title" "firewall.agent:status" "$msg" >/dev/null 2>&1
    [ $? -eq 0 ] && post_ok=1
  fi
fi

if [ "$post_ok" -eq 1 ]; then
  echo "[$(date -u +%Y-%m-%dT%H:%M:%SZ)] status_notification posted: $payload" >> "$LOG"
  exit 0
fi

if command -v termux-notification >/dev/null 2>&1; then
  termux-notification --id "fw_status" --title "$title" --content "$msg" --priority default >/dev/null 2>&1
  if [ $? -eq 0 ]; then
    echo "[$(date -u +%Y-%m-%dT%H:%M:%SZ)] status_notification posted(termux): $payload" >> "$LOG"
    exit 0
  fi
fi

echo "[$(date -u +%Y-%m-%dT%H:%M:%SZ)] status_notification skipped (no backend): $payload" >> "$LOG"
