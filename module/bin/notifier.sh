#!/system/bin/sh
# Notification helper for audit/safe/enforce events.

MODDIR=${0%/*}/..
RUNDIR="$MODDIR/runtime"
LOG="$RUNDIR/logs/notify.log"
mkdir -p "$RUNDIR/logs"
touch "$LOG"

level="$1"
title="$2"
message="$3"
incident_id="$4"
action_cmd="$5"

safe_title=$(echo "$title" | tr '\n' ' ' | sed 's/"/\\"/g')
safe_message=$(echo "$message" | tr '\n' ' ' | sed 's/"/\\"/g')

now="$(date -u +%Y-%m-%dT%H:%M:%SZ)"
echo "[$now] level=$level id=$incident_id title=\"$safe_title\" msg=\"$safe_message\"" >> "$LOG"

if command -v termux-notification >/dev/null 2>&1; then
  if [ -n "$action_cmd" ]; then
    termux-notification \
      --id "fw_${incident_id}" \
      --title "$safe_title" \
      --content "$safe_message" \
      --priority high \
      --button1 "Eksekusi" \
      --button1-action "$action_cmd" \
      --button2 "Abaikan" \
      --button2-action "sh $MODDIR/bin/manual_action.sh reject $incident_id" >/dev/null 2>&1
  else
    termux-notification \
      --id "fw_${incident_id}" \
      --title "$safe_title" \
      --content "$safe_message" \
      --priority high >/dev/null 2>&1
  fi
  rc=$?
  echo "[$(date -u +%Y-%m-%dT%H:%M:%SZ)] termux_notification rc=$rc id=$incident_id" >> "$LOG"
  [ "$rc" -eq 0 ] && exit 0
fi

if command -v cmd >/dev/null 2>&1; then
  # Try multiple forms because behavior differs across Android builds.
  cmd notification post -S bigtext -t "$safe_title" "firewall.agent:$incident_id" "$safe_message" >/dev/null 2>&1
  rc=$?
  if [ "$rc" -ne 0 ]; then
    cmd notification post -t "$safe_title" "firewall.agent:$incident_id" "$safe_message" >/dev/null 2>&1
    rc=$?
  fi
  echo "[$(date -u +%Y-%m-%dT%H:%M:%SZ)] cmd_notification rc=$rc id=$incident_id" >> "$LOG"
  [ "$rc" -eq 0 ] && exit 0
fi

# Some ROMs only allow notification posting from shell UID (2000).
if command -v su >/dev/null 2>&1 && command -v cmd >/dev/null 2>&1; then
  su -lp 2000 -c "cmd notification post -S bigtext -t \"$safe_title\" \"firewall.agent:$incident_id\" \"$safe_message\"" >/dev/null 2>&1
  rc=$?
  if [ "$rc" -ne 0 ]; then
    su -lp 2000 -c "cmd notification post -t \"$safe_title\" \"firewall.agent:$incident_id\" \"$safe_message\"" >/dev/null 2>&1
    rc=$?
  fi
  echo "[$(date -u +%Y-%m-%dT%H:%M:%SZ)] cmd_notification_shell rc=$rc id=$incident_id" >> "$LOG"
  [ "$rc" -eq 0 ] && exit 0
fi

echo "[$(date -u +%Y-%m-%dT%H:%M:%SZ)] notification_failed id=$incident_id" >> "$LOG"
exit 0
