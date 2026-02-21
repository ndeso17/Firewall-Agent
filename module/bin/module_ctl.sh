#!/system/bin/sh

MODDIR=${0%/*}/..
CFG="$MODDIR/config/policy.json"
RUNDIR="$MODDIR/runtime"
STATE="$RUNDIR/state.json"
LOGDIR="$RUNDIR/logs"
CTLLOG="$LOGDIR/module_ctl.log"
UPDATER="$MODDIR/bin/model_updater.sh"
ACTION="$MODDIR/bin/manual_action.sh"
ESCALATE_DIR="$RUNDIR/escalations"
NOTIFY_STATUS="$MODDIR/bin/notify_status.sh"
NOTIFIER="$MODDIR/bin/notifier.sh"

mkdir -p "$LOGDIR"
touch "$CTLLOG"

log_ctl() {
  msg="$1"
  uid="$(id -u 2>/dev/null || echo '?')"
  echo "[$(date -u +%Y-%m-%dT%H:%M:%SZ)] pid=$$ uid=$uid $msg" >> "$CTLLOG"
}

set_mode() {
  target="$1"
  log_ctl "action=mode target=$target begin"
  tmp="$CFG.tmp"
  sed -E "s/(\"mode\"[[:space:]]*:[[:space:]]*\")[^\"]+(\")/\1$target\2/" "$CFG" > "$tmp" \
    && mv "$tmp" "$CFG"
  rc=$?
  sh "$NOTIFY_STATUS" >/dev/null 2>&1
  log_ctl "action=mode target=$target rc=$rc end"
  echo "mode updated: $target"
}

show_status() {
  if [ -f "$STATE" ]; then
    cat "$STATE"
  else
    echo '{"service":"unknown","mode":"unknown"}'
  fi
}

flush_rules() {
  log_ctl "action=flush begin"
  if command -v iptables >/dev/null 2>&1; then
    iptables -F && echo "iptables flushed"
    rc=$?
    log_ctl "action=flush rc=$rc backend=iptables"
  else
    echo "iptables not found"
    log_ctl "action=flush rc=127 backend=iptables_missing"
  fi
}

notify_toggle() {
  state="$1"
  log_ctl "action=notify_toggle state=$state begin"
  title="Firewall Agent"
  nonce="$(date +%s)"
  if [ "$state" = "enable" ]; then
    msg="Firewall diaktifkan."
    id="fw_toggle_enable_$nonce"
  else
    msg="Firewall dinonaktifkan."
    id="fw_toggle_disable_$nonce"
  fi
  sh "$NOTIFIER" "info" "$title" "$msg" "$id" >/dev/null 2>&1
  rc=$?
  log_ctl "action=notify_toggle state=$state rc=$rc id=$id end"
}

disable_firewall() {
  log_ctl "action=disable begin"
  flush_rules
  notify_toggle "disable"
  log_ctl "action=disable end"
}

enable_firewall() {
  log_ctl "action=enable begin"
  sh "$NOTIFY_STATUS" >/dev/null 2>&1
  status_rc=$?
  notify_toggle "enable"
  log_ctl "action=enable notify_status_rc=$status_rc end"
}

log_ctl "invoke argv='$*'"

case "$1" in
  status)
    show_status
    ;;
  mode)
    case "$2" in
      audit|enforce|safe) set_mode "$2" ;;
      *) echo "usage: $0 mode {audit|enforce|safe}" ;;
    esac
    ;;
  flush)
    flush_rules
    ;;
  disable)
    disable_firewall
    ;;
  enable)
    enable_firewall
    ;;
  update-now)
    sh "$UPDATER"
    ;;
  approve)
    sh "$ACTION" approve "$2"
    ;;
  reject)
    sh "$ACTION" reject "$2"
    ;;
  export-latest-prompt)
    latest="$(ls -1t "$ESCALATE_DIR" 2>/dev/null | head -n1)"
    if [ -z "$latest" ]; then
      echo "no escalation prompt"
      exit 1
    fi
    cat "$ESCALATE_DIR/$latest"
    ;;
  *)
    echo "usage: $0 {status|mode|flush|enable|disable|update-now|approve <incident_id>|reject <incident_id>|export-latest-prompt}"
    ;;
esac
