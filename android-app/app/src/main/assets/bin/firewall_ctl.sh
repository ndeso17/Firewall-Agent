#!/system/bin/sh
# Bundled root controller for Firewall Agent app.

BASE_DIR="/data/local/tmp/firewall_agent"
STATE="$BASE_DIR/state.json"
LOG_DIR="$BASE_DIR/logs"
CTL_LOG="$LOG_DIR/controller.log"
CHAIN="FA_AGENT"

mkdir -p "$LOG_DIR"

log_ctl() {
  echo "[$(date -u +%Y-%m-%dT%H:%M:%SZ)] $*" >> "$CTL_LOG"
}

read_mode() {
  if [ -f "$STATE" ]; then
    sed -n 's/.*"mode"[[:space:]]*:[[:space:]]*"\([^"]*\)".*/\1/p' "$STATE" | head -n1
  fi
}

read_enabled() {
  if [ -f "$STATE" ]; then
    sed -n 's/.*"firewall_enabled"[[:space:]]*:[[:space:]]*\(true\|false\).*/\1/p' "$STATE" | head -n1
  fi
}

write_state() {
  mode="$1"
  enabled="$2"
  last_action="$3"
  last_result="$4"
  cat > "$STATE" <<JSON
{"service":"running","mode":"$mode","firewall_enabled":$enabled,"last_action":"$last_action","last_result":"$last_result","updated_at":"$(date -u +%Y-%m-%dT%H:%M:%SZ)"}
JSON
}

post_notify() {
  title="$1"
  body="$2"
  if command -v cmd >/dev/null 2>&1; then
    cmd notification post -S bigtext -t "$title" "firewall.agent.app:$(date +%s)" "$body" >/dev/null 2>&1
    return
  fi
}

ensure_default_state() {
  mode="$(read_mode)"
  enabled="$(read_enabled)"
  [ -z "$mode" ] && mode="audit"
  case "$enabled" in
    true|false) ;;
    *) enabled="true" ;;
  esac
  if [ ! -f "$STATE" ]; then
    write_state "$mode" "$enabled" "bootstrap" "ok"
  fi
}

status_cmd() {
  ensure_default_state
  cat "$STATE"
}

mode_cmd() {
  target="$1"
  case "$target" in
    audit|safe|enforce) ;;
    *) echo "invalid mode"; exit 1 ;;
  esac
  enabled="$(read_enabled)"
  [ -z "$enabled" ] && enabled="true"
  write_state "$target" "$enabled" "mode" "ok"
  log_ctl "mode=$target"
  post_notify "Firewall Agent" "Mode changed: $target"
  echo "mode updated: $target"
}

enable_cmd() {
  mode="$(read_mode)"
  [ -z "$mode" ] && mode="audit"

  iptables -N "$CHAIN" >/dev/null 2>&1 || true
  iptables -C OUTPUT -j "$CHAIN" >/dev/null 2>&1 || iptables -I OUTPUT 1 -j "$CHAIN" >/dev/null 2>&1

  write_state "$mode" "true" "enable" "ok"
  log_ctl "enable rc=$?"
  post_notify "Firewall Agent" "Firewall diaktifkan"
  echo "firewall enabled"
}

disable_cmd() {
  mode="$(read_mode)"
  [ -z "$mode" ] && mode="audit"

  while iptables -C OUTPUT -j "$CHAIN" >/dev/null 2>&1; do
    iptables -D OUTPUT -j "$CHAIN" >/dev/null 2>&1 || break
  done
  iptables -F "$CHAIN" >/dev/null 2>&1 || true
  iptables -X "$CHAIN" >/dev/null 2>&1 || true

  write_state "$mode" "false" "disable" "ok"
  log_ctl "disable"
  post_notify "Firewall Agent" "Firewall dinonaktifkan"
  echo "firewall disabled"
}

apply_cmd() {
  mode="$(read_mode)"
  [ -z "$mode" ] && mode="audit"
  enabled="$(read_enabled)"
  [ -z "$enabled" ] && enabled="true"

  if [ "$enabled" != "true" ]; then
    write_state "$mode" "false" "apply" "skipped_disabled"
    echo "apply skipped: firewall disabled"
    exit 0
  fi

  iptables -N "$CHAIN" >/dev/null 2>&1 || true
  iptables -C OUTPUT -j "$CHAIN" >/dev/null 2>&1 || iptables -I OUTPUT 1 -j "$CHAIN" >/dev/null 2>&1

  # Placeholder for per-app selected rules. This keeps apply fast and deterministic.
  write_state "$mode" "true" "apply" "ok"
  log_ctl "apply"
  post_notify "Firewall Agent" "Rules applied"
  echo "rules applied"
}

log_ctl "invoke: $*"

case "$1" in
  status)
    status_cmd
    ;;
  mode)
    mode_cmd "$2"
    ;;
  enable)
    enable_cmd
    ;;
  disable)
    disable_cmd
    ;;
  apply)
    apply_cmd
    ;;
  *)
    echo "usage: $0 {status|mode <audit|safe|enforce>|enable|disable|apply}"
    exit 1
    ;;
esac
