#!/system/bin/sh
# Manual action executor for SAFE mode pending incidents.

MODDIR=${0%/*}/..
RUNDIR="$MODDIR/runtime"
PENDING_DIR="$RUNDIR/pending_actions"
INCIDENT_DIR="$RUNDIR/incidents"
ACTION_DIR="$RUNDIR/actions"
BLOCKS="$RUNDIR/blocked_uids.txt"
LOG="$RUNDIR/logs/actions.log"

mkdir -p "$PENDING_DIR" "$INCIDENT_DIR" "$ACTION_DIR" "$RUNDIR/logs"
touch "$BLOCKS" "$LOG"

apply_block() {
  uid="$1"
  if command -v iptables >/dev/null 2>&1; then
    iptables -C OUTPUT -m owner --uid-owner "$uid" -j REJECT >/dev/null 2>&1 \
      || iptables -A OUTPUT -m owner --uid-owner "$uid" -j REJECT >/dev/null 2>&1
  fi
  grep -q "^$uid$" "$BLOCKS" 2>/dev/null || echo "$uid" >> "$BLOCKS"
}

set_status() {
  id="$1"
  status="$2"
  reason="$3"
  file="$PENDING_DIR/$id.json"
  if [ ! -f "$file" ]; then
    return 0
  fi
  uid=$(sed -n 's/.*"uid"[[:space:]]*:[[:space:]]*"\?\([^",}]*\)"\?.*/\1/p' "$file" | head -n1)
  score=$(sed -n 's/.*"score"[[:space:]]*:[[:space:]]*\([0-9.]*\).*/\1/p' "$file" | head -n1)
  [ -z "$uid" ] && uid="-"
  [ -z "$score" ] && score="0.00"
  cat > "$file" <<EOF
{"incident_id":"$id","uid":"$uid","score":$score,"status":"$status","updated_at":"$(date -u +%Y-%m-%dT%H:%M:%SZ)","reason":"$reason"}
EOF
}

get_value() {
  key="$1"
  file="$2"
  sed -n "s/.*\"$key\"[[:space:]]*:[[:space:]]*\"\\?\\([^\",}]*\\)\"\\?.*/\\1/p" "$file" | head -n1
}

resolve_source_file() {
  id="$1"
  if [ -f "$PENDING_DIR/$id.json" ]; then
    echo "$PENDING_DIR/$id.json"
    return 0
  fi
  if [ -f "$INCIDENT_DIR/$id.json" ]; then
    echo "$INCIDENT_DIR/$id.json"
    return 0
  fi
  return 1
}

write_action_record() {
  id="$1"
  uid="$2"
  mode="$3"
  action="$4"
  source="$5"
  cat > "$ACTION_DIR/$id.json" <<EOF
{"incident_id":"$id","uid":"$uid","mode":"$mode","action":"$action","source":"$source","updated_at":"$(date -u +%Y-%m-%dT%H:%M:%SZ)"}
EOF
}

cmd="$1"
incident_id="$2"
case "$cmd" in
  approve|block)
    file=$(resolve_source_file "$incident_id")
    if [ -z "$file" ]; then
      echo "incident not found: $incident_id"
      exit 1
    fi
    uid=$(get_value uid "$file")
    mode=$(get_value mode "$file")
    [ -z "$uid" ] && uid="-"
    [ -z "$mode" ] && mode="unknown"
    if [ "$uid" != "-" ]; then
      apply_block "$uid"
    fi
    set_status "$incident_id" "approved_block" "manual_safe_approve"
    write_action_record "$incident_id" "$uid" "$mode" "manual_block" "$(basename "$(dirname "$file")")"
    echo "$(date -u +%Y-%m-%dT%H:%M:%SZ) id=$incident_id action=approve uid=$uid" >> "$LOG"
    echo "approved and blocked uid=$uid"
    ;;
  reject|allow)
    file=$(resolve_source_file "$incident_id")
    if [ -z "$file" ]; then
      echo "incident not found: $incident_id"
      exit 1
    fi
    uid=$(get_value uid "$file")
    mode=$(get_value mode "$file")
    [ -z "$uid" ] && uid="-"
    [ -z "$mode" ] && mode="unknown"
    set_status "$incident_id" "rejected_allow" "manual_safe_reject"
    write_action_record "$incident_id" "$uid" "$mode" "manual_allow" "$(basename "$(dirname "$file")")"
    echo "$(date -u +%Y-%m-%dT%H:%M:%SZ) id=$incident_id action=reject uid=$uid" >> "$LOG"
    echo "rejected (allow) uid=$uid"
    ;;
  *)
    echo "usage: $0 {approve|reject|block|allow} <incident_id>"
    exit 1
    ;;
esac
