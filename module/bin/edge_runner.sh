#!/system/bin/sh
# Edge loop worker with mode-specific action engine.

MODDIR=${0%/*}/..
CFG="$1"
RUNDIR="$2"
STATE="$RUNDIR/state.json"
BLOCKS="$RUNDIR/blocked_uids.txt"
LOCK="$RUNDIR/.runner.lock"
INFER="$MODDIR/bin/infer_runner.sh"
MODEL_ONNX="$RUNDIR/model.onnx"
FEATURES="$RUNDIR/features.json"
FEATURE_CONTRACT="$RUNDIR/config/features_contract.json"
FALLBACK_CONTRACT="$MODDIR/assets/default_features_contract.json"
COLLECT="$MODDIR/bin/collect_traffic.sh"
MAPPER="$MODDIR/bin/feature_mapper.sh"
NOTIFIER="$MODDIR/bin/notifier.sh"
ACTION_CTL="$MODDIR/bin/manual_action.sh"
INCIDENT_DIR="$RUNDIR/incidents"
PENDING_DIR="$RUNDIR/pending_actions"
ESCALATE_DIR="$RUNDIR/escalations"
ACTION_DIR="$RUNDIR/actions"
DECISION_LOG="$RUNDIR/logs/decision.log"
SELECTED_JSON="$RUNDIR/telemetry/selected_uid.json"
APPS_JSON="$MODDIR/webroot/data/apps.json"

if [ -f "$LOCK" ]; then
  exit 0
fi
touch "$LOCK"
trap 'rm -f "$LOCK"' EXIT

mkdir -p "$RUNDIR"
mkdir -p "$RUNDIR/logs" "$INCIDENT_DIR" "$PENDING_DIR" "$ESCALATE_DIR" "$ACTION_DIR"
touch "$BLOCKS"
touch "$DECISION_LOG"

json_num() {
  key="$1"
  sed -n "s/.*\"$key\"[[:space:]]*:[[:space:]]*\\([0-9.]*\\).*/\\1/p" "$CFG" | head -n1
}

json_str() {
  key="$1"
  sed -n "s/.*\"$key\"[[:space:]]*:[[:space:]]*\"\\([^\"]*\\)\".*/\\1/p" "$CFG" | head -n1
}

json_bool() {
  key="$1"
  sed -n "s/.*\"$key\"[[:space:]]*:[[:space:]]*\\(true\\|false\\).*/\\1/p" "$CFG" | head -n1
}

json_file_str() {
  key="$1"
  file="$2"
  sed -n "s/.*\"$key\"[[:space:]]*:[[:space:]]*\"\\([^\"]*\\)\".*/\\1/p" "$file" | head -n1
}

json_file_num() {
  key="$1"
  file="$2"
  sed -n "s/.*\"$key\"[[:space:]]*:[[:space:]]*\\([0-9][0-9]*\\).*/\\1/p" "$file" | head -n1
}

resolve_app_by_uid() {
  lookup_uid="$1"
  app_name="-"
  app_pkg="-"
  case "$lookup_uid" in
    ''|'-'|*[!0-9]*) return 0 ;;
  esac
  [ -f "$APPS_JSON" ] || return 0
  entry="$(tr -d '\n' < "$APPS_JSON" | sed 's/^\[//;s/\]$//' | awk -v uid="$lookup_uid" '
    BEGIN { RS="\\},\\{" }
    {
      s=$0
      if (s ~ ("\"uid\":" uid "[,}]")) {
        gsub(/^\{/, "", s); gsub(/\}$/, "", s)
        print s
        exit
      }
    }')"
  [ -z "$entry" ] && return 0
  app_name="$(echo "{$entry}" | sed -n 's/.*"name":"\([^"]*\)".*/\1/p' | head -n1)"
  app_pkg="$(echo "{$entry}" | sed -n 's/.*"pkg":"\([^"]*\)".*/\1/p' | head -n1)"
  [ -z "$app_name" ] && app_name="-"
  [ -z "$app_pkg" ] && app_pkg="-"
}

apply_block() {
  uid="$1"
  [ -z "$uid" ] && return 0
  [ "$uid" = "-" ] && return 0
  if command -v iptables >/dev/null 2>&1; then
    iptables -C OUTPUT -m owner --uid-owner "$uid" -j REJECT >/dev/null 2>&1 \
      || iptables -A OUTPUT -m owner --uid-owner "$uid" -j REJECT >/dev/null 2>&1
  fi
  grep -q "^$uid$" "$BLOCKS" 2>/dev/null || echo "$uid" >> "$BLOCKS"
}

should_notify() {
  uid="$1"
  reason="$2"
  cooldown="$3"
  [ -z "$cooldown" ] && cooldown=120
  [ "$cooldown" -lt 0 ] && cooldown=0
  marker="$RUNDIR/.notify_${uid}_${reason}"
  now_epoch="$(date +%s)"
  last=0
  if [ -f "$marker" ]; then
    last="$(cat "$marker" 2>/dev/null)"
  fi
  [ -z "$last" ] && last=0
  if [ $((now_epoch - last)) -lt "$cooldown" ]; then
    return 1
  fi
  echo "$now_epoch" > "$marker"
  return 0
}

mode=$(json_str mode)
threshold=$(json_num malicious_threshold)
cooldown=$(json_num cooldown_seconds)
uncertain_margin=$(json_num uncertain_margin)
ui_enable_notification=$(json_bool ui_enable_notification)
if [ -z "$mode" ]; then
  mode="audit"
fi
[ -z "$threshold" ] && threshold="0.8"
[ -z "$cooldown" ] && cooldown="120"
[ -z "$uncertain_margin" ] && uncertain_margin="0.10"
[ -z "$ui_enable_notification" ] && ui_enable_notification="true"

# Runtime telemetry collection + feature mapping.
collect_source="$(sh "$COLLECT" 2>/dev/null | tail -n1)"
sh "$MAPPER" >/dev/null 2>&1
[ -z "$collect_source" ] && collect_source="unknown"

infer_json=$(sh "$INFER" "$MODEL_ONNX" "$FEATURES")
score=$(echo "$infer_json" | sed -n 's/.*"score":[[:space:]]*\([0-9.]*\).*/\1/p' | head -n1)
uid=$(echo "$infer_json" | sed -n 's/.*"uid":[[:space:]]*"\?\([^",}]*\)"\?.*/\1/p' | head -n1)
reason=$(echo "$infer_json" | sed -n 's/.*"reason":[[:space:]]*"\([^"]*\)".*/\1/p' | head -n1)

[ -z "$score" ] && score="0.00"
[ -z "$uid" ] && uid="-"
[ -z "$reason" ] && reason="inference_parse_error"
reason="${reason}|src:${collect_source}"
decision="log_only"
net_source="$collect_source"
net_src="-"
net_dst="-"
net_proto="-"
net_dport=0
app_name="-"
app_pkg="-"
if [ -f "$SELECTED_JSON" ]; then
  net_source="$(json_file_str source "$SELECTED_JSON")"
  net_src="$(json_file_str src_ip "$SELECTED_JSON")"
  net_dst="$(json_file_str dst_ip "$SELECTED_JSON")"
  net_proto="$(json_file_str proto "$SELECTED_JSON")"
  net_dport="$(json_file_num dst_port "$SELECTED_JSON")"
fi
[ -z "$net_source" ] && net_source="$collect_source"
[ -z "$net_src" ] && net_src="-"
[ -z "$net_dst" ] && net_dst="-"
[ -z "$net_proto" ] && net_proto="-"
[ -z "$net_dport" ] && net_dport=0
resolve_app_by_uid "$uid"

is_malicious=0
is_uncertain=0
if awk "BEGIN {exit !($score >= $threshold)}"; then
  is_malicious=1
else
  lower="$(awk "BEGIN {v=$threshold-$uncertain_margin; if (v<0) v=0; print v}")"
  if awk "BEGIN {exit !($score >= $lower && $score < $threshold)}"; then
    is_uncertain=1
  fi
fi

incident_id="$(date -u +%Y%m%dT%H%M%SZ)_${uid}"
incident_file="$INCIDENT_DIR/$incident_id.json"

if [ "$is_malicious" -eq 1 ]; then
  case "$mode" in
    audit)
      decision="notify_only"
      reason="audit_alert:$reason"
      if [ "$ui_enable_notification" = "true" ] && should_notify "$uid" "audit" "$cooldown"; then
        sh "$NOTIFIER" "warn" "Firewall Agent Audit" \
          "Aktivitas mencurigakan terdeteksi UID=$uid score=$score (tanpa aksi)." \
          "$incident_id" ""
      fi
      ;;
    safe)
      decision="pending_user_action"
      reason="safe_pending:$reason"
cat > "$PENDING_DIR/$incident_id.json" <<EOF
{"incident_id":"$incident_id","mode":"$mode","uid":"$uid","app_name":"$app_name","app_pkg":"$app_pkg","score":$score,"status":"pending","planned_action":"block_uid","created_at":"$(date -u +%Y-%m-%dT%H:%M:%SZ)","reason":"$reason","net_source":"$net_source","net_src":"$net_src","net_dst":"$net_dst","net_proto":"$net_proto","net_dport":$net_dport}
EOF
      if [ "$ui_enable_notification" = "true" ] && should_notify "$uid" "safe" "$cooldown"; then
        sh "$NOTIFIER" "warn" "Firewall Agent Safe Mode" \
          "UID=$uid score=$score butuh persetujuan. Gunakan tombol Eksekusi." \
          "$incident_id" "sh $ACTION_CTL approve $incident_id"
      fi
      ;;
    enforce)
      decision="block"
      reason="enforce_block:$reason"
      apply_block "$uid"
      cat > "$ACTION_DIR/$incident_id.json" <<EOF
{"incident_id":"$incident_id","mode":"$mode","uid":"$uid","action":"auto_block","source":"ml_enforce","updated_at":"$(date -u +%Y-%m-%dT%H:%M:%SZ)"}
EOF
      if [ "$ui_enable_notification" = "true" ] && should_notify "$uid" "enforce" "$cooldown"; then
        sh "$NOTIFIER" "critical" "Firewall Agent Enforce" \
          "UID=$uid score=$score diblok otomatis oleh mode enforce." \
          "$incident_id" ""
      fi
      ;;
  esac
fi

if [ "$is_uncertain" -eq 1 ]; then
  decision="escalate_review"
  reason="uncertain_band:$reason"
  prompt_file="$ESCALATE_DIR/prompt_${incident_id}.txt"
  cat > "$prompt_file" <<EOF
Firewall Agent - Escalation Prompt
timestamp_utc: $(date -u +%Y-%m-%dT%H:%M:%SZ)
incident_id: $incident_id
mode: $mode
uid: $uid
score: $score
threshold: $threshold
uncertain_margin: $uncertain_margin
reason: $reason

Instruction for analyst:
1. Review apakah perilaku ini malicious/benign.
2. Tentukan fitur tambahan atau perubahan threshold/model.
3. Buat rekomendasi update model ONNX berdasarkan evidence.

Raw inference payload:
$infer_json
EOF
  if [ "$ui_enable_notification" = "true" ] && should_notify "$uid" "uncertain" "$cooldown"; then
    sh "$NOTIFIER" "info" "Firewall Agent Needs Review" \
      "ML ragu untuk UID=$uid score=$score. Prompt tersimpan: $(basename "$prompt_file")" \
      "$incident_id" ""
  fi
fi

cat > "$STATE" <<EOF
{"service":"running","mode":"$mode","last_decision":"$decision","last_reason":"$reason","last_score":"$score","last_uid":"$uid","updated_at":"$(date -u +%Y-%m-%dT%H:%M:%SZ)"}
EOF

cat > "$incident_file" <<EOF
{"incident_id":"$incident_id","mode":"$mode","uid":"$uid","app_name":"$app_name","app_pkg":"$app_pkg","score":$score,"decision":"$decision","planned_action":"block_uid","reason":"$reason","inference_reason":"$reason","net_source":"$net_source","net_src":"$net_src","net_dst":"$net_dst","net_proto":"$net_proto","net_dport":$net_dport,"created_at":"$(date -u +%Y-%m-%dT%H:%M:%SZ)"}
EOF

echo "$(date -u +%Y-%m-%dT%H:%M:%SZ) mode=$mode decision=$decision reason=$reason score=$score uid=$uid incident=$incident_id" >> "$DECISION_LOG"
echo "[runner] mode=$mode decision=$decision reason=$reason score=$score uid=$uid incident=$incident_id"
