#!/system/bin/sh
MODDIR=${0%/*}/../..
CFG="$MODDIR/config/policy.json"

urldecode() {
  # decode %XX and +
  in="$1"
  in="${in//+/ }"
  printf '%b' "${in//%/\\x}"
}

get_param() {
  key="$1"
  raw=$(echo "$QUERY_STRING" | tr '&' '\n' | sed -n "s/^${key}=//p" | head -n1)
  urldecode "$raw"
}

mode=$(get_param mode)
threshold=$(get_param threshold)
uncertain_margin=$(get_param uncertain_margin)
cooldown=$(get_param cooldown)
ttl=$(get_param ttl)
ui_enable_notification=$(get_param ui_enable_notification)
ui_rules_progress=$(get_param ui_rules_progress)
ui_confirm_firewall=$(get_param ui_confirm_firewall)
ui_blacklist_default=$(get_param ui_blacklist_default)
ui_whitelist_default=$(get_param ui_whitelist_default)
log_target=$(get_param log_target)
log_service=$(get_param log_service)
log_show_hostname=$(get_param log_show_hostname)
log_ping_timeout=$(get_param log_ping_timeout)
profiles=$(get_param profiles)
active_profile=$(get_param active_profile)
language=$(get_param language)

[ -z "$mode" ] && mode="audit"
[ -z "$threshold" ] && threshold="0.8"
[ -z "$uncertain_margin" ] && uncertain_margin="0.1"
[ -z "$cooldown" ] && cooldown="120"
[ -z "$ttl" ] && ttl="1800"
[ -z "$ui_enable_notification" ] && ui_enable_notification="true"
[ -z "$ui_rules_progress" ] && ui_rules_progress="true"
[ -z "$ui_confirm_firewall" ] && ui_confirm_firewall="true"
[ -z "$ui_blacklist_default" ] && ui_blacklist_default="block"
[ -z "$ui_whitelist_default" ] && ui_whitelist_default="allow"
[ -z "$log_target" ] && log_target="NFLOG"
[ -z "$log_service" ] && log_service="false"
[ -z "$log_show_hostname" ] && log_show_hostname="false"
[ -z "$log_ping_timeout" ] && log_ping_timeout="15"
[ -z "$profiles" ] && profiles="default,gaming,work"
[ -z "$active_profile" ] && active_profile="default"
[ -z "$language" ] && language="id"

case "$mode" in
  audit|safe|enforce) ;;
  *) echo "invalid mode"; exit 1 ;;
esac

case "$threshold" in
  ''|*[!0-9.]* ) echo "invalid threshold"; exit 1 ;;
esac
case "$uncertain_margin" in
  ''|*[!0-9.]* ) echo "invalid uncertain_margin"; exit 1 ;;
esac
case "$cooldown" in
  ''|*[!0-9]* ) echo "invalid cooldown"; exit 1 ;;
esac
case "$ttl" in
  ''|*[!0-9]* ) echo "invalid ttl"; exit 1 ;;
esac
case "$log_ping_timeout" in
  ''|*[!0-9]* ) echo "invalid ping timeout"; exit 1 ;;
esac
case "$ui_blacklist_default" in
  allow|block) ;;
  *) echo "invalid ui_blacklist_default"; exit 1 ;;
esac
case "$ui_whitelist_default" in
  allow|block) ;;
  *) echo "invalid ui_whitelist_default"; exit 1 ;;
esac
case "$log_target" in
  NFLOG|LOG|ULOG|NONE) ;;
  *) echo "invalid log_target"; exit 1 ;;
esac
case "$language" in
  id|en|ko) ;;
  *) echo "invalid language"; exit 1 ;;
esac

profiles_json=$(echo "$profiles" | awk -F',' '{
  out="[";
  for (i=1; i<=NF; i++) {
    gsub(/^[ \t]+|[ \t]+$/, "", $i);
    if ($i != "") {
      if (out != "[") out=out ",";
      out=out "\"" $i "\"";
    }
  }
  if (out == "[") out="[\"default\"]";
  else out=out "]";
  print out;
}')

cat > "$CFG" <<EOF
{
  "mode": "$mode",
  "malicious_threshold": $threshold,
  "uncertain_margin": $uncertain_margin,
  "cooldown_seconds": $cooldown,
  "block_ttl_seconds": $ttl,
  "allowlist_uids": [0, 1000],
  "loop_interval_seconds": 10,
  "ui_enable_notification": $ui_enable_notification,
  "ui_rules_progress": $ui_rules_progress,
  "ui_confirm_firewall": $ui_confirm_firewall,
  "ui_blacklist_default": "$ui_blacklist_default",
  "ui_whitelist_default": "$ui_whitelist_default",
  "log_target": "$log_target",
  "log_service": $log_service,
  "log_show_hostname": $log_show_hostname,
  "log_ping_timeout": $log_ping_timeout,
  "profiles": $profiles_json,
  "active_profile": "$active_profile",
  "language": "$language"
}
EOF

echo "preferences saved"
