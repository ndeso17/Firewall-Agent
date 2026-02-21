#!/system/bin/sh
MODDIR=${0%/*}/../..
CFG="$MODDIR/config/policy.json"

if [ -f "$CFG" ]; then
  cat "$CFG"
  exit 0
fi

cat <<'EOF'
{
  "mode": "audit",
  "malicious_threshold": 0.8,
  "uncertain_margin": 0.1,
  "cooldown_seconds": 120,
  "block_ttl_seconds": 1800,
  "allowlist_uids": [0, 1000],
  "loop_interval_seconds": 10,
  "ui_enable_notification": true,
  "ui_rules_progress": true,
  "ui_confirm_firewall": true,
  "ui_blacklist_default": "block",
  "ui_whitelist_default": "allow",
  "log_target": "NFLOG",
  "log_service": false,
  "log_show_hostname": false,
  "log_ping_timeout": 15,
  "profiles": ["default", "gaming", "work"],
  "active_profile": "default",
  "language": "id"
}
EOF
