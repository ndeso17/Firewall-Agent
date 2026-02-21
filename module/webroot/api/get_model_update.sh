#!/system/bin/sh
MODDIR=${0%/*}/../..
CFG="$MODDIR/config/model_update.json"

if [ -f "$CFG" ]; then
  cat "$CFG"
  exit 0
fi

cat <<'EOF'
{
  "manifest_url": "",
  "onnx_url": "",
  "channel": "stable",
  "auto_update": false,
  "check_interval_minutes": 60
}
EOF
