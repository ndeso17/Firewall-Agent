#!/system/bin/sh
MODDIR=${0%/*}/../..
CFG="$MODDIR/config/model_update.json"

urldecode() {
  in="$1"
  in="${in//+/ }"
  printf '%b' "${in//%/\\x}"
}

get_param() {
  key="$1"
  raw=$(echo "$QUERY_STRING" | tr '&' '\n' | sed -n "s/^${key}=//p" | head -n1)
  urldecode "$raw"
}

manifest_url=$(get_param manifest_url)
onnx_url=$(get_param onnx_url)
channel=$(get_param channel)
auto_update=$(get_param auto_update)
check_interval_minutes=$(get_param check_interval_minutes)

[ -z "$channel" ] && channel="stable"
[ -z "$auto_update" ] && auto_update="false"
[ -z "$check_interval_minutes" ] && check_interval_minutes="60"

case "$channel" in
  stable|beta|dev) ;;
  *) echo "invalid channel"; exit 1 ;;
esac
case "$auto_update" in
  true|false) ;;
  *) echo "invalid auto_update"; exit 1 ;;
esac
case "$check_interval_minutes" in
  ''|*[!0-9]* ) echo "invalid check interval"; exit 1 ;;
esac

cat > "$CFG" <<EOF
{
  "manifest_url": "$manifest_url",
  "onnx_url": "$onnx_url",
  "channel": "$channel",
  "auto_update": $auto_update,
  "check_interval_minutes": $check_interval_minutes
}
EOF

echo "model update config saved"
