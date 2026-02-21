#!/system/bin/sh
MODDIR=${0%/*}/../..
ACT="$MODDIR/bin/manual_action.sh"

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

cmd=$(get_param cmd)
id=$(get_param id)

[ -z "$cmd" ] && cmd="approve"

case "$cmd" in
  approve|reject|block|allow) ;;
  *) echo "invalid cmd"; exit 1 ;;
esac

if [ -z "$id" ]; then
  echo "missing id"
  exit 1
fi

sh "$ACT" "$cmd" "$id"
