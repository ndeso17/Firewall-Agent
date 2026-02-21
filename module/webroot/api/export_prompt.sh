#!/system/bin/sh
MODDIR=${0%/*}/../..
ESCALATE_DIR="$MODDIR/runtime/escalations"

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

id=$(get_param id)
[ -z "$id" ] && id=$(ls -1t "$ESCALATE_DIR" 2>/dev/null | head -n1)

if [ -z "$id" ]; then
  echo "no escalation prompt available"
  exit 1
fi

file="$ESCALATE_DIR/$id"
if [ ! -f "$file" ]; then
  echo "prompt not found: $id"
  exit 1
fi

cat "$file"
