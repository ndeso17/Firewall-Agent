#!/system/bin/sh
MODDIR=${0%/*}/../..
INCIDENT_DIR="$MODDIR/runtime/incidents"
PENDING_DIR="$MODDIR/runtime/pending_actions"
ACTION_DIR="$MODDIR/runtime/actions"

emit_array() {
  dir="$1"
  first=1
  if [ -d "$dir" ]; then
    ls -1t "$dir" 2>/dev/null | head -n 100 | while read -r f; do
      [ -n "$f" ] || continue
      [ -f "$dir/$f" ] || continue
      line="$(cat "$dir/$f")"
      if [ -z "$line" ]; then
        continue
      fi
      if [ "$first" -eq 1 ]; then
        printf '%s' "$line"
        first=0
      else
        printf ',%s' "$line"
      fi
    done
  fi
}

printf '{'
printf '"incidents":['
emit_array "$INCIDENT_DIR"
printf '],'
printf '"pending":['
emit_array "$PENDING_DIR"
printf '],'
printf '"actions":['
emit_array "$ACTION_DIR"
printf ']'
printf '}'
