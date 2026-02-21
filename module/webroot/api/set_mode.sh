#!/system/bin/sh
MODDIR=${0%/*}/../..
CTL="$MODDIR/bin/module_ctl.sh"

MODE=$(echo "$QUERY_STRING" | sed -n 's/.*mode=\([^&]*\).*/\1/p')

case "$MODE" in
  audit|safe|enforce)
    "$CTL" mode "$MODE"
    ;;
  *)
    echo "invalid mode"
    ;;
esac
