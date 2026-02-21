#!/system/bin/sh
# Publish installed app list (and best-effort real icons) for WebUI.

MODDIR=${0%/*}/..
WDATA="$MODDIR/webroot/data"
WICON="$MODDIR/webroot/icons"
APPS_JSON="$WDATA/apps.json"
TMP_APPS="$WDATA/.apps.tmp.json"
LOG="$MODDIR/runtime/logs/apps.log"
PKG_LIST="$WDATA/.pkg_list.tmp.txt"
PKG_CAND="$WDATA/.pkg_cand.tmp.txt"
UNZIP_BIN=""
PKG_SOURCE="unknown"

mkdir -p "$WDATA" "$WICON"
mkdir -p "$MODDIR/runtime/logs"
touch "$LOG"

if command -v unzip >/dev/null 2>&1; then
  UNZIP_BIN="$(command -v unzip)"
elif [ -x /system/bin/unzip ]; then
  UNZIP_BIN="/system/bin/unzip"
elif [ -x /system/bin/toybox ]; then
  UNZIP_BIN="/system/bin/toybox unzip"
fi

escape_json() {
  echo "$1" | sed 's/\\/\\\\/g; s/"/\\"/g'
}

pretty_name_from_pkg() {
  pkg="$1"
  base="${pkg##*.}"
  [ -z "$base" ] && base="$pkg"
  echo "$base" | sed 's/[_-]/ /g; s/[0-9]\+$//g' | awk '
    {
      for (i=1; i<=NF; i++) {
        w=$i
        $i=toupper(substr(w,1,1)) tolower(substr(w,2))
      }
      if (NF == 0) print "Unknown"
      else print $0
    }'
}

pick_icon_from_apk() {
  apk="$1"
  out_base="$2"
  if [ ! -f "$apk" ]; then
    return 1
  fi
  [ -n "$UNZIP_BIN" ] || return 1
  entry="$($UNZIP_BIN -l "$apk" 2>/dev/null | awk '{print $4}' | while IFS= read -r p; do
    case "$p" in
      res/mipmap*/ic_launcher*.png|res/mipmap*/ic_launcher*.webp|res/mipmap*/ic_launcher_round*.png|res/mipmap*/ic_launcher_round*.webp) echo "$p"; break ;;
    esac
  done)"
  if [ -z "$entry" ]; then
    entry="$($UNZIP_BIN -l "$apk" 2>/dev/null | awk '{print $4}' | while IFS= read -r p; do
      case "$p" in
        res/drawable*/ic_launcher*.png|res/drawable*/ic_launcher*.webp|res/drawable*/app_icon*.png|res/drawable*/app_icon*.webp) echo "$p"; break ;;
      esac
    done)"
  fi
  if [ -n "$entry" ]; then
    ext="png"
    case "$entry" in
      *.webp) ext="webp" ;;
      *.jpg|*.jpeg) ext="jpg" ;;
      *.png) ext="png" ;;
    esac
    out="$out_base.$ext"
    $UNZIP_BIN -p "$apk" "$entry" > "$out" 2>/dev/null || return 1
    [ -s "$out" ] || return 1
    echo "$out"
    return 0
  fi
  return 1
}

rm -f "$PKG_LIST" "$PKG_CAND"

valid_pkg_lines() {
  file="$1"
  [ -s "$file" ] || return 1
  grep -q '^package:[^ ]' "$file"
}

# Collect package list from most reliable command available.
if [ -x /system/bin/cmd ]; then
  /system/bin/cmd package list packages -U > "$PKG_CAND" 2>>"$LOG"
  if valid_pkg_lines "$PKG_CAND"; then
    mv "$PKG_CAND" "$PKG_LIST"
    PKG_SOURCE="cmd"
  else
    rm -f "$PKG_CAND"
  fi
fi
if [ ! -s "$PKG_LIST" ] && [ -x /system/bin/pm ]; then
  /system/bin/pm list packages -U > "$PKG_CAND" 2>>"$LOG"
  if valid_pkg_lines "$PKG_CAND"; then
    mv "$PKG_CAND" "$PKG_LIST"
    PKG_SOURCE="pm_u"
  else
    rm -f "$PKG_CAND"
  fi
fi
if [ ! -s "$PKG_LIST" ] && [ -x /system/bin/pm ]; then
  /system/bin/pm list packages > "$PKG_CAND" 2>>"$LOG"
  if valid_pkg_lines "$PKG_CAND"; then
    mv "$PKG_CAND" "$PKG_LIST"
    PKG_SOURCE="pm"
  else
    rm -f "$PKG_CAND"
  fi
fi
if [ ! -s "$PKG_LIST" ] && [ -r /data/system/packages.list ]; then
  awk 'NF>=2 && $2 ~ /^[0-9]+$/ { printf "package:%s uid:%s\n", $1, $2 }' \
    /data/system/packages.list > "$PKG_CAND" 2>>"$LOG"
  if valid_pkg_lines "$PKG_CAND"; then
    mv "$PKG_CAND" "$PKG_LIST"
    PKG_SOURCE="packages_list"
  else
    rm -f "$PKG_CAND"
  fi
fi

if [ ! -s "$PKG_LIST" ]; then
  echo "[$(date -u +%Y-%m-%dT%H:%M:%SZ)] no package list output from cmd/pm/packages.list" >> "$LOG"
  # Keep previous apps.json if available; avoid replacing with empty list repeatedly.
  if [ ! -f "$APPS_JSON" ]; then
    echo '[]' > "$APPS_JSON"
  fi
  exit 0
fi

{
  printf '['
  first=1
  while IFS= read -r line; do
    pkg="$(echo "$line" | sed -n 's/^package:\([^ ]*\).*/\1/p')"
    uid="$(echo "$line" | sed -n 's/.*[[:space:]]uid:\([0-9][0-9]*\).*/\1/p')"
    [ -z "$uid" ] && uid="$(echo "$line" | sed -n 's/.*[[:space:]]userId:\([0-9][0-9]*\).*/\1/p')"
    [ -z "$pkg" ] && continue
    [ -z "$uid" ] && uid=0

    type="user"
    if [ "$uid" -lt 10000 ]; then
      type="system"
    fi
    case "$pkg" in
      android|com.android.shell|com.android.systemui|com.google.android.gms) type="core" ;;
    esac

    name="$(pretty_name_from_pkg "$pkg")"
    icon_url=""
    icon_file="$WICON/$pkg.webp"
    [ -s "$icon_file" ] || icon_file="$WICON/$pkg.png"
    [ -s "$icon_file" ] || icon_file="$WICON/$pkg.jpg"
    icon_ext="${icon_file##*.}"
    if [ ! -s "$icon_file" ]; then
      apk_list="$WDATA/.apk_paths.$$"
      /system/bin/pm path "$pkg" 2>/dev/null | sed -n 's/^package://p' > "$apk_list"
      while IFS= read -r apk_path; do
        [ -n "$apk_path" ] || continue
        found="$(pick_icon_from_apk "$apk_path" "$WICON/$pkg" 2>/dev/null || true)"
        if [ -n "$found" ] && [ -s "$found" ]; then
          icon_file="$found"
          break
        fi
      done < "$apk_list"
      rm -f "$apk_list"
    fi
    if [ -s "$icon_file" ]; then
      icon_url="./icons/$pkg.${icon_file##*.}"
    fi

    jpkg="$(escape_json "$pkg")"
    jname="$(escape_json "$name")"
    jicon="$(escape_json "$icon_url")"
    if [ "$first" -eq 0 ]; then
      printf ','
    fi
    first=0
    printf '{"id":"%s","uid":%s,"name":"%s","pkg":"%s","type":"%s","icon_url":"%s","perms":{"local":true,"wifi":true,"cellular":true,"roaming":false,"vpn":true,"bluetooth_tethering":false,"tor":false}}' \
      "$jpkg" "$uid" "$jname" "$jpkg" "$type" "$jicon"
  done < "$PKG_LIST"
  printf ']'
} > "$TMP_APPS"

count="$(grep -o '"id":"' "$APPS_JSON" 2>/dev/null | wc -l | tr -d ' ')"
new_count="$(grep -o '"id":"' "$TMP_APPS" 2>/dev/null | wc -l | tr -d ' ')"
[ -z "$new_count" ] && new_count=0

if [ "$new_count" -gt 0 ]; then
  mv "$TMP_APPS" "$APPS_JSON"
  echo "[$(date -u +%Y-%m-%dT%H:%M:%SZ)] apps published count=$new_count source=$PKG_SOURCE" >> "$LOG"
else
  rm -f "$TMP_APPS"
  old_count="$(grep -o '"id":"' "$APPS_JSON" 2>/dev/null | wc -l | tr -d ' ')"
  [ -z "$old_count" ] && old_count=0
  if [ ! -f "$APPS_JSON" ]; then
    echo '[]' > "$APPS_JSON"
  fi
  echo "[$(date -u +%Y-%m-%dT%H:%M:%SZ)] skip overwrite (new_count=0, old_count=$old_count, source=$PKG_SOURCE)" >> "$LOG"
fi
