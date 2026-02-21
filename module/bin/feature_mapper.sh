#!/system/bin/sh
# Map runtime traffic telemetry into ONNX feature vector contract.

MODDIR=${0%/*}/..
RUNDIR="$MODDIR/runtime"
CONTRACT="$RUNDIR/config/features_contract.json"
FALLBACK_CONTRACT="$MODDIR/assets/default_features_contract.json"
SELECTED="$RUNDIR/telemetry/selected_uid.json"
OUT="$RUNDIR/features.json"

if [ ! -f "$CONTRACT" ] && [ -f "$FALLBACK_CONTRACT" ]; then
  CONTRACT="$FALLBACK_CONTRACT"
fi

if [ ! -f "$CONTRACT" ]; then
  # Defensive fallback: always produce fixed-length vector.
  i=0
  vec=""
  while [ "$i" -lt 117 ]; do
    [ -z "$vec" ] && vec="0.0000" || vec="$vec,0.0000"
    i=$((i+1))
  done
  cat > "$OUT" <<EOF
{"version":"v1","uid":"$uid","features":[${vec}]}
EOF
  exit 0
fi

uid="-"
dbytes=0
dpkts=0
tbytes=0
tpkts=0
if [ -f "$SELECTED" ]; then
  uid=$(sed -n 's/.*"uid"[[:space:]]*:[[:space:]]*"\([^"]*\)".*/\1/p' "$SELECTED" | head -n1)
  dbytes=$(sed -n 's/.*"delta_bytes"[[:space:]]*:[[:space:]]*\([0-9][0-9]*\).*/\1/p' "$SELECTED" | head -n1)
  dpkts=$(sed -n 's/.*"delta_packets"[[:space:]]*:[[:space:]]*\([0-9][0-9]*\).*/\1/p' "$SELECTED" | head -n1)
  tbytes=$(sed -n 's/.*"total_bytes"[[:space:]]*:[[:space:]]*\([0-9][0-9]*\).*/\1/p' "$SELECTED" | head -n1)
  tpkts=$(sed -n 's/.*"total_packets"[[:space:]]*:[[:space:]]*\([0-9][0-9]*\).*/\1/p' "$SELECTED" | head -n1)
fi
[ -z "$uid" ] && uid="-"
[ -z "$dbytes" ] && dbytes=0
[ -z "$dpkts" ] && dpkts=0
[ -z "$tbytes" ] && tbytes=0
[ -z "$tpkts" ] && tpkts=0

tmp_names="$RUNDIR/.feature_names.tmp"
sed -n 's/^[[:space:]]*"\([^"]*\)",\?/\1/p' "$CONTRACT" > "$tmp_names"

if [ ! -s "$tmp_names" ]; then
  i=0
  vec=""
  while [ "$i" -lt 117 ]; do
    [ -z "$vec" ] && vec="0.0000" || vec="$vec,0.0000"
    i=$((i+1))
  done
  cat > "$OUT" <<EOF
{"version":"v1","uid":"$uid","features":[${vec}]}
EOF
  rm -f "$tmp_names"
  exit 0
fi

awk -v uid="$uid" -v dbytes="$dbytes" -v dpkts="$dpkts" -v tbytes="$tbytes" -v tpkts="$tpkts" '
function cap(v, m) { return (v > m ? m : v) }
function ratio(a, b) { if (b <= 0) return 0; return a / b }
BEGIN {
  first=1;
  uidn=uid+0;
  db=dbytes+0; dp=dpkts+0; tb=tbytes+0; tp=tpkts+0;
  printf "{\"version\":\"v1\",\"uid\":\"%s\",\"features\":[", uid;
}
{
  f=$0;
  v=0;
  if (f=="APP") v=(uidn >= 10000 ? 1 : 0);
  else if (f=="SYSTEM") v=(uidn > 0 && uidn < 10000 ? 1 : 0);
  else if (f=="NETWORK") v=cap(db/2048.0, 10);
  else if (f=="SOCKET") v=cap(dp/20.0, 10);
  else if (f=="PACKET") v=cap(dp/50.0, 10);
  else if (f=="CONNECT") v=(dp > 0 ? 1 : 0);
  else if (f=="HTTP") v=cap(db/8192.0, 10);
  else if (f=="HOST") v=(db > 0 ? 1 : 0);
  else if (f=="UDP") v=0;
  else if (f=="TOR") v=0;
  else if (f=="PROXY") v=0;
  else if (f=="TRANSPORT") v=cap(tp/100.0, 10);
  else if (f=="SERVER") v=(ratio(db, tb) > 0.30 ? 1 : 0);
  else if (f=="CLIENT") v=(ratio(db, tb) <= 0.30 && db > 0 ? 1 : 0);
  else if (f=="MEDIA") v=(db > 1000000 ? 1 : 0);
  else if (f=="SSL") v=cap(db/65536.0, 10);
  else if (f=="FILE") v=cap(tb/131072.0, 10);
  else if (f=="PROCESS") v=(uidn > 0 ? 1 : 0);
  else if (f=="PERMISSION") v=(uidn > 0 ? 1 : 0);
  else if (f=="CACHE") v=cap(tb/262144.0, 10);
  else if (f=="RESOURCE") v=cap(tp/120.0, 10);
  else if (f=="SERVICE") v=(uidn > 0 ? 1 : 0);
  else if (f=="ACCESS") v=(db > 0 ? 1 : 0);

  if (!first) printf ",";
  printf "%.4f", v;
  first=0;
}
END {
  printf "]}\n";
}
' "$tmp_names" > "$OUT"

rm -f "$tmp_names"
exit 0
