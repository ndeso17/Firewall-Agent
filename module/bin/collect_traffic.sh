#!/system/bin/sh
# Collect per-UID traffic counters and choose the most active app UID.

MODDIR=${0%/*}/..
RUNDIR="$MODDIR/runtime"
TDIR="$RUNDIR/telemetry"
SRC_XT="/proc/net/xt_qtaguid/stats"
SRC_DEV="/proc/net/dev"
UIDSTAT_DIR="/proc/uid_stat"
SNAP_CUR="$TDIR/current.tsv"
SNAP_PREV="$TDIR/prev.tsv"
DELTA="$TDIR/delta.tsv"
SELECTED="$TDIR/selected_uid.json"
DEV_CUR="$TDIR/dev_current.txt"
DEV_PREV="$TDIR/dev_prev.txt"
UID_CUR="$TDIR/uid_current.tsv"
UID_PREV="$TDIR/uid_prev.tsv"
UID_DELTA="$TDIR/uid_delta.tsv"

mkdir -p "$TDIR"

NET_SRC_IP="-"
NET_DST_IP="-"
NET_DST_PORT=0
NET_PROTO="-"

hex_ip_le() {
  h="$(echo "$1" | tr '[:lower:]' '[:upper:]')"
  case "$h" in
    ????????) ;;
    *) echo "-"; return 0 ;;
  esac
  case "$h" in
    *[!0-9A-F]*) echo "-"; return 0 ;;
  esac
  b1="$(echo "$h" | cut -c7-8)"
  b2="$(echo "$h" | cut -c5-6)"
  b3="$(echo "$h" | cut -c3-4)"
  b4="$(echo "$h" | cut -c1-2)"
  echo "$((16#$b1)).$((16#$b2)).$((16#$b3)).$((16#$b4))"
}

fill_net_meta() {
  target_uid="$1"
  NET_SRC_IP="-"
  NET_DST_IP="-"
  NET_DST_PORT=0
  NET_PROTO="-"

  case "$target_uid" in
    ''|'-'|*[!0-9]*) return 0 ;;
  esac

  line=""
  if [ -r /proc/net/tcp ]; then
    line="$(awk -v uid="$target_uid" 'NR>1 && $8==uid && $4=="01" {print $2 " " $3 " tcp"; exit}' /proc/net/tcp 2>/dev/null)"
    [ -z "$line" ] && line="$(awk -v uid="$target_uid" 'NR>1 && $8==uid {print $2 " " $3 " tcp"; exit}' /proc/net/tcp 2>/dev/null)"
  fi
  if [ -z "$line" ] && [ -r /proc/net/udp ]; then
    line="$(awk -v uid="$target_uid" 'NR>1 && $8==uid {print $2 " " $3 " udp"; exit}' /proc/net/udp 2>/dev/null)"
  fi
  [ -z "$line" ] && return 0

  local_addr="$(echo "$line" | awk '{print $1}')"
  remote_addr="$(echo "$line" | awk '{print $2}')"
  proto="$(echo "$line" | awk '{print $3}')"
  local_hex="${local_addr%:*}"
  remote_hex="${remote_addr%:*}"
  remote_port_hex="${remote_addr#*:}"

  NET_SRC_IP="$(hex_ip_le "$local_hex")"
  NET_DST_IP="$(hex_ip_le "$remote_hex")"
  case "$remote_port_hex" in
    ''|*[!0-9A-Fa-f]*) NET_DST_PORT=0 ;;
    *) NET_DST_PORT=$((16#$(echo "$remote_port_hex" | tr '[:lower:]' '[:upper:]'))) ;;
  esac
  [ "$NET_DST_IP" = "0.0.0.0" ] && NET_DST_IP="-"
  [ "$NET_SRC_IP" = "0.0.0.0" ] && NET_SRC_IP="-"
  [ -z "$proto" ] && proto="-"
  NET_PROTO="$proto"
}

if [ ! -r "$SRC_XT" ]; then
  if [ -d "$UIDSTAT_DIR" ]; then
    # Fallback #1: /proc/uid_stat per-UID counters.
    rm -f "$UID_CUR"
    for d in "$UIDSTAT_DIR"/*; do
      [ -d "$d" ] || continue
      uid="$(basename "$d")"
      case "$uid" in
        ''|*[!0-9]*) continue ;;
      esac
      rcv=0
      snd=0
      [ -r "$d/tcp_rcv" ] && rcv="$(cat "$d/tcp_rcv" 2>/dev/null)"
      [ -r "$d/tcp_snd" ] && snd="$(cat "$d/tcp_snd" 2>/dev/null)"
      [ -z "$rcv" ] && rcv=0
      [ -z "$snd" ] && snd=0
      printf "%s\t%s\t%s\n" "$uid" "$rcv" "$snd" >> "$UID_CUR"
    done
    if [ -s "$UID_CUR" ]; then
      [ -f "$UID_PREV" ] || cp "$UID_CUR" "$UID_PREV"
      awk -F '\t' '
      FNR==NR {pr[$1]=$2; ps[$1]=$3; next}
      {
        uid=$1; r=$2+0; s=$3+0; dr=r-pr[uid]; ds=s-ps[uid];
        if (dr<0) dr=0; if (ds<0) ds=0;
        db=dr+ds; tb=r+s;
        printf "%s\t%s\t%s\n", uid, db, tb;
      }' "$UID_PREV" "$UID_CUR" > "$UID_DELTA"
      cp "$UID_CUR" "$UID_PREV"

      row="$(awk -F '\t' '
      BEGIN {best=-1; u="-"; tb=0}
      {
        uid=$1+0; db=$2+0; t=$3+0;
        if (uid >= 10000 && db > best) {best=db; u=uid; tb=t}
      }
      END { printf "%s\t%s\t%s\n", u, best, tb }' "$UID_DELTA")"
      uid="$(echo "$row" | awk -F '\t' '{print $1}')"
      dbytes="$(echo "$row" | awk -F '\t' '{print $2}')"
      tbytes="$(echo "$row" | awk -F '\t' '{print $3}')"
      [ -z "$uid" ] && uid="-"
      [ -z "$dbytes" ] && dbytes=0
      [ -z "$tbytes" ] && tbytes=0
      [ "$dbytes" -lt 0 ] && dbytes=0
      fill_net_meta "$uid"
      cat > "$SELECTED" <<EOF
{"uid":"$uid","delta_bytes":$dbytes,"delta_packets":0,"total_bytes":$tbytes,"total_packets":0,"source":"uid_stat","src_ip":"$NET_SRC_IP","dst_ip":"$NET_DST_IP","dst_port":$NET_DST_PORT,"proto":"$NET_PROTO"}
EOF
      echo "uid_stat"
      exit 0
    fi
  fi

  if [ -r "$SRC_DEV" ]; then
    # Fallback: global network delta (no per-UID available on this ROM/kernel)
    awk 'NR>2 {
      gsub(":", "", $1);
      if ($1 != "lo") {
        rx += $2; rp += $3; tx += $10; tp += $11;
      }
    }
    END { printf "%s %s %s %s\n", rx, rp, tx, tp }' "$SRC_DEV" > "$DEV_CUR"
    if [ ! -f "$DEV_PREV" ]; then
      cp "$DEV_CUR" "$DEV_PREV"
    fi
    read -r crx crp ctx ctp < "$DEV_CUR"
    read -r prx prp ptx ptp < "$DEV_PREV"
    [ -z "$crx" ] && crx=0; [ -z "$ctx" ] && ctx=0; [ -z "$crp" ] && crp=0; [ -z "$ctp" ] && ctp=0
    [ -z "$prx" ] && prx=0; [ -z "$ptx" ] && ptx=0; [ -z "$prp" ] && prp=0; [ -z "$ptp" ] && ptp=0
    dbytes=$(( (crx-prx) + (ctx-ptx) ))
    dpkts=$(( (crp-prp) + (ctp-ptp) ))
    [ "$dbytes" -lt 0 ] && dbytes=0
    [ "$dpkts" -lt 0 ] && dpkts=0
    tbytes=$((crx+ctx))
    tpkts=$((crp+ctp))
    cp "$DEV_CUR" "$DEV_PREV"
    fill_net_meta "-"
    cat > "$SELECTED" <<EOF
{"uid":"-","delta_bytes":$dbytes,"delta_packets":$dpkts,"total_bytes":$tbytes,"total_packets":$tpkts,"source":"proc_net_dev","src_ip":"$NET_SRC_IP","dst_ip":"$NET_DST_IP","dst_port":$NET_DST_PORT,"proto":"$NET_PROTO"}
EOF
    echo "proc_net_dev"
    exit 0
  fi
  cat > "$SELECTED" <<'EOF'
{"uid":"-","delta_bytes":0,"delta_packets":0,"total_bytes":0,"total_packets":0,"source":"none","src_ip":"-","dst_ip":"-","dst_port":0,"proto":"-"}
EOF
  echo "none"
  exit 0
fi

# current snapshot: uid rx_bytes tx_bytes rx_packets tx_packets
awk 'NR>1 {
  uid=$4;
  if (uid ~ /^[0-9]+$/) {
    rx[uid]+=$6; tx[uid]+=$8; rxp[uid]+=$7; txp[uid]+=$9;
  }
}
END {
  for (u in rx) {
    printf "%s\t%s\t%s\t%s\t%s\n", u, rx[u], tx[u], rxp[u], txp[u];
  }
}' "$SRC_XT" > "$SNAP_CUR"

if [ ! -s "$SNAP_CUR" ]; then
  cat > "$SELECTED" <<'EOF'
{"uid":"-","delta_bytes":0,"delta_packets":0,"total_bytes":0,"total_packets":0,"source":"xt_qtaguid_empty"}
EOF
  echo "xt_qtaguid_empty"
  exit 0
fi

if [ ! -f "$SNAP_PREV" ]; then
  cp "$SNAP_CUR" "$SNAP_PREV"
fi

awk -F '\t' '
FNR==NR {
  p_rx[$1]=$2; p_tx[$1]=$3; p_rxp[$1]=$4; p_txp[$1]=$5;
  next;
}
{
  uid=$1; rx=$2; tx=$3; rxp=$4; txp=$5;
  d_rx=rx-p_rx[uid]; d_tx=tx-p_tx[uid]; d_rxp=rxp-p_rxp[uid]; d_txp=txp-p_txp[uid];
  if (d_rx < 0) d_rx=0; if (d_tx < 0) d_tx=0; if (d_rxp < 0) d_rxp=0; if (d_txp < 0) d_txp=0;
  d_bytes=d_rx+d_tx; d_pkts=d_rxp+d_txp;
  t_bytes=rx+tx; t_pkts=rxp+txp;
  printf "%s\t%s\t%s\t%s\t%s\n", uid, d_bytes, d_pkts, t_bytes, t_pkts;
}' "$SNAP_PREV" "$SNAP_CUR" > "$DELTA"

cp "$SNAP_CUR" "$SNAP_PREV"

# Pick most active app UID (>=10000). Fallback to top UID if none.
row="$(awk -F '\t' '
BEGIN {best=-1; bestu="-"; bestp=0; besttb=0; besttp=0; fbest=-1; fuid="-"; fp=0; ftb=0; ftp=0}
{
  uid=$1; db=$2+0; dp=$3+0; tb=$4+0; tp=$5+0;
  if (db > fbest) {fbest=db; fuid=uid; fp=dp; ftb=tb; ftp=tp}
  if (uid+0 >= 10000 && db > best) {best=db; bestu=uid; bestp=dp; besttb=tb; besttp=tp}
}
END {
  if (bestu != "-") printf "%s\t%s\t%s\t%s\t%s\n", bestu, best, bestp, besttb, besttp;
  else printf "%s\t%s\t%s\t%s\t%s\n", fuid, fbest, fp, ftb, ftp;
}' "$DELTA")"

uid="$(echo "$row" | awk -F '\t' '{print $1}')"
dbytes="$(echo "$row" | awk -F '\t' '{print $2}')"
dpkts="$(echo "$row" | awk -F '\t' '{print $3}')"
tbytes="$(echo "$row" | awk -F '\t' '{print $4}')"
tpkts="$(echo "$row" | awk -F '\t' '{print $5}')"

[ -z "$uid" ] && uid="-"
[ -z "$dbytes" ] && dbytes=0
[ -z "$dpkts" ] && dpkts=0
[ -z "$tbytes" ] && tbytes=0
[ -z "$tpkts" ] && tpkts=0

fill_net_meta "$uid"
cat > "$SELECTED" <<EOF
{"uid":"$uid","delta_bytes":$dbytes,"delta_packets":$dpkts,"total_bytes":$tbytes,"total_packets":$tpkts,"source":"xt_qtaguid","src_ip":"$NET_SRC_IP","dst_ip":"$NET_DST_IP","dst_port":$NET_DST_PORT,"proto":"$NET_PROTO"}
EOF

echo "xt_qtaguid"
