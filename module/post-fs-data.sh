#!/system/bin/sh
# Initialize runtime directories early.

MODDIR=${0%/*}
RUNDIR="$MODDIR/runtime"
LOGDIR="$RUNDIR/logs"
CFGDIR="$RUNDIR/config"
INCIDENT_DIR="$RUNDIR/incidents"
PENDING_DIR="$RUNDIR/pending_actions"
ESCALATE_DIR="$RUNDIR/escalations"
ACTION_DIR="$RUNDIR/actions"
TELEMETRY_DIR="$RUNDIR/telemetry"
WEBDATA_DIR="$MODDIR/webroot/data"
WEBICON_DIR="$MODDIR/webroot/icons"
ASSET_MODEL="$MODDIR/assets/default_model.onnx"
ASSET_CONTRACT="$MODDIR/assets/default_features_contract.json"
MODEL_DST="$RUNDIR/model.onnx"
CONTRACT_DST="$CFGDIR/features_contract.json"

mkdir -p "$LOGDIR"
mkdir -p "$CFGDIR"
mkdir -p "$INCIDENT_DIR"
mkdir -p "$PENDING_DIR"
mkdir -p "$ESCALATE_DIR"
mkdir -p "$ACTION_DIR"
mkdir -p "$TELEMETRY_DIR"
mkdir -p "$WEBDATA_DIR"
mkdir -p "$WEBICON_DIR"
chmod 700 "$RUNDIR"
chmod 700 "$LOGDIR"
chmod 700 "$CFGDIR"
chmod 700 "$INCIDENT_DIR"
chmod 700 "$PENDING_DIR"
chmod 700 "$ESCALATE_DIR"
chmod 700 "$ACTION_DIR"
chmod 700 "$TELEMETRY_DIR"
chmod 755 "$WEBDATA_DIR"
chmod 755 "$WEBICON_DIR"

# Defensive permission fix (some installers may not preserve +x bits).
chmod 0755 "$MODDIR/post-fs-data.sh" 2>/dev/null || true
chmod 0755 "$MODDIR/service.sh" 2>/dev/null || true
chmod 0755 "$MODDIR/uninstall.sh" 2>/dev/null || true
chmod 0755 "$MODDIR/customize.sh" 2>/dev/null || true
chmod 0755 "$MODDIR/bin/"*.sh 2>/dev/null || true
chmod 0755 "$MODDIR/webroot/api/"*.sh 2>/dev/null || true
if [ -f "$MODDIR/bin/python_infer.py" ]; then
  chmod 0755 "$MODDIR/bin/python_infer.py" 2>/dev/null || true
fi
if [ -f "$MODDIR/bin/native/infer_runner_native" ]; then
  chmod 0755 "$MODDIR/bin/native/infer_runner_native" 2>/dev/null || true
fi
if [ -d "$MODDIR/bin/native/lib" ]; then
  chmod 0755 "$MODDIR/bin/native/lib" 2>/dev/null || true
  chmod 0644 "$MODDIR/bin/native/lib/"*.so* 2>/dev/null || true
fi

# Default state for WebUI/CLI.
if [ ! -f "$RUNDIR/state.json" ]; then
  cat > "$RUNDIR/state.json" <<'EOF'
{"service":"starting","mode":"audit","last_decision":"none","updated_at":"-"}
EOF
fi

# Seed default ONNX assets on first boot after install.
if [ ! -f "$MODEL_DST" ] && [ -f "$ASSET_MODEL" ]; then
  cp "$ASSET_MODEL" "$MODEL_DST"
fi

if [ ! -f "$CONTRACT_DST" ] && [ -f "$ASSET_CONTRACT" ]; then
  cp "$ASSET_CONTRACT" "$CONTRACT_DST"
fi
