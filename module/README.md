# AI Adaptive Firewall Module (Magisk/KSU)

## Status
Scaffold v0.1.0 (safe-by-default, mode `audit`) with installable Magisk/KSU template.

## Structure
- `module.prop`: module metadata.
- `META-INF/com/google/android/*`: installer entrypoint for Magisk/KSU.
- `customize.sh`: installer logic (permissions + extraction).
- `post-fs-data.sh`: init runtime folder/state.
- `service.sh`: background loop executor.
- `bin/edge_runner.sh`: policy tick runner and ONNX score gate.
- `bin/infer_runner.sh`: inference wrapper (native first, Python fallback).
- `bin/python_infer.py`: ONNX fallback runner via `onnxruntime` Python package.
- `bin/notifier.sh`: send alert notification for audit/safe/enforce events.
- `bin/manual_action.sh`: execute SAFE pending action (`approve`/`reject`).
- `bin/selftest_onnx.sh`: run ONNX backend self-test and store result.
- `bin/collect_traffic.sh`: collect per-UID network counters from kernel stats.
- `bin/feature_mapper.sh`: map runtime traffic telemetry into ONNX feature vector.
- `bin/publish_web_data.sh`: publish runtime JSON snapshot to `webroot/data/`.
- `bin/notify_status.sh`: post status notification (service/mode/reason) so user can verify firewall is active.
- `bin/model_updater.sh`: scheduler update ONNX model from configured URL.
- `bin/module_ctl.sh`: CLI control (`status`, `mode`, `flush`).
- `webroot/`: KSUWebUI page and simple API scripts.
  - `alerts.html`: suspicious activity timeline + action panel.

## Install
0. (Recommended) Build native ONNX runner first:
   - Install Android NDK (via Android Studio SDK Manager).
   - Put ONNX Runtime prebuilt Android arm64 in one of these paths:
     - `third_party/onnxruntime-android-arm64`
     - `module/bin/native/onnxruntime`
     - `~/onnxruntime-android-arm64`
   - Optional manual env:
     - `export ONNXRUNTIME_ROOT=/path/to/onnxruntime-android-arm64`
     - `export ANDROID_NDK_ROOT=/path/to/android-ndk`
   - `bash scripts/build_infer_runner_native.sh --android --abi arm64-v8a`
1. Build zip:
   - `bash scripts/build_module_zip.sh`
2. Install `dist/ai-adaptive-firewall-module.zip` via Magisk or KSU.
3. Reboot.

## Priv-App + IMS/RIL Path (GSI-friendly)
For deeper telephony integration without full custom ROM, use priv-app mounting via Magisk/KSU:

1. Build Android app APK:
   - `cd android-app && JAVA_HOME=/home/mrksvt/android-studio/jbr ./gradlew assembleDebug`
2. Build priv-app module zip:
   - `bash scripts/build_privapp_module_zip.sh android-app/app/build/outputs/apk/debug/app-debug.apk`
3. Install zip:
   - `dist/ai-adaptive-firewall-privapp-module.zip`
4. Reboot.

This variant mounts:
- `/system/priv-app/FirewallAgentRoot/FirewallAgentRoot.apk`
- `/system/etc/permissions/privapp-permissions-com.mrksvt.firewallagent.xml`

Best-effort setup scripts:
- `bin/telephony_priv_setup.sh`: tries role holder + appops setup for dialer/call-screening.
- `bin/ims_ril_probe.sh`: collects device-specific IMS/RIL signals for analysis.
- `bin/ims_ril_adapter.sh`: builds vendor adapter profile (`mtk/qti/unisoc`) from latest probe output.

## Runtime Controls
- Status:
  - `sh /data/adb/modules/ai.adaptive.firewall/bin/module_ctl.sh status`
- ONNX health via WebUI API:
  - `/data/adb/modules/ai.adaptive.firewall/webroot/api/onnx_health.sh`
- Change mode:
  - `sh /data/adb/modules/ai.adaptive.firewall/bin/module_ctl.sh mode audit`
  - `sh /data/adb/modules/ai.adaptive.firewall/bin/module_ctl.sh mode safe`
  - `sh /data/adb/modules/ai.adaptive.firewall/bin/module_ctl.sh mode enforce`
- Emergency flush:
  - `sh /data/adb/modules/ai.adaptive.firewall/bin/module_ctl.sh flush`
- Trigger model update check now:
  - `sh /data/adb/modules/ai.adaptive.firewall/bin/module_ctl.sh update-now`
- Manual IMS/RIL probe:
  - `sh /data/adb/modules/ai.adaptive.firewall/bin/ims_ril_probe.sh`
- Manual IMS/RIL adapter refresh:
  - `sh /data/adb/modules/ai.adaptive.firewall/bin/ims_ril_adapter.sh`
- Manual telephony setup:
  - `sh /data/adb/modules/ai.adaptive.firewall/bin/telephony_priv_setup.sh`
- Approve SAFE pending action:
  - `sh /data/adb/modules/ai.adaptive.firewall/bin/module_ctl.sh approve <incident_id>`
- Reject SAFE pending action:
  - `sh /data/adb/modules/ai.adaptive.firewall/bin/module_ctl.sh reject <incident_id>`
- Export latest escalation prompt:
  - `sh /data/adb/modules/ai.adaptive.firewall/bin/module_ctl.sh export-latest-prompt`

## Mode Behavior
- `audit`: only notify user, no automatic block.
- `safe`: create pending action + notify user for manual execute.
- `enforce`: auto block UID when score >= threshold.
- uncertain score band (`threshold - uncertain_margin` to `< threshold`):
  - create escalation prompt under `runtime/escalations/` for analyst/retraining.

## Runtime Data Path
- `collect_traffic.sh` reads `/proc/net/xt_qtaguid/stats` and selects most active UID.
- If xt_qtaguid is unavailable, fallback uses `/proc/net/dev` global traffic delta.
- `feature_mapper.sh` converts telemetry into `runtime/features.json`.
- `edge_runner.sh` runs ONNX on this live feature payload each loop.
- `publish_web_data.sh` writes static JSON for WebUI:
  - `webroot/data/status.json`
  - `webroot/data/onnx_health.json`

## Notes
- Build packs default ONNX + feature contract from `server/` into module assets.
- On first boot, default model is seeded to `/data/adb/modules/ai.adaptive.firewall/runtime/model.onnx`.
- ONNX execution backend priority:
  1. Native runner: `bin/native/infer_runner_native`
  2. Python fallback: `python3 + onnxruntime + numpy`
- Notification backend priority:
  1. `termux-notification` (supports action button)
  2. `cmd notification post` (basic notification)
- If both backends are unavailable, runtime status reason will show `native_runner_missing` or `python_dep_missing`.
- Model update URL can be configured from KSUWebUI menu: `Model Update URL`.
- IMS/RIL behavior is vendor-specific. Probe outputs are saved under:
  - `/data/adb/modules/ai.adaptive.firewall/runtime/ims_ril/`
