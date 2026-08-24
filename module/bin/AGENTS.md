# Module Shell Scripts (module/bin/)

**Part of:** Firewall-Agent module (see `../AGENTS.md`)

## OVERVIEW
Policy engine + system glue for the Magisk module, all POSIX sh (+1 Python fallback). Single-responsibility scripts chained by `edge_runner.sh` / `service.sh`.

## SCRIPT INVENTORY
**Policy pipeline**
| Script | Role |
|--------|------|
| collect_traffic.sh | per-UID network counters from kernel stats |
| feature_mapper.sh | traffic telemetry → ONNX feature vector (per contract) |
| infer_runner.sh | native `infer_runner_native` first, `python_infer.py` fallback |
| edge_runner.sh | loop worker: mode-gated action engine, lock-protected |
| python_infer.py | onnxruntime fallback runner |

**Control & notify**
| Script | Role |
|--------|------|
| module_ctl.sh | CLI: status / mode / flush |
| manual_action.sh | execute pending action (approve/reject) |
| notifier.sh | alert notification (audit/safe/enforce events) |
| notify_status.sh | status notification — verify firewall active |
| selftest_onnx.sh | ONNX backend self-test → store result |

**Data publish**
| Script | Role |
|--------|------|
| publish_web_data.sh | runtime JSON snapshot → `webroot/data/` |
| publish_apps.sh | app inventory → `webroot/data/apps.json` |
| model_updater.sh | scheduled ONNX model update from configured URL |

**Telephony (GSI)**
| Script | Role |
|--------|------|
| telephony_priv_setup.sh | role holder + appops for dialer/call-screening |
| ims_ril_probe.sh | collect device IMS/RIL signals |
| ims_ril_adapter.sh | vendor-specific adapter profile |

## PIPELINE CONTRACT
- `edge_runner.sh` reads policy config, locks via `runtime/.runner.lock` (exit if present)
- Feature vector validated against `runtime/config/features_contract.json`
- Decisions → `runtime/{incidents,pending_actions,escalations,actions}` + `logs/decision.log`
- `webroot/data/apps.json` consumed by webroot API (status UI)

## CONVENTIONS
- POSIX sh: no bashisms, no `jq` — sed/awk for JSON
- All paths derived: `MODDIR=${0%/*}/..`, runtime under `$RUNDIR`
- Every script appends to `$RUNDIR/logs/` with `[tag]` prefix
- Never hardcode device paths — probe or use `$PATH`

## ANTI-PATTERNS
- Hardcoded `/system/bin/unzip|toybox|cmd|pm` (publish_apps.sh:21+), `/system/bin/python3` (infer_runner.sh:55) — breaks non-standard PATH devices; probe first
- `rm -rf` unguarded in `../uninstall.sh:10` — add existence checks
