# Magisk/KSU Module (module/)

**Part of:** Firewall-Agent root project (see `../AGENTS.md`)

## OVERVIEW
AI Adaptive Firewall — Magisk/KSU module: ONNX policy engine in POSIX sh, KSUWebUI frontend, GSI telephony integration. id=`ai.adaptive.firewall`, v0.1.0, safe-by-default (`audit` mode).

## STRUCTURE
```
module/
├── module.prop                    # id, version, author
├── post-fs-data.sh                # early boot: runtime dirs, seed model, perms
├── service.sh                     # boot loop executor
├── customize.sh / uninstall.sh    # install/uninstall
├── system_privapp_permissions.xml # priv-app grant (GSI telephony)
├── config/                        # policy.json, model_update.json
├── bin/                           # policy engine scripts (separate AGENTS.md)
│   └── native/                    # infer_runner_native + libonnxruntime.so (prebuilt)
└── webroot/                       # KSUWebUI pages + shell API (separate AGENTS.md)
```

## BOOT CHAIN
1. `post-fs-data.sh` — create `runtime/{logs,incidents,pending_actions,escalations,actions,telemetry,config}`, seed ONNX model + feature contract, set permissions
2. `service.sh` — run selftest → publish web data → app inventory → status notify → telephony/IMS-RIL probes → enter `edge_runner.sh` loop (interval from `config/policy.json` `loop_interval_seconds`)

## POLICY ENGINE (edge_runner.sh)
```
collect_traffic.sh (per-UID counters)
  → feature_mapper.sh (→ features.json per contract)
  → infer_runner.sh (native binary first, python_infer.py fallback)
  → decision (audit|safe|enforce) → policy.json + incidents/actions
```
- Modes: `audit` (log only, default) → `safe` (auto-approve known) → `enforce` (block)
- Human-in-loop: pending_actions + manual_action.sh (`approve`/`reject`)
- Thresholds/tunables in `config/policy.json` (malicious_threshold, block_ttl, allowlist_uids, cooldown)

## CONFIG FILES
| File | Content |
|------|---------|
| config/policy.json | mode, thresholds, allowlist, loop interval |
| config/model_update.json | ONNX model source URL + update schedule |

## CONVENTIONS
- POSIX sh only (`#!/system/bin/sh`), paths via `MODDIR=${0%/*}`, JSON via sed/awk (no jq)
- Default mode MUST stay `audit` — never ship enforce-by-default
- Prebuilt native artifacts (infer_runner_native, libonnxruntime.so) checked in; source in `bin/native/src/`

## NOTES
- `runtime/` is gitignored — CI zips module with `-x "runtime/*"`
- GSI telephony = priv-app mount + IMS/RIL probing (see `bin/AGENTS.md`)
