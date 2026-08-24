# KSUWebUI Frontend (module/webroot/)

**Part of:** Firewall-Agent module (see `../AGENTS.md`)

## OVERVIEW
KSUWebUI-served control panel: static HTML/JS pages + shell-script API endpoints. No HTTP server — KSUWebUI serves static files and executes `api/*.sh` on request.

## STRUCTURE
```
webroot/
├── index.html          # main dashboard
├── rules.html          # iptables rules view
├── logs.html           # runtime logs viewer
├── alerts.html         # incidents timeline + action panel
├── preferences.html    # module prefs (get/set)
├── model_update.html   # ONNX model update UI
├── app.js              # frontend logic
├── ksu_bridge.js       # KSUWebUI bridge (page ↔ API calls)
├── style.css
├── api/                # 13 shell endpoints (below)
└── data/               # runtime JSON (published by bin/publish_*.sh)
```

## API ENDPOINTS (api/*.sh)
| Endpoint | Purpose |
|----------|---------|
| status.sh | module state, backend (native/python), pending/escalation counts |
| rules.sh | `iptables -S OUTPUT` dump + incidents |
| incidents.sh | incident feed |
| alerts_feed.sh | alerts timeline |
| action.sh | act on pending/escalated item |
| set_mode.sh / set_preferences.sh | write mode / prefs |
| get_preferences.sh / get_model_update.sh | read prefs / update config |
| set_model_update.sh | set model source + schedule |
| onnx_health.sh | native/Python backend health |
| view_log.sh | tail runtime logs |
| export_prompt.sh | export/backup prompt |

## DATA FLOW
```
HTML page → ksu_bridge.js → exec api/<endpoint>.sh → stdout JSON → DOM update
bin/publish_web_data.sh / publish_apps.sh → webroot/data/*.json → read by api scripts
```

## CONVENTIONS
- Endpoints are POSIX sh, output JSON on stdout only (no echo noise before JSON)
- `MODDIR=${0%/*}/../..` path resolution from api/ to module root — brittle, keep structure stable
- Frontend reads `data/` JSON + api output; no inline server logic

## NOTES
- `runtime/` excluded from module zip (CI) — `data/` must be regenerated at boot via publish scripts
- Keep api scripts dependency-free: only core shellutils + iptables
