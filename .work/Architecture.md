# Architecture — Firewall Agent Root

## Struktur Folder
```
Firewall-Agent/
├── android-app/                    # Aplikasi Android
│   └── app/src/
│       ├── main/java/com/mrksvt/firewallagent/     # 54 file Kotlin
│       │   ├── *.Activity.kt                       # UI screens (ViewBinding)
│       │   ├── *Store.kt                           # Persistence (SharedPreferences/File)
│       │   ├── *Service.kt                         # Background service (backend process)
│       │   ├── *Receiver.kt                        # Broadcast receivers
│       │   ├── RootFirewallController.kt           # Inti kontrol root (libsu + iptables)
│       │   └── xposed/                             # LSPosed hooks
│       │       ├── HybridAdHook.kt                 # Ad blocking + anti-redirect (2830 baris)
│       │       ├── DnsHideHook.kt                  # DNS hide
│       │       └── RequestDecisionEngine.kt        # Engine keputusan request
│       ├── publik/java/.../EvilTwinCreatorLauncher.kt   # Flavor publik
│       ├── res/                                    # Layout, drawable, values
│       └── assets/bin/firewall_ctl.sh              # Shell backend di-asset
├── module/                         # Modul Magisk/KSU
│   ├── module.prop                  # id=ai.adaptive.firewall v0.1.0
│   ├── service.sh                   # Main loop executor saat boot
│   ├── post-fs-data.sh              # Init runtime folder/state
│   ├── customize.sh / uninstall.sh
│   ├── bin/                         # 17 script shell + python
│   │   ├── edge_runner.sh           # Policy tick runner + ONNX score gate
│   │   ├── infer_runner.sh          # Native first, Python fallback
│   │   ├── feature_mapper.sh        # Trafik → feature vector ONNX
│   │   ├── collect_traffic.sh       # Per-UID network counters
│   │   ├── python_infer.py          # Fallback onnxruntime
│   │   └── ... (model_updater, module_ctl, notifier, ims_ril_*)
│   ├── bin/native/                  # Native ONNX runner
│   │   └── src/infer_runner_native.cpp + CMakeLists.txt
│   ├── webroot/                     # KSUWebUI pages
│   │   ├── index.html, rules.html, logs.html, alerts.html
│   │   ├── preferences.html, model_update.html
│   │   ├── app.js, ksu_bridge.js, style.css
│   └── config/                      # policy.json, model_update.json
└── .github/workflows/release.yml    # CI: build APK + module zip
```

## Layer Aplikasi
1. **UI Layer** — Activities + Adapters (ViewBinding) + Compose (LoadingDialogController, charts)
2. **State Layer** — `*Store.kt` singletons (SharedPreferences/JSON file): AppConfigStore, AppInventoryStore, AdEventStore, AdsMatcherStore, CallDatasetStore, DnsBypassStore, AppMetaCacheStore, AppIconCacheStore, LogSnapshotCache, BlacklistFeedSync
3. **Service Layer** — `:backend` process services: FirewallKeepAliveService, GlobalRuleSyncService, EvilTwinDetectionService; Telecom: FirewallCallScreeningService, FirewallInCallService, FirewallConnectionService
4. **Root Control** — RootFirewallController (libsu 5.2.2, iptables), asset shell `firewall_ctl.sh`
5. **Xposed Layer** — HybridAdHook, DnsHideHook, RequestDecisionEngine (compileOnly xposed-api-stub.jar)

## Arsitektur Modul (AI Adaptive Firewall)
```
service.sh (boot loop)
  ├── selftest_onnx.sh          → status backend
  ├── publish_web_data.sh       → JSON snapshot → webroot/data/
  ├── publish_apps.sh           → daftar app → webroot/data/apps.json
  ├── notify_status.sh          → notifikasi status
  ├── telephony_priv_setup.sh   → role holder + appops (GSI)
  ├── ims_ril_probe.sh          → collect IMS/RIL signals
  └── edge_runner.sh (loop)     → collect_traffic → feature_mapper → infer (native/python) → policy.json → aksi audit/safe/enforce
```

## Routing & Auth
- Tidak ada auth (local app). Root access via libsu su request.
- AndroidManifest: MainActivity (LAUNCHER), DialerEntryActivity (APP_DIALER), 18 activity lain exported=false.
- Xposed: meta-data `xposedmodule`, scope dari `@array/xposed_scope`.

## State Management
- Singleton objects (Store) + SharedPreferences. Service state via foreground notification.
- Apply rules: LoadingDialogController (Compose) dengan progress determinate per-step.

## API Pattern
- Antarmuka app↔modul: tidak langsung HTTP; modul publish JSON ke `webroot/data/`, app baca via root/shell atau UI KSU terpisah.
- webroot API: fetch(`./data/apps.json`) pattern (KSUWebUI static).
