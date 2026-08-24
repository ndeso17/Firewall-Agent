# PROJECT KNOWLEDGE BASE

**Generated:** 2026-08-25
**Commit:** 61645f4
**Branch:** main

## OVERVIEW
Android root firewall: per-UID iptables control (FAB), call screening, hybrid ad blocking (LSPosed), Evil Twin Wi-Fi detection, traffic monitor. Plus Magisk/KSU module "AI Adaptive Firewall" — ONNX policy engine in shell. Stack: Kotlin 17, ViewBinding+Compose, libsu, Xposed stub; POSIX sh module backend.

## STRUCTURE
```
Firewall-Agent/
├── android-app/    # Android app (Gradle, 57 kt files)
│   └── app/src/main/java/com/mrksvt/firewallagent/
│       ├── *.Activity.kt, *Store.kt, *Service.kt, *Receiver.kt
│       ├── RootFirewallController.kt   # iptables core (libsu)
│       └── xposed/                     # LSPosed hooks (separate AGENTS.md)
├── module/         # Magisk/KSU module (54 files, separate AGENTS.md)
│   ├── bin/        # policy engine shell scripts (separate AGENTS.md)
│   └── webroot/    # KSUWebUI + shell API (separate AGENTS.md)
├── .github/workflows/release.yml   # tag v* → APK + module zip release
└── .work/          # design docs (PRD/Architecture/INDEX — read first)
```

## WHERE TO LOOK
| Task | Location | Notes |
|------|----------|-------|
| iptables rules / root exec | `RootFirewallController.kt:34` | libsu, `checkRoot` (11 callers), FA_APP chains, `applyAppRulesWithProgress` |
| Ad blocking / anti-redirect | `xposed/HybridAdHook.kt:31` | 2830 lines — WebView/WebResourceResponse interception |
| DNS masking | `xposed/DnsHideHook.kt:32` | fakes ad domains to 127.0.0.1, masks Private DNS |
| Manifest entry points | `android-app/app/src/main/AndroidManifest.xml` | 17 activities, 5 services, 4 receivers, Xposed meta |
| Module boot chain | `module/service.sh` + `post-fs-data.sh` | post-fs-data inits runtime → service.sh runs edge_runner loop |
| Policy decision | `module/bin/edge_runner.sh` | collect_traffic → feature_mapper → infer → policy.json |
| WebUI API | `module/webroot/api/` | 13 shell endpoints (status, rules, incidents, set_mode) |
| CI release | `.github/workflows/release.yml` | tag push → build APK + zip module → gh-release |
| Persistence stores | `*Store.kt` singletons | SharedPreferences/JSON (AppConfigStore, AdEventStore, CallDatasetStore...) |
| Apply progress UI | `LoadingDialogController.kt:142` | Compose determinate dialog |

## CODE MAP
| Symbol | Type | Location | Refs | Role |
|--------|------|----------|------|------|
| RootFirewallController | object | RootFirewallController.kt:34 | core | iptables apply/enable/disable/status via `bin/firewall_ctl.sh` asset |
| checkRoot | fun | RootFirewallController.kt:57 | 11 | su probe; gates all root features |
| requestRootAccess | fun | RootFirewallController.kt:64 | 1 | triggers Magisk/KSU grant dialog |
| FirewallKeepAliveService | service | FirewallKeepAliveService.kt:31 | 2 | `:backend` process keep-alive, `Thread.sleep` blocking |
| HybridAdHook | hook | xposed/HybridAdHook.kt:31 | — | IXposedHookLoadPackage, blocks ad URLs |
| DnsHideHook | hook | xposed/DnsHideHook.kt:32 | — | IXposedHookLoadPackage, DNS mask |
| MainActivity | activity | MainActivity.kt:73 | launcher | 2509 lines — FAB UI + apply flow |
| GlobalRuleSyncService | service | GlobalRuleSyncService.kt:23 | — | rule sync between app + module |
| BootCompletedReceiver | receiver | BootCompletedReceiver.kt:9 | — | BOOT_COMPLETED → start backend |

## CONVENTIONS
- Build flavors `publik`/`privat` (non-standard names) — `assemblePublikDebug`/`assemblePrivatDebug`
- JVM 17, minSdk 26, targetSdk 34; AGP Kotlin compose 1.5.14
- Xposed dep: `compileOnly files("libs/xposed-api-stub.jar")` — never ship stub
- Shell: POSIX sh only (`#!/system/bin/sh`), paths via `MODDIR=${0%/*}`, no jq (sed/awk JSON)
- Commits: Conventional (`fix:`, `feat:`, `docs:`, `chore:`)
- Store naming: `<Domain>Store.kt` = object singleton over SharedPreferences
- No ktlint/editorconfig — style enforced by review only

## ANTI-PATTERNS (THIS PROJECT)
- `Thread.sleep` in services — blocks `:backend` (FirewallKeepAliveService.kt:321,412,430) → ANR risk; use coroutine `delay()`
- `@Suppress("DEPRECATION")` sprawl — MainActivity.kt:759+, AppMetaCacheStore.kt:62+ hides tech debt
- Hardcoded loopback IPs/ports (127.0.0.0/8, 9040/9050) duplicated across RootFirewallController, MainActivity, AdGuardActivity — centralize
- Hardcoded `/system/bin/*` in module scripts (publish_apps.sh:21+, infer_runner.sh:55) — breaks non-standard PATH devices
- `rm -rf` in `module/uninstall.sh:10` — guard with existence checks
- Never flip module default mode off `audit` (safe-by-default)

## UNIQUE STYLES
- Asset-backed root control: `assets/bin/firewall_ctl.sh` installed at init, executed via libsu
- iptables chains `FA_APP`/`FAU_<uid>`; Tor allow via loopback 9040/9050; iface wildcards `wlan+`, `rmnet+`, `tun+`
- Magisk rule persistence at `/data/adb/modules/firewallagent-rules` (original_rules.v4 backup)
- WebUI endpoints are shell scripts, not server — KSUWebUI serves static + sh
- GSI telephony: priv-app mounting + IMS/RIL probes (`ims_ril_probe.sh`, `telephony_priv_setup.sh`)

## COMMANDS
```bash
# Build APK (debug)
cd android-app && ./gradlew assembleDebug          # both flavors
cd android-app && ./gradlew assemblePublikDebug    # publik only
# Install
cd android-app && ./gradlew installPublikDebug
# Package Magisk module (exclude runtime)
cd module && zip -r ../release-assets/FirewallAgent-<TAG>-magisk.zip . -x "runtime/*" "*.DS_Store"
# Native ONNX runner (module/bin/native/)
#   NDK + onnxruntime prebuilt → CMake via NDK; see module/bin/native/README.md
# Release: push tag vX.Y.Z → CI builds + publishes GitHub release
```

## NOTES
- `.work/` docs (PRD/Architecture/Design/Schema/Rules/INDEX) — read before feature work; INDEX.md = symbol map, regenerate on major changes
- Codegraph index at `.codegraph` (symlink) — use `codegraph_explore` for call graphs
- No Kotlin LSP configured — codegraph is primary code map tool
- `xposed_scope` array in `res/values/xposed_scope.xml` targets non-Google, non-self packages
- Module binary `bin/native/infer_runner_native` + `libonnxruntime.so` are prebuilt; source in `bin/native/src/`
- No automated tests in repo (explore scan: zero test files)
