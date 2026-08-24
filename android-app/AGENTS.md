# Android App Layer (android-app/)

**Part of:** Firewall-Agent root project (see `../AGENTS.md`)

## OVERVIEW
Gradle Android app — FAB firewall UI, root control, call screening, traffic monitor. Kotlin 17, ViewBinding + Compose, libsu 5.2.2, Xposed stub (compileOnly).

## STRUCTURE
```
app/src/
├── main/
│   ├── java/com/mrksvt/firewallagent/    # 57 kt files (see below)
│   │   └── xposed/                       # LSPosed hooks (separate AGENTS.md)
│   ├── res/                              # layout (24), drawable (32), values, menu
│   └── assets/bin/firewall_ctl.sh        # shell backend, installed at root-init
├── publik/java/                          # flavor-specific source (EvilTwinCreatorLauncher)
└── main/AndroidManifest.xml              # 17 activities, 5 services, 4 receivers
```

## WHERE TO LOOK
| Task | Location | Notes |
|------|----------|-------|
| Manifest entry points | `app/src/main/AndroidManifest.xml` | services: keep-alive, rule-sync, 3 telecom (screening/in-call/connection) |
| Root control | `RootFirewallController.kt:34` | libsu `Shell` builder, iptables chains `FA_APP`/`FAU_<uid>` |
| Persistence | `*Store.kt` singletons | SharedPreferences/JSON objects |
| Background backend | `FirewallKeepAliveService.kt:31` | runs in `:backend` process, `Thread.sleep` loop (⚠️) |
| Dialer integration | `DialerEntryActivity.kt:7` | APP_DIALER intent filter |
| Loading/apply UI | `LoadingDialogController.kt:142` | Compose determinate dialog |

## KEY CLASSES
| Class | File:line | Role |
|-------|-----------|------|
| MainActivity | MainActivity.kt:73 | 2509 lines — FAB UI, apply flow, tabs |
| RootFirewallController | RootFirewallController.kt:34 | object — all root/iptables ops, `checkRoot` gates features |
| FirewallKeepAliveService | FirewallKeepAliveService.kt:31 | `:backend` process keep-alive loop |
| GlobalRuleSyncService | GlobalRuleSyncService.kt:23 | syncs rules app ↔ module |
| HybridAdHook / DnsHideHook | xposed/*.kt | LSPosed (separate AGENTS.md in xposed/) |
| AdMlScorer | AdMlScorer.kt:12 | ML ad scoring |
| CallRiskEngine | CallRiskEngine.kt:23 | phone-number risk scoring |
| EvilTwinDetector | EvilTwinDetector.kt:19 | Wi-Fi anomaly detection |
| TrafficChartView / SecurityPieChartView | *.kt:12 | custom canvas charts |
| AppConfigStore etc. | *Store.kt | object singletons over SharedPreferences |

## CONVENTIONS
- ViewBinding for XML screens; Compose only for dialog/loading/chart components
- `<Domain>Store.kt` = object singleton; `<Domain>Activity.kt` = screen; `<Domain>Adapter.kt` = RecyclerView
- Asset shell `assets/bin/firewall_ctl.sh` installed to cache at `RootFirewallController.init`, exec'd via libsu
- Xposed deps never shipped: `compileOnly files("libs/xposed-api-stub.jar")`

## ANTI-PATTERNS (APP-SPECIFIC)
- `Thread.sleep` blocks `:backend` (FirewallKeepAliveService.kt:321,412,430) → ANR; prefer coroutine `delay()`
- `@Suppress("DEPRECATION")` spread (MainActivity.kt:759+, AppMetaCacheStore.kt:62+) — migrate, don't suppress
- Loopback IPs/ports duplicated (127.0.0.0/8, 9040/9050) across RootFirewallController/MainActivity/AdGuardActivity — centralize
