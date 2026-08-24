# Maps Index — Firewall-Agent

> Generated: 2026-08-25 (manual scan — index-project.mjs mendukung JS/TS, project ini Kotlin+Shell)
> Regenerate: jalankan ulang scan simbol saat kode berubah

## Cara Pakai (untuk AGENT)
1. Baca file ini SEBELUM membaca file source satu-satu.
2. Cari simbol via grep (nama class/object/activity/script).
3. Buka file asli HANYA jika deskripsi kurang — pakai baris awal-akhir.
4. Lokasi relatif terhadap akar repo.

## Activities (dari AndroidManifest)
| Simbol | Lokasi | Deskripsi |
|---|---|---|
| MainActivity | MainActivity.kt:73 | Screen utama (2509 baris), launcher, FAB UI + apply rules |
| AdGuardActivity | AdGuardActivity.kt:23 | Screen Ads Guard (DNS, DoH, statistik) |
| AdsMatcherActivity | AdsMatcherActivity.kt:17 | Screen matcher rule ads |
| AlertsActivity | AlertsActivity.kt:20 | Screen alert/notifikasi |
| CallGuardActivity | CallGuardActivity.kt:26 | Screen Call Guard (whitelist/blacklist) |
| CallGuardDialerActivity | CallGuardDialerActivity.kt:34 | Dialer dengan proteksi |
| CallLogMenuActivity | CallLogMenuActivity.kt:15 | Menu log panggilan |
| DialerEntryActivity | DialerEntryActivity.kt:7 | Entry dialer (APP_DIALER intent) |
| EvilTwinActivity | EvilTwinActivity.kt:37 | Screen deteksi Evil Twin |
| ModelUpdateActivity | ModelUpdateActivity.kt:10 | Screen update model |
| NetworkLogTableActivity | NetworkLogTableActivity.kt:25 | Tabel log jaringan |
| PreferencesActivity | PreferencesActivity.kt:15 | Preferensi |
| RamOptimizerActivity | RamOptimizerActivity.kt:17 | RAM optimizer |
| RulesActivity | RulesActivity.kt:14 | Screen rules |
| SecurityStatsActivity | SecurityStatsActivity.kt:41 | Statistik keamanan (931 baris) |
| TorActivity | TorActivity.kt:14 | Screen Tor |
| TrafficFlowLogActivity | TrafficFlowLogActivity.kt:14 | Log flow trafik |
| TrafficMonitorActivity | TrafficMonitorActivity.kt:19 | Monitor trafik realtime |
| EvilTwinCreatorLauncher | publik/java/.../EvilTwinCreatorLauncher.kt | Flavor publik launcher |

## Services & Receivers
| Simbol | Lokasi | Deskripsi |
|---|---|---|
| FirewallKeepAliveService | FirewallKeepAliveService.kt:31 | Keep-alive backend (:backend process) |
| GlobalRuleSyncService | GlobalRuleSyncService.kt:23 | Sinkronisasi rule global |
| EvilTwinDetectionService | EvilTwinDetectionService.kt:25 | Monitoring Evil Twin background |
| FirewallCallScreeningService | FirewallCallScreeningService.kt:8 | Call screening (BIND_SCREENING_SERVICE) |
| FirewallInCallService | FirewallInCallService.kt:6 | In-call UI (BIND_INCALL_SERVICE) |
| FirewallConnectionService | FirewallConnectionService.kt:5 | Telecom ConnectionService |
| BootCompletedReceiver | BootCompletedReceiver.kt:9 | Start service saat boot |
| PackageAddedReceiver | PackageAddedReceiver.kt:12 | Deteksi app baru |
| PackageRemovedReceiver | PackageRemovedReceiver.kt:8 | Cleanup orphan rule |
| RestartServiceReceiver | RestartServiceReceiver.kt:8 | Restart service |
| EvilTwinReceiver | EvilTwinReceiver.kt:16 | Receiver hasil scan Evil Twin |

## Objects & Engines (inti)
| Simbol | Lokasi | Deskripsi |
|---|---|---|
| RootFirewallController | RootFirewallController.kt:34 | Kontrol root: iptables rules, apply, exec (libsu) |
| RequestDecisionEngine | xposed/RequestDecisionEngine.kt:20 | Engine keputusan request ads |
| HybridAdHook | xposed/HybridAdHook.kt:31 | Hook anti-ads + anti-redirect (2830 baris) |
| DnsHideHook | xposed/DnsHideHook.kt:32 | Hook hide DNS |
| AdMlScorer | AdMlScorer.kt:12 | ML scorer ads |
| CallRiskEngine | CallRiskEngine.kt:23 | Risk scoring nomor |
| EvilTwinDetector | EvilTwinDetector.kt:19 | Deteksi anomali Wi-Fi |
| TrafficEndpointInspector | TrafficEndpointInspector.kt:14 | Inspeksi endpoint trafik |

## Stores (persistence)
| Simbol | Lokasi | Deskripsi |
|---|---|---|
| AppConfigStore | AppConfigStore.kt:6 | Konfigurasi app |
| AppInventoryStore | AppInventoryStore.kt:8 | Inventori app |
| AppMetaCacheStore | AppMetaCacheStore.kt:18 | Cache metadata (CachedAppMeta:10) |
| AppIconCacheStore | AppIconCacheStore.kt:13 | Cache icon |
| AdEventStore | AdEventStore.kt:12 | Event ads blocked |
| AdsMatcherStore | AdsMatcherStore.kt:8 | Rule matcher ads |
| CallDatasetStore | CallDatasetStore.kt:7 | Dataset nomor |
| DnsBypassStore | DnsBypassStore.kt:16 | Bypass DNS |
| LogSnapshotCache | LogSnapshotCache.kt:5 | Snapshot log |
| BlacklistFeedSync | BlacklistFeedSync.kt:10 | Sinkron feed blacklist |
| NotifyHelper | NotifyHelper.kt:20 | Helper notifikasi |
| LoadingDialogController | LoadingDialogController.kt:142 | Compose loading dialog (ApplyProgress:2451) |

## Adapters & Custom Views
| Simbol | Lokasi | Deskripsi |
|---|---|---|
| AppRulesAdapter | AppRulesAdapter.kt:18 | List rule app (AppRuleEntry:8) |
| EvilTwinAdapter | EvilTwinAdapter.kt:10 | List hasil scan |
| RamOptimizerAdapter | RamOptimizerAdapter.kt:8 | List proses RAM |
| TrafficAppUsageAdapter | TrafficAppUsageAdapter.kt:19 | List usage per app (TrafficAppUsage:10) |
| TrafficChartView | TrafficChartView.kt:12 | Grafik trafik |
| SecurityPieChartView | SecurityPieChartView.kt:12 | Pie chart keamanan |
| SecurityTrendChartView | SecurityTrendChartView.kt:12 | Trend chart |
| SimpleTextWatcher | SimpleTextWatcher.kt:6 | TextWatcher sederhana |

## Modul Magisk (module/)
| File | Deskripsi |
|---|---|
| service.sh | Main loop executor saat boot |
| post-fs-data.sh | Init runtime folder/state |
| customize.sh / uninstall.sh | Installer/uninstaller |
| module.prop | Metadata (id=ai.adaptive.firewall v0.1.0) |
| bin/edge_runner.sh | Policy tick runner + ONNX score gate |
| bin/infer_runner.sh | Inferensi (native → python fallback) |
| bin/python_infer.py | Fallback onnxruntime |
| bin/feature_mapper.sh | Trafik → feature vector ONNX |
| bin/collect_traffic.sh | Per-UID network counters |
| bin/model_updater.sh | Update model ONNX terjadwal |
| bin/module_ctl.sh | CLI kontrol (status/mode/flush) |
| bin/notifier.sh + notify_status.sh | Notifikasi alert/status |
| bin/manual_action.sh | Eksekusi pending action (approve/reject) |
| bin/selftest_onnx.sh | Self-test backend ONNX |
| bin/publish_web_data.sh + publish_apps.sh | Publish JSON ke webroot/data |
| bin/ims_ril_probe.sh + ims_ril_adapter.sh | Probing/adapter IMS-RIL |
| bin/telephony_priv_setup.sh | Priv-app setup (GSI) |
| bin/native/src/infer_runner_native.cpp | Native ONNX runner (C++, CMake) |

## Webroot (KSUWebUI)
| File | Deskripsi |
|---|---|
| index.html | Halaman utama (Rules) |
| rules.html / logs.html / alerts.html / preferences.html / model_update.html | Halaman fitur |
| app.js / ksu_bridge.js / style.css | Frontend web + bridge KSU |
| data/apps.json | API data app (dipublish script) |
