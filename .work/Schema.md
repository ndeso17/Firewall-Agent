# Schema — Firewall Agent Root

## Entitas Inti

### AppNetRule (RootFirewallController.kt:15)
```kotlin
data class AppNetRule(
    // uid, kolom jaringan (lan/wifi/mobile/vpn/bt/tor), arah (download/upload)
)
```

### ApplyRulesSummary (RootFirewallController.kt:26)
```kotlin
data class ApplyRulesSummary(
    // hasil apply: jumlah rule berhasil/gagal, pesan per-step
)
```

### ExecResult (RootFirewallController.kt:7)
```kotlin
data class ExecResult( // output + exit code dari shell root )
```

### AppRuleEntry (AppRulesAdapter.kt:8)
```kotlin
data class AppRuleEntry( // entry rule app untuk list UI )
```

### SecurityStats / AdAppStat (SecurityStatsActivity.kt:900-907)
```kotlin
data class AdAppStat( /* stat ads per app */ )
data class SecurityStats( /* agregat trend malware/ads/call */ )
```

### EvilTwinNetwork + ThreatLevel (EvilTwinActivity.kt:419,433)
```kotlin
data class EvilTwinNetwork( /* info AP hasil scan */ )
enum class ThreatLevel { LOW, MEDIUM, HIGH, CRITICAL }
```

### RiskEntry / RiskReport (CallRiskEngine.kt:8,17)
```kotlin
data class RiskEntry( /* skor risiko per nomor */ )
data class RiskReport( /* agregat laporan risiko */ )
```

### DecisionAction / DecisionResult (xposed/RequestDecisionEngine.kt:9,15)
```kotlin
enum class DecisionAction { /* ALLOW / BLOCK / REDIRECT / DLL */ }
data class DecisionResult( /* keputusan + alasan untuk satu request */ )
```

## Persistence (Store singletons)
| Store | Isi |
|-------|-----|
| AppConfigStore | konfigurasi app (SharedPreferences) |
| AppInventoryStore | inventori app terinstall |
| AppMetaCacheStore | cache metadata app (CachedAppMeta) |
| AppIconCacheStore | cache icon app |
| AdEventStore | event ads blocked |
| AdsMatcherStore | rule matcher ads |
| CallDatasetStore | dataset nomor (whitelist/blacklist) |
| DnsBypassStore | daftar bypass DNS |
| LogSnapshotCache | snapshot log |
| BlacklistFeedSync | sinkronisasi feed blacklist |

## API Response Shapes (module webroot)
- `data/apps.json` — daftar app + rule (dipublish `publish_apps.sh`)
- Runtime JSON snapshot — per-UID traffic + policy (dipublish `publish_web_data.sh`)
- `config/policy.json` — policy state (mode: audit/safe/enforce)
- `config/model_update.json` — konfigurasi update model ONNX

## Modul Runtime (service.sh)
- `$MODDIR/runtime/logs/service.log` — log utama
- Runtime folders dibuat di `post-fs-data.sh`
