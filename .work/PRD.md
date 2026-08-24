# PRD — Firewall Agent Root

## Tujuan Produk
Aplikasi Android berbasis root untuk kontrol akses jaringan per aplikasi (firewall UID), proteksi panggilan, proteksi iklan hybrid, dan deteksi Evil Twin Wi-Fi. Didampingi modul Magisk/KSU "AI Adaptive Firewall" yang menjalankan policy engine berbasis ONNX di level sistem.

## Struktur Project
- `android-app/` — aplikasi Android (UI, service backend, kontrol root via libsu, Xposed hooks)
- `module/` — modul Magisk/KSU (bootstrap saat boot, policy engine, inferensi ONNX, KSUWebUI)
- `.github/workflows/release.yml` — CI build APK + zip modul saat tag `v*`

## Role Pengguna
| Role | Kebutuhan |
|------|-----------|
| **Pengguna akhir** | Blokir internet per app, proteksi panggilan spam, blokir iklan, deteksi Evil Twin, monitor trafik |
| **Power user / root user** | Kontrol granular per UID/jaringan/arah trafik, profil rule, modul Magisk |

## Fitur per Role

### Pengguna akhir
1. **FAB (Firewall Access Board)** — rule akses internet per app:
   - Rule berbasis UID, kolom jaringan (LAN/Local, WiFi, Seluler, VPN, Bluetooth, Tor)
   - Arah trafik: Download / Upload
   - Filter grup: All, Core, System, User, Protected
   - Multi-profil rule, apply dengan progress + notifikasi hasil
   - Deteksi app baru + auto-cleanup orphan rule saat app di-uninstall
2. **Call Guard** — whitelist/blacklist nomor, blokir tak dikenal, call screening, risk scoring, load recent calls
3. **Ads Guard** — DNS filtering (Private DNS/DoH), DNS lock, hybrid app-level ad blocking via LSPosed hook, statistik ads blocked, ping provider DNS
4. **Evil Twin Detection** — scan Wi-Fi, klasifikasi Low/Medium/High/Critical, monitoring background, laporan ke `Documents/FirewallAgent`
5. **Traffic Monitor** — grafik realtime + statistik per app
6. **Security Stats** — trend malware/ads/call

### Modul sistem (Magisk/KSU)
1. Policy engine berbasis ONNX dengan mode `audit` (safe-by-default) → `safe` → `enforce`
2. Collect per-UID traffic counters → feature vector → score inferensi
3. KSUWebUI status page (rules/logs/alerts/preferences/model update)
4. Native inferensi (`infer_runner_native` C++) dengan fallback Python ONNX
5. IMS/RIL probing + telephony priv-app setup (GSI-friendly)
6. Self-test ONNX + notifikasi status firewall aktif

## Flow Utama
1. **Aktivasi**: Install APK → grant root → aktifkan Firewall Agent → atur rule FAB → Apply ke iptables
2. **Boot**: Modul `service.sh` jalankan selftest → publish data → probe IMS/RIL → loop `edge_runner.sh`
3. **Ads Guard hybrid**: Aktifkan LSPosed scope → hook `HybridAdHook` di app target
4. **Call Guard**: CallScreeningService evaluasi nomor → blokir/jinkan per rule

## Versi Saat Ini
- App: v1.0.8 (versionCode 8), flavor `publik` / `privat`
- Modul: v0.1.0 (scaffold, mode `audit`)
