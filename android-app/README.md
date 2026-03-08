# Firewall Agent (Android)

Firewall Agent adalah aplikasi Android untuk filtering DNS + firewall root + hook anti-ads/anti-redirect.

## Fitur Inti

### 1) FAB (Firewall Access Board)
Fitur utama untuk kontrol akses internet per aplikasi secara granular.

Kemampuan:
- Rule per aplikasi berbasis UID
- Kolom rule jaringan: LAN/Local, WiFi, Seluler, VPN, Bluetooth, Tor
- Kolom kontrol arah trafik: Download dan Upload
- Filter grup: All, Core, System, User, Protected
- Profil rule (multi profile) untuk skenario berbeda
- Apply rules dengan progress + notifikasi hasil
- Deteksi aplikasi baru + notifikasi agar rule segera diset
- Auto cleanup orphan rules ketika app di-uninstall

### 2) Call Guard
Fitur proteksi panggilan untuk meminimalkan spam/nomor tidak dikenal.

Kemampuan:
- Whitelist dan blacklist nomor
- Blokir panggilan nomor tak dikenal (mode konfigurasi)
- Integrasi call-screening (tergantung kompatibilitas ROM/vendor)
- Load recent calls untuk tindakan cepat (add ke whitelist/blacklist)
- Risk scoring dasar untuk bantu prioritas nomor berisiko

### 3) Ads Guard
Proteksi iklan menggunakan pendekatan hybrid, bukan hanya 1 lapisan.

Kemampuan:
- DNS-based filtering (Private DNS / DoH provider)
- DNS lock untuk mencegah bypass DNS biasa
- Hybrid app-level ad blocking via LSPosed hook (opsional)
- Statistik jumlah ads blocked
- Support ping provider DNS + pilih DNS tercepat

### 4) Evil Twin Detection
Fitur pemantauan Wi-Fi untuk membantu mendeteksi indikasi access point palsu (Evil Twin) berdasarkan anomali jaringan.

Kemampuan:
- Scan jaringan Wi-Fi sekitar dan analisis indikator risiko
- Monitoring latar belakang (Start/Stop Monitor)
- Klasifikasi tingkat ancaman: Low, Medium, High, Critical
- Ringkasan total jaringan dan jaringan mencurigakan
- Simpan laporan hasil scan ke Documents/FirewallAgent

## Fitur Pelengkap

- Traffic Monitor (grafik realtime + statistik per app)
- Security Stats (trend malware/ads/call)
- Background keep-alive service + autostart setelah boot
- Logging dan telemetry untuk troubleshooting

## Highlight patch terbaru (v1.0.6)

- Stabilitas init hook dan logging diagnostik ditingkatkan.
- Hardening anti-redirect browser/store/installer diperketat.
- Perbaikan blank page pada halaman hybrid tertentu (whitelist renderer inti).
- Optimasi anti-lag pada loop scheduler ads agresif.

## Instalasi & Penggunaan (User)

1. Install APK, download [di sini](https://github.com/ndeso17/Firewall-Agent/releases/download/v1.0.6/app-publik-debug.apk)
2. Buka **Firewall Agent Root**
3. Grant akses root saat diminta
4. Aktifkan Firewall Agent
5. Atur rule FAB (jaringan + upload/download) sesuai kebutuhan
6. Tekan **Apply** untuk menerapkan ke `iptables`
7. Jika pakai Ads Guard hybrid, aktifkan LSPosed scope untuk app target

Contoh install via ADB:
```bash
adb install -r app-publik-debug.apk
```

## Catatan penting

- Beberapa fitur hook membutuhkan LSPosed/Xposed aktif.
- Fitur yang memerlukan root tetap membutuhkan akses root (Magisk/KSU).
- Untuk keamanan publik, selalu prioritaskan rilis APK publik terbaru (`app-publik-debug.apk`).
