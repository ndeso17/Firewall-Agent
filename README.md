# Firewall Agent Root

Firewall Agent Root adalah aplikasi Android berbasis root untuk kontrol akses jaringan per aplikasi, proteksi panggilan, dan proteksi iklan secara hybrid.

Arsitektur project:

- `android-app/` -> aplikasi Android (UI, service backend, kontrol root)
- `module/` -> modul Magisk (bootstrap runtime saat boot, script/root backend)

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

## Fitur Pelengkap

- Traffic Monitor (grafik realtime + statistik per app)
- Security Stats (trend malware/ads/call)
- Background keep-alive service + autostart setelah boot
- Logging dan telemetry untuk troubleshooting

## Kebutuhan

- Android device yang sudah root
- Magisk aktif
- LSPosed (opsional, untuk Ads Guard hybrid hook)
- ADB (opsional, untuk debugging)

## Instalasi (User)

### 1) Install modul Magisk

1. Buka Magisk
2. Masuk menu **Modules**
3. Install modul dari folder `module/` (zip-kan sesuai struktur modul Magisk bila perlu)
4. Reboot device

### 2) Install aplikasi Android

1. Install APK dari `android-app`
2. Buka Firewall Agent Root
3. Grant akses root saat diminta

### 3) Setup awal

1. Aktifkan Firewall Agent
2. Atur rule FAB (jaringan + upload/download) sesuai kebutuhan
3. Tekan **Apply** untuk menerapkan ke iptables
4. Jika pakai Ads Guard hybrid, aktifkan LSPosed scope untuk app target

## Build (Developer)

```bash
cd android-app
JAVA_HOME=/home/mrksvt/android-studio/jbr ./gradlew assembleDebug
JAVA_HOME=/home/mrksvt/android-studio/jbr ./gradlew assembleRelease
```

Output APK:

- Debug: `android-app/app/build/outputs/apk/debug/`
- Release: `android-app/app/build/outputs/apk/release/`

## Catatan

- Salah konfigurasi rule dapat memutus akses internet app tertentu.
- Selalu backup profil/rule sebelum perubahan besar.
- Beberapa fitur telephony sangat bergantung pada ROM/vendor/device.

## Donasi

Kalau project ini membantu, dukungan kamu sangat berarti untuk maintenance fitur, bugfix, dan pengembangan berikutnya.

👉 https://naxgrinting.my.id/
