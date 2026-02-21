# Firewall Agent Root App (Android)

Aplikasi Android native untuk kontrol firewall via root (Magisk/KSU), lebih responsif dibanding KSU WebUI.

## Fitur awal
- Check root availability.
- Refresh status service lokal app.
- Set mode: `audit`, `safe`, `enforce`.
- Enable firewall.
- Disable firewall.
- Apply rules.
- Notifikasi native Android saat aksi sukses/gagal.

## Dependensi
- Android Studio (Hedgehog+ disarankan).
- Android SDK API 34.
- Root manager aktif (Magisk/KSU) di device.

## Buka project
1. Buka folder `android-app` di Android Studio.
2. Sync Gradle.
3. Build lalu install ke device root.

## Catatan
- Eksekusi root dilakukan dengan `libsu`.
- Script kontrol dibundle di app asset (`assets/bin/firewall_ctl.sh`) lalu diekstrak ke `filesDir/bin` saat app start.
- Runtime state/log disimpan di `/data/local/tmp/firewall_agent`.
- Ini fondasi awal control app; layar daftar app + rule matrix bisa ditambahkan di tahap berikutnya.
