# Rules — Firewall Agent Root

## Konvensi Koding (Kotlin)
- Package: `com.mrksvt.firewallagent` (app), `...firewallagent.xposed` (hooks)
- UI: `AppCompatActivity` + ViewBinding (buildFeatures.viewBinding = true)
- Compose: hanya untuk komponen dialog/loading/chart — bukan pengganti XML layout
- Store: `object` singleton + SharedPreferences/file JSON
- Naming file: `<Domain>Activity.kt`, `<Domain>Store.kt`, `<Domain>Adapter.kt`, `<Domain>Service.kt`, `<Domain>Receiver.kt`, `<Domain>Detector.kt`, `<Domain>Engine.kt`
- JVM target 17, minSdk 26, targetSdk 34

## Konvensi Modul (Shell)
- Shell scripts di `module/bin/`, bash-free (`#!/system/bin/sh`), POSIX
- Semua path dari `MODDIR=${0%/*}` — tidak ada hardcode absolut
- Log append ke `$RUNDIR/logs/` (LOG tagging `[service]`, `[edge]`, dst)
- Mode default `audit` (safe-by-default) — jangan enforce tanpa konfigurasi
- Native ONNX runner: C++ di `bin/native/src/`, build via CMake + NDK

## Konvensi Git
- Commit message: `fix:`, `feat:`, `docs:`, `chore:`, `refactor:` prefix
- Branch default: `main`, tag `v*` memicu CI release
- APK publik dirilis sebagai `app-publik-debug.apk` / `FirewallAgent-<tag>-debug.apk`

## File Wajib Baca Sebelum Kerja
- `.work/INDEX.md` — maps index kode (simbol + lokasi baris + commit)
- `.work/PRD.md`, `.work/Architecture.md`, `.work/Design.md`, `.work/Schema.md`, `.work/Rules.md` (file ini)

## Hal yang Dilarang
- Jangan tambah dependency tanpa kebutuhan jelas (stack minimal: libsu, xposed-stub, material)
- Jangan commit APK/artefak build ke git
- Jangan ubah mode default modul dari `audit` ke `enforce`
- Jangan hardcode UID/IP di script modul — lewat config
- Jangan pakai `as any` / suppress type error (tidak relevan Kotlin — gunakan safe cast/null-safe)
