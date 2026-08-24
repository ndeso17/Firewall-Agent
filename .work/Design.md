# Design — Firewall Agent Root

## Stack UI
- **Layout**: XML ViewBinding (AppCompatActivity) — mayoritas screen
- **Compose**: material3 — LoadingDialogController, ApplyProgressContent, chart views
- **Chart custom**: TrafficChartView, SecurityPieChartView, SecurityTrendChartView (custom View canvas)
- **Theme**: `Theme.FirewallAgentRoot` (values/themes.xml + values-night/themes.xml)
- **Material Components**: com.google.android.material 1.12.0, appcompat 1.7.0, recyclerview, cardview, constraintlayout

## Identitas Visual
- App icon: `ic_launcher_security` (drawable, bukan mipmap)
- Warna: `res/values/colors.xml` (dark theme + light, values-night)
- Label app: `Firewall Agent Root`

## Layout Resources (24)
activity_main, activity_adguard, activity_ads_matcher, activity_alerts, activity_call_guard,
activity_call_guard_dialer, activity_call_log_menu, activity_evil_twin, activity_model_update,
activity_network_log_table, + 14 lain (rules, preferences, tor, traffic, ram, security stats, dll)

## Drawable (32)
- Background: bg_app_icon_slot, bg_apply_fab_circle, bg_callguard_* (avatar, circle dark/green, panel)
- Icon: ic_apply_rules, ic_cell_4gplus, ic_cell_5g, + 22 lain

## Pattern Layout
- Aktivitas utama: bottom nav / FAB (bg_apply_fab_circle + ic_apply_rules)
- Call Guard: dialer avatar (bg_callguard_avatar + circle)
- Adapters: RecyclerView pattern (AppRulesAdapter, EvilTwinAdapter, RamOptimizerAdapter, TrafficAppUsageAdapter)

## WebUI (module/webroot)
- Pages: index (rules), logs, alerts, preferences, model_update
- `style.css` + `ksu_bridge.js` (KSUWebUI integration)
- Static JSON API: `data/apps.json`
