package com.mrksvt.firewallagent

import android.content.BroadcastReceiver
import android.content.Context
import android.content.Intent
import android.os.Build
import android.util.Log

class BootCompletedReceiver : BroadcastReceiver() {
    private val tag = "FA.BootReceiver"

    override fun onReceive(context: Context, intent: Intent?) {
        val action = intent?.action ?: return
        val accepted = action == Intent.ACTION_BOOT_COMPLETED ||
            action == Intent.ACTION_LOCKED_BOOT_COMPLETED ||
            action == Intent.ACTION_MY_PACKAGE_REPLACED ||
            action == "android.intent.action.QUICKBOOT_POWERON" ||
            action == "com.htc.intent.action.QUICKBOOT_POWERON"
        if (!accepted) return

        Log.i(tag, "boot event received: action=$action")

        // ─── 1. Selalu start FirewallKeepAliveService (monitoring + DNS handover) ───
        val serviceIntent = Intent(context, FirewallKeepAliveService::class.java)
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
            context.startForegroundService(serviceIntent)
        } else {
            context.startService(serviceIntent)
        }

        // ─── 2. Auto-restore iptables rules dari SharedPreferences ───────────────────
        // Rules disimpan oleh RootFirewallController ketika user klik Apply.
        // Setiap boot, rules harus di-restore karena iptables tidak persist setelah reboot.
        val goAsync = goAsync()
        Thread {
            try {
                RootFirewallController.init(context)
                val rootOk = RootFirewallController.checkRoot()
                if (!rootOk) {
                    Log.w(tag, "root not available at boot, skip rule restore")
                    return@Thread
                }

                // Restore all stored app UID rules from shadow prefs
                val shadowPref = context.getSharedPreferences("fw_shadow_rules", Context.MODE_PRIVATE)
                val ruleStateJson = shadowPref.getString("rule_state_json", "{}").orEmpty()
                val blockedUidsCsv = shadowPref.getString("blocked_uids_csv", "").orEmpty()

                val blockedUids = blockedUidsCsv
                    .split(',')
                    .mapNotNull { it.trim().toIntOrNull() }
                    .filter { it > 0 }

                if (blockedUids.isNotEmpty()) {
                    Log.i(tag, "boot-restore: applying ${blockedUids.size} blocked uid rules")
                    val rules = blockedUids.map { uid ->
                        AppNetRule(
                            uid = uid,
                            local = false,
                            wifi = false,
                            cellular = false,
                            roaming = false,
                            vpn = false,
                            bluetooth = false,
                            tor = false,
                        )
                    }
                    RootFirewallController.applyAppRulesIncremental(
                        upsertRules = rules,
                        removeUids = emptySet(),
                    ) { done, total -> Log.i(tag, "boot-restore: applied $done/$total") }
                    Log.i(tag, "boot-restore: uid rules applied ok")
                } else {
                    Log.i(tag, "boot-restore: no blocked uids stored, skip rule restore")
                }

                // ─── 3. Start GlobalRuleSyncService jika sebelumnya aktif ───────────────
                val strictEnabled = context
                    .getSharedPreferences("global_strict_state", Context.MODE_PRIVATE)
                    .getBoolean("enabled", false)
                if (strictEnabled) {
                    Log.i(tag, "boot-restore: starting GlobalRuleSyncService")
                    val strictIntent = Intent(context, GlobalRuleSyncService::class.java).apply {
                        setAction(GlobalRuleSyncService.ACTION_START_GLOBAL_STRICT)
                    }
                    if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
                        context.startForegroundService(strictIntent)
                    } else {
                        context.startService(strictIntent)
                    }
                }

                // ─── 4. Restore DNS lock jika sebelumnya aktif ───────────────────────────
                val adguardPref = context.getSharedPreferences("adguard_dns", Context.MODE_PRIVATE)
                val dnsLockEnabled = adguardPref.getBoolean("dns_lock_enabled", false)
                val savedDnsHost = adguardPref.getString("saved_dns_host", "").orEmpty()
                if (dnsLockEnabled && savedDnsHost.isNotBlank()) {
                    Log.i(tag, "boot-restore: restoring DNS lock host=$savedDnsHost")
                    RootFirewallController.runRaw(
                        "settings put global private_dns_mode hostname; " +
                            "settings put global private_dns_specifier $savedDnsHost",
                    )
                }

                NotifyHelper.ensureChannel(context)
                NotifyHelper.post(
                    context,
                    "Firewall Agent",
                    "Rules otomatis dipulihkan setelah reboot (${blockedUids.size} app diblokir).",
                    1401,
                )
                Log.i(tag, "boot-restore: completed")
            } catch (e: Exception) {
                Log.e(tag, "boot-restore failed: ${e.message}")
            } finally {
                goAsync.finish()
            }
        }.start()
    }
}
