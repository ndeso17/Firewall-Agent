package com.mrksvt.firewallagent

import android.content.BroadcastReceiver
import android.content.Context
import android.content.Intent
import org.json.JSONObject

class PackageRemovedReceiver : BroadcastReceiver() {
    override fun onReceive(context: Context, intent: Intent?) {
        if (intent?.action != Intent.ACTION_PACKAGE_FULLY_REMOVED) return
        val pkg = intent.data?.schemeSpecificPart?.trim().orEmpty()
        val uid = intent.getIntExtra(Intent.EXTRA_UID, -1)
        if (uid <= 0 && pkg.isBlank()) return

        RootFirewallController.init(context.applicationContext)
        if (uid > 0 && RootFirewallController.checkRoot()) {
            RootFirewallController.removeUidRules(setOf(uid))
        }
        if (uid > 0) {
            cleanupShadowState(context, uid)
        }
        if (pkg.isNotBlank()) {
            cleanupProfileRuleEntries(context, pkg)
            cleanupKnownPackages(context, pkg)
            AppInventoryStore.remove(context.applicationContext, pkg)
            AppMetaCacheStore.remove(context.applicationContext, pkg)
        }
    }

    private fun cleanupProfileRuleEntries(context: Context, packageName: String) {
        val profilePref = context.getSharedPreferences("fw_profiles", Context.MODE_PRIVATE)
        val raw = profilePref.getString("profiles_csv", "anlap").orEmpty()
        val profiles = raw.split(',')
            .map { it.trim() }
            .filter { it.isNotBlank() }
            .ifEmpty { listOf("anlap") }
            .distinct()

        profiles.forEach { profile ->
            val key = profile.lowercase()
                .replace(Regex("[^a-z0-9._-]"), "_")
                .ifBlank { "default" }
            context.getSharedPreferences("fw_app_rules_$key", Context.MODE_PRIVATE)
                .edit()
                .remove(packageName)
                .apply()
        }
    }

    private fun cleanupKnownPackages(context: Context, packageName: String) {
        val pref = context.getSharedPreferences("fw_known_packages", Context.MODE_PRIVATE)
        val raw = pref.getString("known_csv", "").orEmpty()
        val kept = raw.split(',')
            .map { it.trim() }
            .filter { it.isNotBlank() && it != packageName }
            .distinct()
            .sorted()
            .joinToString(",")
        pref.edit().putString("known_csv", kept).apply()
    }

    private fun cleanupShadowState(context: Context, uid: Int) {
        val pref = context.getSharedPreferences("fw_shadow_rules", Context.MODE_PRIVATE)
        val csv = pref.getString("blocked_uids_csv", "").orEmpty()
        val kept = csv.split(',')
            .mapNotNull { it.trim().toIntOrNull() }
            .filter { it > 0 && it != uid }
            .distinct()
            .joinToString(",")

        val stateRaw = pref.getString("rule_state_json", "{}").orEmpty()
        val stateObj = runCatching { JSONObject(stateRaw) }.getOrDefault(JSONObject())
        stateObj.remove(uid.toString())

        pref.edit()
            .putString("blocked_uids_csv", kept)
            .putString("rule_state_json", stateObj.toString())
            .apply()
    }
}
