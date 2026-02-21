package com.mrksvt.firewallagent

import android.content.BroadcastReceiver
import android.content.Context
import android.content.Intent
import android.util.Log
import org.json.JSONObject
import java.util.Locale
import kotlin.concurrent.thread
import kotlin.math.absoluteValue

class PackageAddedReceiver : BroadcastReceiver() {
    private val tag = "FA.PackageAdded"

    override fun onReceive(context: Context, intent: Intent?) {
        if (intent?.action != Intent.ACTION_PACKAGE_ADDED) return
        if (intent.getBooleanExtra(Intent.EXTRA_REPLACING, false)) return

        val pkg = intent.data?.schemeSpecificPart?.trim().orEmpty()
        val uid = intent.getIntExtra(Intent.EXTRA_UID, -1)
        Log.i(tag, "received PACKAGE_ADDED pkg=$pkg uid=$uid replacing=false")
        if (pkg.isBlank() || uid <= 0) return
        if (!RootFirewallController.isManagedAppUid(uid)) return
        if (pkg == context.packageName) return

        val pending = goAsync()
        val appCtx = context.applicationContext
        thread(name = "fa-pkg-added") {
            try {
                applyDefaultDenyToAllProfiles(appCtx, pkg)
                clearShadowStateForUid(appCtx, uid)
                enforceImmediatelyIfEnabled(appCtx, uid)
                AppInventoryStore.upsert(appCtx, pkg, uid)
                AppMetaCacheStore.upsert(appCtx, pkg, uid)
                notifyNewAppNeedsRules(appCtx, pkg)
                Log.i(tag, "new app default-deny+notify done pkg=$pkg uid=$uid")
            } catch (t: Throwable) {
                Log.e(tag, "receiver failed pkg=$pkg uid=$uid", t)
            } finally {
                pending.finish()
            }
        }
    }

    private fun applyDefaultDenyToAllProfiles(context: Context, pkg: String) {
        val profilePref = context.getSharedPreferences("fw_profiles", Context.MODE_PRIVATE)
        val raw = profilePref.getString("profiles_csv", "anlap").orEmpty()
        val profiles = raw.split(',')
            .map { it.trim() }
            .filter { it.isNotBlank() }
            .ifEmpty { listOf("anlap") }
            .distinct()

        val deny = JSONObject()
            .put("local", false)
            .put("wifi", false)
            .put("cellular", false)
            .put("roaming", false)
            .put("vpn", false)
            .put("bluetooth_tethering", false)
            .put("tor", false)
            .put("download", false)
            .put("upload", false)
            .toString()

        profiles.forEach { profile ->
            val prefName = "fw_app_rules_${profileKey(profile)}"
            val pref = context.getSharedPreferences(prefName, Context.MODE_PRIVATE)
            // Always overwrite on fresh install to guarantee secure default deny.
            pref.edit().putString(pkg, deny).apply()
        }
    }

    private fun clearShadowStateForUid(context: Context, uid: Int) {
        val profilePref = context.getSharedPreferences("fw_profiles", Context.MODE_PRIVATE)
        val raw = profilePref.getString("profiles_csv", "anlap").orEmpty()
        val profiles = raw.split(',')
            .map { it.trim() }
            .filter { it.isNotBlank() }
            .ifEmpty { listOf("anlap") }
            .distinct()

        profiles.forEach { profile ->
            val shadowName = "fw_shadow_rules_${profileKey(profile)}"
            val pref = context.getSharedPreferences(shadowName, Context.MODE_PRIVATE)

            val blockedCsv = pref.getString("blocked_uids_csv", "").orEmpty()
            val kept = blockedCsv.split(',')
                .mapNotNull { it.trim().toIntOrNull() }
                .filter { it > 0 && it != uid }
                .distinct()
                .joinToString(",")

            val stateRaw = pref.getString("rule_state_json", "{}").orEmpty()
            val obj = runCatching { JSONObject(stateRaw) }.getOrDefault(JSONObject())
            obj.remove(uid.toString())

            pref.edit()
                .putString("blocked_uids_csv", kept)
                .putString("rule_state_json", obj.toString())
                .apply()
        }
    }

    private fun enforceImmediatelyIfEnabled(context: Context, uid: Int) {
        RootFirewallController.init(context)
        if (!RootFirewallController.checkRoot()) return

        val status = RootFirewallController.status().stdout
        val statusEnabled = runCatching {
            JSONObject(status).optBoolean("firewall_enabled", false)
        }.getOrDefault(false)
        // Fallback detection: if FA_APP already hooked to OUTPUT, treat firewall as active.
        val chainEnabled = RootFirewallController.runRaw("iptables -C OUTPUT -j FA_APP >/dev/null 2>&1").ok
        if (!statusEnabled && !chainEnabled) return

        val denyRule = AppNetRule(
            uid = uid,
            local = false,
            wifi = false,
            cellular = false,
            roaming = false,
            vpn = false,
            bluetooth = false,
            tor = false,
            download = false,
            upload = false,
        )
        val (res, _) = RootFirewallController.applyAppRulesIncremental(
            upsertRules = listOf(denyRule),
            removeUids = emptySet(),
        ) { _, _ -> }

        if (res.ok) {
            NotifyHelper.ensureChannel(context)
            NotifyHelper.post(
                context,
                "Firewall Agent",
                "App baru di-set default deny internet (UID $uid).",
                119 + (uid % 1000),
            )
        }
    }

    private fun notifyNewAppNeedsRules(context: Context, packageName: String) {
        NotifyHelper.ensureChannel(context)
        NotifyHelper.postNewAppNeedsRules(context, packageName)
        NotifyHelper.post(
            context,
            "Aplikasi baru terdeteksi",
            "$packageName diblokir default. Atur rules Firewall Agent sebelum digunakan.",
            7000 + (packageName.hashCode().absoluteValue % 1000),
        )
    }

    private fun profileKey(profile: String): String {
        return profile
            .lowercase(Locale.ROOT)
            .replace(Regex("[^a-z0-9._-]"), "_")
            .ifBlank { "default" }
    }
}
