package com.mrksvt.firewallagent

import android.content.Context
import org.json.JSONArray
import org.json.JSONObject
import java.util.Locale

/**
 * Stores and manages the DNS bypass whitelist — apps that are allowed to bypass
 * the Private DNS lock (FA_DNS iptables chain) so they can still reach the internet,
 * while the Xposed hook still intercepts and nullifies their ad SDK calls.
 *
 * This is the critical piece that lets apps "work" without Private DNS being visible
 * to them, while still protecting the user from ads/gambling/porn domains.
 */
object DnsBypassStore {
    private const val PREF = "dns_bypass_store"
    private const val KEY_BYPASS_JSON = "bypass_packages_json"
    private const val KEY_BYPASS_UIDS = "bypass_uids_csv"
    private const val KEY_BYPASS_MODE = "bypass_mode" // "off" | "selective" | "all_non_system"

    fun loadBypassPackages(context: Context): Set<String> {
        val raw = context.getSharedPreferences(PREF, Context.MODE_PRIVATE)
            .getString(KEY_BYPASS_JSON, "[]")
            .orEmpty()
        return runCatching {
            val arr = JSONArray(raw)
            buildSet {
                for (i in 0 until arr.length()) {
                    val s = arr.optString(i).trim()
                    if (s.isNotBlank()) add(s)
                }
            }
        }.getOrDefault(emptySet())
    }

    fun saveBypassPackages(context: Context, packages: Set<String>) {
        val arr = JSONArray()
        packages.forEach { arr.put(it) }
        context.getSharedPreferences(PREF, Context.MODE_PRIVATE)
            .edit()
            .putString(KEY_BYPASS_JSON, arr.toString())
            .apply()
        // Sync UIDs from current inventory
        syncBypassUids(context, packages)
    }

    fun addBypassPackage(context: Context, pkg: String) {
        val current = loadBypassPackages(context).toMutableSet()
        current += pkg.trim()
        saveBypassPackages(context, current)
    }

    fun removeBypassPackage(context: Context, pkg: String) {
        val current = loadBypassPackages(context).toMutableSet()
        current -= pkg.trim()
        saveBypassPackages(context, current)
    }

    fun isPackageBypassed(context: Context, pkg: String): Boolean =
        pkg in loadBypassPackages(context)

    fun loadBypassUids(context: Context): Set<Int> {
        val csv = context.getSharedPreferences(PREF, Context.MODE_PRIVATE)
            .getString(KEY_BYPASS_UIDS, "")
            .orEmpty()
        return csv.split(',')
            .mapNotNull { it.trim().toIntOrNull() }
            .filter { it > 0 }
            .toSet()
    }

    fun syncBypassUids(context: Context, packages: Set<String> = loadBypassPackages(context)) {
        val inventory = AppInventoryStore.read(context)
        val uids = packages
            .mapNotNull { pkg -> inventory[pkg] }
            .filter { it > 0 }
            .toSet()
        context.getSharedPreferences(PREF, Context.MODE_PRIVATE)
            .edit()
            .putString(KEY_BYPASS_UIDS, uids.joinToString(","))
            .apply()
    }

    fun getBypassMode(context: Context): String =
        context.getSharedPreferences(PREF, Context.MODE_PRIVATE)
            .getString(KEY_BYPASS_MODE, "selective")
            .orEmpty()

    fun setBypassMode(context: Context, mode: String) {
        context.getSharedPreferences(PREF, Context.MODE_PRIVATE)
            .edit()
            .putString(KEY_BYPASS_MODE, mode)
            .apply()
    }

    /**
     * Builds the iptables FA_DNS exemption rules for bypassed UIDs.
     * These apps' DNS traffic will be allowed to flow through even when FA_DNS lock is on.
     * The apps still get Private DNS (AdGuard/etc.), but DNS lock won't block their plaintext
     * fallback probes that cause "no network" false positives.
     */
    fun buildBypassExemptionScript(context: Context): String {
        val uids = loadBypassUids(context)
        if (uids.isEmpty()) return ""
        return buildString {
            uids.forEach { uid ->
                // Allow DNS traffic for bypassed UIDs (before the general block rules)
                append("iptables -I FA_DNS 1 -m owner --uid-owner $uid -j RETURN > /dev/null 2>&1 || true;")
            }
        }
    }

    /**
     * Returns a summary JSON for UI display.
     */
    fun statusJson(context: Context): JSONObject {
        val packages = loadBypassPackages(context)
        val uids = loadBypassUids(context)
        val mode = getBypassMode(context)
        return JSONObject()
            .put("mode", mode)
            .put("bypass_package_count", packages.size)
            .put("bypass_uid_count", uids.size)
            .put("packages", JSONArray(packages.toList()))
            .put("uids", JSONArray(uids.toList()))
    }
}
