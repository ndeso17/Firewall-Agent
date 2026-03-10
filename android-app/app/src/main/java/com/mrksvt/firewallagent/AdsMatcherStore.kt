package com.mrksvt.firewallagent

import android.content.Context
import org.json.JSONArray
import java.net.IDN
import java.util.Locale

object AdsMatcherStore {
    private const val PREF = "adguard_dns"
    private const val KEY_BLACKLIST = "ads_matcher_blacklist_json"
    private const val KEY_WHITELIST = "ads_matcher_whitelist_json"

    fun loadBlacklist(context: Context): Set<String> = loadSet(context, KEY_BLACKLIST)

    fun saveBlacklist(context: Context, values: Set<String>) = saveSet(context, KEY_BLACKLIST, values)

    fun loadWhitelist(context: Context): Set<String> = loadSet(context, KEY_WHITELIST)

    fun saveWhitelist(context: Context, values: Set<String>) = saveSet(context, KEY_WHITELIST, values)

    fun mergeBlockedPatterns(
        base: List<String>,
        dynamic: List<String>,
        blacklist: Set<String>,
        external: List<String>,
        whitelist: Set<String>,
    ): List<String> {
        val merged = AdMlScorer.mergePatterns(
            AdMlScorer.mergePatterns(
                AdMlScorer.mergePatterns(base, dynamic),
                blacklist.toList(),
            ),
            external,
        )
        return merged.filterNot { pattern -> isWhitelisted(pattern, whitelist) }
    }

    private fun loadSet(context: Context, key: String): Set<String> {
        val raw = context.getSharedPreferences(PREF, Context.MODE_PRIVATE)
            .getString(key, "[]")
            .orEmpty()
        return runCatching {
            val arr = JSONArray(raw)
            buildSet {
                for (i in 0 until arr.length()) {
                    val v = normalize(arr.optString(i))
                    if (v.isNotBlank()) add(v)
                }
            }
        }.getOrDefault(emptySet())
    }

    private fun saveSet(context: Context, key: String, values: Set<String>) {
        val arr = JSONArray()
        values.asSequence()
            .map { normalize(it) }
            .filter { it.isNotBlank() }
            .distinct()
            .forEach { arr.put(it) }
        context.getSharedPreferences(PREF, Context.MODE_PRIVATE)
            .edit()
            .putString(key, arr.toString())
            .apply()
    }

    private fun isWhitelisted(pattern: String, whitelist: Set<String>): Boolean {
        val normalized = normalize(pattern)
        if (normalized.isBlank()) return false
        return whitelist.any { allowed ->
            normalized == allowed ||
                normalized.endsWith(".$allowed") ||
                allowed in normalized
        }
    }

    fun normalize(raw: String): String {
        val cleaned = raw.trim()
            .lowercase(Locale.ROOT)
            .removePrefix("http://")
            .removePrefix("https://")
            .removePrefix("www.")
            .removePrefix("*.")
            .removePrefix(".")
            .trim('/')
            .trim('.')
        if (cleaned.isBlank()) return ""
        return runCatching { IDN.toASCII(cleaned) }.getOrDefault(cleaned)
    }
}
