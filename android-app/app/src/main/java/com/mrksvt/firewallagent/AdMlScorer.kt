package com.mrksvt.firewallagent

import android.content.Context
import org.json.JSONArray
import java.net.URI
import java.util.Locale

object AdMlScorer {
    private const val PREF = "adguard_dns"
    private const val KEY_DYNAMIC = "ml_ad_patterns_json"

    private val tokenWeights = mapOf(
        "ad" to 0.8,
        "ads" to 1.1,
        "advert" to 1.0,
        "doubleclick" to 2.0,
        "googlesyndication" to 2.0,
        "googleads" to 2.2,
        "adservice" to 1.7,
        "admob" to 2.0,
        "unityads" to 2.0,
        "applovin" to 2.0,
        "ironsource" to 2.0,
        "startapp" to 1.8,
        "inmobi" to 1.8,
        "vungle" to 1.8,
        "chartboost" to 1.8,
        "criteo" to 1.8,
        "adnxs" to 1.7,
        "tracking" to 1.2,
        "tracker" to 1.2,
        "analytics" to 0.6,
        "measure" to 0.6,
        "sdk" to 0.3,
        "native" to 0.2,
    )

    fun loadDynamicPatterns(context: Context): List<String> {
        val raw = context.getSharedPreferences(PREF, Context.MODE_PRIVATE)
            .getString(KEY_DYNAMIC, "[]")
            .orEmpty()
        return runCatching {
            val arr = JSONArray(raw)
            buildList {
                for (i in 0 until arr.length()) {
                    val s = arr.optString(i).trim().lowercase(Locale.ROOT)
                    if (s.isNotBlank()) add(s)
                }
            }
        }.getOrDefault(emptyList())
    }

    fun saveDynamicPatterns(context: Context, patterns: List<String>) {
        val arr = JSONArray()
        patterns.distinct().forEach { arr.put(it) }
        context.getSharedPreferences(PREF, Context.MODE_PRIVATE)
            .edit()
            .putString(KEY_DYNAMIC, arr.toString())
            .apply()
    }

    fun extractHostsFromHybridLog(raw: String): List<String> {
        val out = linkedSetOf<String>()
        val regex = Regex("""https?://([A-Za-z0-9._-]+)""")
        regex.findAll(raw).forEach { m ->
            val host = m.groupValues.getOrNull(1).orEmpty()
                .trim()
                .lowercase(Locale.ROOT)
                .removePrefix("www.")
            if (host.isNotBlank()) out += host
        }
        raw.lines().forEach { line ->
            if (!line.contains("FA.HybridAdHook")) return@forEach
            val idx = when {
                line.contains("blocked") -> line.indexOf("blocked")
                line.contains("intercepted request") -> line.indexOf("intercepted request")
                else -> -1
            }
            if (idx < 0) return@forEach
            val part = line.substring(idx)
            val host = runCatching {
                val maybeUrl = part.substringAfter(": ", "")
                if (maybeUrl.startsWith("http://") || maybeUrl.startsWith("https://")) {
                    URI(maybeUrl).host.orEmpty()
                } else {
                    ""
                }
            }.getOrDefault("").lowercase(Locale.ROOT).removePrefix("www.")
            if (host.isNotBlank()) out += host
        }
        return out.toList()
    }

    fun scoreHost(host: String): Double {
        if (host.isBlank()) return 0.0
        val h = host.lowercase(Locale.ROOT)
        val tokens = h.split(Regex("[^a-z0-9]+")).filter { it.isNotBlank() }
        var score = 0.0
        tokens.forEach { t ->
            score += tokenWeights[t] ?: 0.0
            tokenWeights.entries.firstOrNull { t.contains(it.key) && it.key.length >= 4 }?.let { score += it.value * 0.35 }
        }
        if (h.startsWith("ad.") || h.startsWith("ads.")) score += 1.0
        if (h.contains(".ad.")) score += 0.8
        if (h.contains("doubleclick") || h.contains("googlesyndication")) score += 1.2
        if (h.contains("googleads")) score += 1.0
        if (h.length in 12..28) score += 0.2
        return score
    }

    fun buildMlPatterns(staticPatterns: List<String>, hybridLogRaw: String, maxDynamic: Int = 40): List<String> {
        val candidates = extractHostsFromHybridLog(hybridLogRaw)
        if (candidates.isEmpty()) return emptyList()
        val staticSet = staticPatterns.map { it.lowercase(Locale.ROOT) }.toSet()
        val scored = candidates
            .map { it.lowercase(Locale.ROOT) }
            .distinct()
            .map { host -> host to scoreHost(host) }
            .filter { (_, s) -> s >= 1.5 }
            .sortedByDescending { it.second }

        val dynamic = linkedSetOf<String>()
        for ((host, _) in scored) {
            dynamic += host
            val secondLevel = host.substringAfter('.').takeIf { it.contains('.') } ?: host
            if (secondLevel.length > 6) dynamic += secondLevel
            if (dynamic.size >= maxDynamic) break
        }
        return dynamic
            .map { it.trim() }
            .filter { it.isNotBlank() && it !in staticSet && it.length <= 80 }
            .take(maxDynamic)
    }

    fun mergePatterns(staticPatterns: List<String>, dynamicPatterns: List<String>): List<String> {
        val merged = LinkedHashSet<String>()
        staticPatterns.forEach { if (it.isNotBlank()) merged += it.trim().lowercase(Locale.ROOT) }
        dynamicPatterns.forEach { if (it.isNotBlank()) merged += it.trim().lowercase(Locale.ROOT) }
        return merged.toList()
    }
}
