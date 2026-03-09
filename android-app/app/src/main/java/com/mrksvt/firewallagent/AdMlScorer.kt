package com.mrksvt.firewallagent

import android.content.Context
import org.json.JSONArray
import java.net.URI
import java.util.Locale
import kotlin.math.abs
import kotlin.math.ln
import kotlin.math.max
import kotlin.math.min

object AdMlScorer {
    private const val PREF = "adguard_dns"
    private const val KEY_DYNAMIC = "ml_ad_patterns_json"
    private const val KEY_USER = "user_ad_patterns_json"
    private const val ML_MIN_SAMPLES = 10
    private const val ML_THRESHOLD = 0.58
    private const val ML_FALLBACK_THRESHOLD = 1.5
    private const val ML_MAX_TOKENS_PER_HOST = 10

    private val tokenWeights = mapOf(
        "ad" to 0.8,
        "ads" to 1.1,
        "advert" to 1.0,
        "doubleclick" to 2.0,
        "googlesyndication" to 2.0,
        "googleads" to 2.2,
        "pagead" to 2.2,
        "adnw" to 2.1,
        "adnw_sync2" to 2.4,
        "adx" to 1.8,
        "omsdk" to 2.3,
        "mraid" to 1.6,
        "vast" to 1.4,
        "beacon" to 1.3,
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
        "casino" to 2.4,
        "judi" to 2.4,
        "slot" to 2.2,
        "bet" to 1.8,
        "poker" to 1.8,
        "roulette" to 1.8,
        "porn" to 2.2,
        "adult" to 1.6,
        "xxx" to 2.0,
        "redirect" to 1.2,
        "click" to 1.0,
        "campaign" to 1.0,
    )
    private val suspiciousTlds = setOf("xyz", "top", "click", "shop", "live", "sbs", "cam", "fun", "pics", "monster")

    private data class LabelSample(val host: String, val blocked: Boolean)

    private data class HostTokenStats(var blocked: Int = 0, var safe: Int = 0)

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
        ensurePrefsReadable(context)
    }

    fun loadUserPatterns(context: Context): List<String> {
        val raw = context.getSharedPreferences(PREF, Context.MODE_PRIVATE)
            .getString(KEY_USER, "[]")
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

    fun saveUserPatterns(context: Context, patterns: List<String>) {
        val arr = JSONArray()
        patterns.distinct().forEach { arr.put(it) }
        context.getSharedPreferences(PREF, Context.MODE_PRIVATE)
            .edit()
            .putString(KEY_USER, arr.toString())
            .apply()
        ensurePrefsReadable(context)
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

    private fun parseLabeledSignals(raw: String): List<LabelSample> {
        if (raw.isBlank()) return emptyList()
        return raw
            .lineSequence()
            .mapNotNull { line ->
                val lower = line.lowercase(Locale.ROOT)
                val blocked = when {
                    lower.contains("fa.hybridadhook") && (
                        lower.contains(" net blocked") ||
                            lower.contains(" blocked") ||
                            lower.contains("intercepted request")
                    ) -> true
                    lower.contains("fa.hybridadhook net observe ") -> false
                    else -> return@mapNotNull null
                }
                val host = extractHostFromLine(line)
                if (host.isBlank()) return@mapNotNull null
                LabelSample(host, blocked)
            }
            .filter { it.host.isNotBlank() && it.host != "-" }
            .toList()
    }

    private fun extractHostFromLine(line: String): String {
        Regex("""\bhost=([A-Za-z0-9._-]+)""").find(line)?.groupValues?.getOrNull(1)?.let { return it.lowercase(Locale.ROOT).removePrefix("www.") }
        Regex("""https?://([A-Za-z0-9._-]+)""").find(line)?.groupValues?.getOrNull(1)?.let {
            return it.lowercase(Locale.ROOT).removePrefix("www.")
        }
        Regex("""\b(?:for|to)\s+([A-Za-z0-9._-]+)\s+in\b""").find(line)?.groupValues?.getOrNull(1)?.let {
            return it.lowercase(Locale.ROOT).removePrefix("www.")
        }
        return ""
    }

    private fun extractHostTokens(host: String): List<String> {
        if (host.isBlank()) return emptyList()
        val normalized = host.lowercase(Locale.ROOT).removePrefix("www.")
        val tokens = mutableSetOf<String>()
        tokens += normalized
        tokens += normalized.split('.', '-', '_').filter { it.length >= 3 }
        val parts = normalized.split('.')
        if (parts.size >= 2) {
            tokens += parts.takeLast(2).joinToString(".")
            tokens += parts.takeLast(3).filter { it.length >= 3 }.joinToString(".")
        }
        if (parts.size >= 3 && parts[0].length >= 3) {
            tokens += parts[0]
        }
        tokens += normalized.substringAfter('.', "")
            .substringBefore(".")
            .takeIf { it.isNotBlank() && it.length >= 4 }
            .orEmpty()
            .let { if (it.isBlank()) emptySet<String>() else setOf(it, "sld:$it") }
        return tokens
            .filter { it.isNotBlank() && it.length <= 48 }
            .distinct()
            .take(ML_MAX_TOKENS_PER_HOST)
    }

    private fun buildTokenModel(samples: List<LabelSample>): Map<String, Double> {
        if (samples.isEmpty()) return emptyMap()
        val tokenStats = hashMapOf<String, HostTokenStats>()
        var blockedCount = 0
        var safeCount = 0
        for (sample in samples) {
            if (sample.blocked) blockedCount++ else safeCount++
            extractHostTokens(sample.host).forEach { token ->
                val s = tokenStats.getOrPut(token) { HostTokenStats() }
                if (sample.blocked) s.blocked++ else s.safe++
            }
        }
        if (safeCount < 1) {
            return emptyMap()
        }
        val prior = ln((blockedCount + 1.0) / (safeCount + 1.0))
        val out = hashMapMap()
        tokenStats.forEach { (token, stat) ->
            val score = ln((stat.blocked + 1.0) / (stat.safe + 1.0))
            if (abs(score) > 0.05) out[token] = score
        }
        out["__bias__"] = prior
        return out
    }

    private fun hashMapMap(): HashMap<String, Double> = hashMapOf<String, Double>()

    private fun classifyHost(host: String, model: Map<String, Double>): Double {
        if (model.isEmpty()) return 0.0
        val normalized = host.lowercase(Locale.ROOT).removePrefix("www.")
        var z = model["__bias__"] ?: -2.5
        extractHostTokens(normalized).forEach { token ->
            z += model[token] ?: 0.0
        }
        z += max(0.0, scoreHost(normalized) * 0.25)
        return 1.0 / (1.0 + (-z).let { min(40.0, max(-40.0, it)) }.let { kotlin.math.exp(it) })
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
        if (h.contains("xn--")) score += 1.1
        if (h.contains("qifei")) score += 2.4
        if (Regex("""(^|[.])\d{2,4}rp[a-z0-9-]*[.]""").containsMatchIn(h)) score += 2.6
        if (Regex("""(^|[.])[a-z]{2,8}\d{2,6}[.]""").containsMatchIn(h)) score += 1.2
        val tld = h.substringAfterLast('.', "")
        if (suspiciousTlds.contains(tld)) score += 0.9
        val digits = h.count { it.isDigit() }
        val letters = h.count { it.isLetter() }
        val total = max(1, digits + letters)
        val digitRatio = digits.toDouble() / total.toDouble()
        if (digitRatio >= 0.22) score += 0.9
        val entropy = shannonEntropy(h.filter { it.isLetterOrDigit() })
        if (entropy >= 3.65) score += 0.8
        if (h.length in 12..28) score += 0.2
        return score
    }

    fun scoreUrl(url: String): Double {
        if (url.isBlank()) return 0.0
        val lower = url.lowercase(Locale.ROOT)
        val host = runCatching { URI(url).host.orEmpty() }.getOrDefault("")
        var score = scoreHost(host)
        if (lower.contains("intent://") || lower.contains("market://")) score += 1.8
        if (lower.contains("redirect=") || lower.contains("target_url=") || lower.contains("browser_fallback_url=")) score += 1.4
        if (lower.contains("pagead") || lower.contains("adview") || lower.contains("adnw_sync2")) score += 2.4
        if (lower.contains("doubleclick") || lower.contains("googleads") || lower.contains("adx")) score += 1.8
        if (lower.contains("omsdk") || lower.contains("mraid") || lower.contains("vast") || lower.contains("beacon")) score += 1.6
        if (lower.contains("p1=") && lower.contains("p2=") && lower.contains("p3=")) score += 1.5
        if (lower.contains("adset") || lower.contains("adid") || lower.contains("cmpn")) score += 1.2
        if (lower.contains("callback")) score += 1.1
        if (lower.contains("utm_") || lower.contains("clickid") || lower.contains("fbclid") || lower.contains("gclid")) score += 0.9
        if (lower.contains("casino") || lower.contains("judi") || lower.contains("slot") || lower.contains("bet")) score += 2.0
        if (lower.length > 140) score += 0.5
        return score
    }

    private fun shannonEntropy(value: String): Double {
        if (value.isBlank()) return 0.0
        val n = value.length.toDouble()
        if (n <= 1.0) return 0.0
        val freq = HashMap<Char, Int>()
        value.forEach { c -> freq[c] = (freq[c] ?: 0) + 1 }
        var entropy = 0.0
        freq.values.forEach { count ->
            val p = count / n
            entropy -= p * ln(p)
        }
        return entropy
    }

    fun buildMlPatterns(
        staticPatterns: List<String>,
        hybridLogRaw: String,
        maxDynamic: Int = 40,
        minScore: Double = ML_THRESHOLD,
    ): List<String> {
        val candidates = extractHostsFromHybridLog(hybridLogRaw)
        if (candidates.isEmpty()) return emptyList()
        val staticSet = staticPatterns.map { it.lowercase(Locale.ROOT) }.toSet()
        val labeled = parseLabeledSignals(hybridLogRaw)
        val model = buildTokenModel(labeled)

        val scored = candidates
            .map { it.lowercase(Locale.ROOT) }
            .distinct()
            .map { host ->
                val base = scoreHost(host)
                val boosted = if (labeled.size >= ML_MIN_SAMPLES) classifyHost(host, model) else 0.0
                val score = if (labeled.size >= ML_MIN_SAMPLES) (0.4 * base + 2.8 * boosted) else base
                Triple(host, base, score)
            }
            .filter { (_, base, _) ->
                if (labeled.size >= ML_MIN_SAMPLES) base >= 0.3 else base >= ML_FALLBACK_THRESHOLD
            }
            .map { (host, base, mlScore) ->
                val isAdLike = if (labeled.size >= ML_MIN_SAMPLES) mlScore >= minScore else base >= ML_FALLBACK_THRESHOLD
                Triple(host, base, mlScore)
                    .takeIf { isAdLike }
                    ?.let { host to mlScore }
            }
            .filterNotNull()
            .sortedByDescending { it.second }

        val dynamic = linkedSetOf<String>()
        scored.forEach { (host, score) ->
            dynamic += host
            if (score > 0.95) {
                val secondLevel = host.substringAfter('.').takeIf { it.contains('.') } ?: host
                if (secondLevel.length > 6) dynamic += secondLevel
            }
            if (dynamic.size >= maxDynamic) return@forEach
        }

        return dynamic
            .map { it.trim() }
            .filter { it.isNotBlank() && it !in staticSet && it.length <= 80 }
            .take(maxDynamic)
    }

    fun buildMlPatternsFromEvents(
        context: Context,
        staticPatterns: List<String>,
        maxDynamic: Int = 40,
        minScore: Double = ML_THRESHOLD,
    ): List<String> {
        val persistedEvents = AdEventStore.loadEvents(context)
            .filter { it.host.isNotBlank() && (it.status == "blocked" || it.status == "observe" || it.status == "faked") }
            .joinToString("\n") { event ->
                val statusToken = when (event.status) {
                    "observe" -> "net observe"
                    "faked" -> "faked"
                    else -> "net blocked"
                }
                "FA.HybridAdHook $statusToken host=${event.host} in ${event.packageName}"
            }
        return buildMlPatterns(
            staticPatterns = staticPatterns,
            hybridLogRaw = persistedEvents,
            maxDynamic = maxDynamic,
            minScore = minScore,
        )
    }

    fun mergePatterns(staticPatterns: List<String>, dynamicPatterns: List<String>): List<String> {
        val merged = LinkedHashSet<String>()
        staticPatterns.forEach { if (it.isNotBlank()) merged += it.trim().lowercase(Locale.ROOT) }
        dynamicPatterns.forEach { if (it.isNotBlank()) merged += it.trim().lowercase(Locale.ROOT) }
        return merged.toList()
    }

    private fun ensurePrefsReadable(context: Context) {
        runCatching {
            val prefDir = java.io.File(context.applicationInfo.dataDir, "shared_prefs")
            val prefFile = java.io.File(prefDir, "$PREF.xml")
            prefDir.setReadable(true, false)
            prefDir.setExecutable(true, false)
            prefFile.setReadable(true, false)
        }
    }
}
