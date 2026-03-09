package com.mrksvt.firewallagent.xposed

import com.mrksvt.firewallagent.AdMlScorer
import java.net.IDN
import java.net.URI
import java.util.Locale
import java.util.concurrent.ConcurrentHashMap

enum class DecisionAction {
    ALLOW,
    BLOCK,
    CHALLENGE,
}

data class DecisionResult(
    val action: DecisionAction,
    val reason: String,
)

class RequestDecisionEngine(
    private val strictPackages: Set<String>,
    private val browserGuardPackages: Set<String>,
    private val officialTrustedHosts: Set<String>,
    private val officialPackageHosts: Map<String, Set<String>>,
    private val highRiskKeywordSet: Set<String>,
    private val knownMalwareHosts: Set<String>,
    private val adPatternProvider: () -> List<String>,
    private val externalBlockedHostProvider: () -> Set<String> = { emptySet() },
) {
    private val decisionCache = ConcurrentHashMap<String, DecisionResult>()

    fun evaluateNetwork(
        pkg: String,
        urlString: String,
        method: String = "UNKNOWN",
        mime: String = "",
        referrer: String = "",
        isDownload: Boolean = false,
    ): DecisionResult {
        val urlLower = urlString.lowercase(Locale.US)
        val host = parseHost(urlString)
        val hostLower = normalizeHost(host)
        val scheme = parseScheme(urlString)
        val path = parsePath(urlString)
        val strict = strictPackages.contains(pkg)
        val browserGuard = browserGuardPackages.contains(pkg)
        if (!strict && !browserGuard) return DecisionResult(DecisionAction.ALLOW, "out-of-scope")

        val cacheKey = listOf(
            "net",
            pkg,
            hostLower,
            path.take(80),
            scheme,
            method.uppercase(Locale.US),
            mime.lowercase(Locale.US),
            if (isDownload) "1" else "0",
        ).joinToString("|")
        decisionCache[cacheKey]?.let { return it }

        val decision = when {
            scheme == "market" || scheme == "intent" -> DecisionResult(DecisionAction.BLOCK, "scheme-external")
            (strict || browserGuard) && isTrustedHostAdEndpoint(urlLower, hostLower) ->
                DecisionResult(DecisionAction.BLOCK, "trusted-host-ad-endpoint")
            browserGuard && isFeedBlockedHost(hostLower) -> DecisionResult(DecisionAction.BLOCK, "browser-feed-block")
            browserGuard && looksLikeSuspiciousCampaignHost(hostLower) -> DecisionResult(DecisionAction.BLOCK, "browser-suspicious-campaign-host")
            browserGuard && looksLikeMalwareDownload(urlLower, hostLower, mime) -> DecisionResult(DecisionAction.BLOCK, "browser-malware-download")
            browserGuard && scoreAsRisky(urlLower, hostLower, referrer) -> DecisionResult(DecisionAction.BLOCK, "ml-score-threshold")
            browserGuard && (isAdOrFraudUrl(urlLower, hostLower) || containsRiskKeywords("$urlLower $hostLower")) ->
                DecisionResult(DecisionAction.BLOCK, "ml-anomaly-host")
            strict && isFeedBlockedHost(hostLower) -> DecisionResult(DecisionAction.BLOCK, "external-blacklist-feed")
            strict && looksLikeMalwareDownload(urlLower, hostLower, mime) -> DecisionResult(DecisionAction.BLOCK, "strict-malware-download")
            strict && isAdOrFraudUrl(urlLower, hostLower) -> DecisionResult(DecisionAction.BLOCK, "ml-anomaly-host")
            strict && !isAllowlistedHost(pkg, hostLower) -> DecisionResult(DecisionAction.BLOCK, "strict-deny-default-non-allowlist")
            strict && scoreAsRisky(urlLower, hostLower, referrer) -> DecisionResult(DecisionAction.BLOCK, "ml-score-threshold")
            else -> DecisionResult(DecisionAction.ALLOW, "allowlisted")
        }

        rememberDecision(cacheKey, decision)
        return decision
    }

    fun evaluateIntent(
        pkg: String,
        action: String,
        dataString: String,
        targetPackage: String,
        mime: String = "",
    ): DecisionResult {
        val strict = strictPackages.contains(pkg)
        val browserGuard = browserGuardPackages.contains(pkg)
        if (!strict && !browserGuard) return DecisionResult(DecisionAction.ALLOW, "out-of-scope")
        val lowerAction = action.lowercase(Locale.US)
        val lowerData = dataString.lowercase(Locale.US)
        val hostLower = normalizeHost(parseHost(dataString))
        val scheme = parseScheme(dataString)
        val targetLower = targetPackage.lowercase(Locale.US)
        val hasWebPayload = lowerData.contains("http://") || lowerData.contains("https://") || lowerData.contains("intent://") || lowerData.contains("market://")

        if (looksLikeExternalTarget(targetLower) && (hasWebPayload || targetLower.isNotBlank())) {
            return DecisionResult(DecisionAction.BLOCK, "external-target-launch=$targetLower")
        }

        if (lowerAction == "android.intent.action.view" || lowerAction == "android.intent.action.send" || lowerAction == "android.intent.action.send_multiple") {
            if (scheme == "market" || scheme == "intent") return DecisionResult(DecisionAction.BLOCK, "external-jump-scheme")
            if (strict && scheme.isNotBlank() && scheme !in setOf("http", "https", "content", "file", "android-app")) {
                return DecisionResult(DecisionAction.BLOCK, "external-jump-custom-scheme")
            }
            if (isTrustedHostAdEndpoint(lowerData, hostLower)) return DecisionResult(DecisionAction.BLOCK, "external-jump-trusted-host-ad-endpoint")
            if (looksLikeExternalTarget(targetLower)) return DecisionResult(DecisionAction.BLOCK, "external-jump-target=$targetLower")
            if (isFeedBlockedHost(hostLower)) return DecisionResult(DecisionAction.BLOCK, "external-jump-feed-block")
            if (looksLikeSuspiciousCampaignHost(hostLower)) return DecisionResult(DecisionAction.BLOCK, "external-jump-suspicious-host")
            if (looksLikeMalwareDownload(lowerData, hostLower, mime)) return DecisionResult(DecisionAction.BLOCK, "external-jump-malware-download")
            if (isAdOrFraudUrl(lowerData, hostLower)) return DecisionResult(DecisionAction.BLOCK, "ml-anomaly-host")
            if (strict && !isAllowlistedHost(pkg, hostLower) && (scheme == "http" || scheme == "https" || scheme == "content" || scheme == "file")) {
                return DecisionResult(DecisionAction.BLOCK, "external-jump-non-allowlist")
            }
            if (strict && targetLower.isNotBlank() && targetLower != pkg.lowercase(Locale.US)) {
                return DecisionResult(DecisionAction.BLOCK, "cross-app-jump")
            }
        }

        return DecisionResult(DecisionAction.ALLOW, "allow-intent")
    }

    private fun looksLikeExternalTarget(targetLower: String): Boolean {
        if (targetLower.isBlank()) return false
        return targetLower.contains("chrome") ||
            targetLower.contains("browser") ||
            targetLower == "com.android.vending" ||
            targetLower.contains("packageinstaller") ||
            targetLower.contains("documentsui") ||
            targetLower.contains("downloads") ||
            targetLower.contains("installer")
    }

    private fun scoreAsRisky(urlLower: String, hostLower: String, referrer: String): Boolean {
        val hostScore = if (hostLower.isBlank()) 0.0 else AdMlScorer.scoreHost(hostLower)
        val urlScore = AdMlScorer.scoreUrl(urlLower)
        val score = maxOf(hostScore, urlScore)
        if (score >= 1.0) return true
        val signal = "$urlLower $hostLower ${referrer.lowercase(Locale.US)}"
        val lexicalScore = listOf("redirect", "click", "install", "download", "casino", "porn", "slot")
            .count { signal.contains(it) }
        return lexicalScore >= 2
    }

    private fun isAllowlistedHost(pkg: String, hostLower: String): Boolean {
        if (hostLower.isBlank()) return false
        if (isOfficialHost(hostLower)) return true
        val pkgHosts = officialPackageHosts[pkg].orEmpty()
        if (pkgHosts.any { hostLower == it || hostLower.endsWith(".$it") }) return true
        return inferPackageOwnedHost(pkg, hostLower)
    }

    private fun inferPackageOwnedHost(pkg: String, hostLower: String): Boolean {
        val tokens = pkg.lowercase(Locale.US).split('.').filter { it.length >= 4 && it !in setOf("com", "android", "app", "apk") }
        if (tokens.isEmpty()) return false
        return tokens.any { token -> hostLower.contains(token) }
    }

    private fun isOfficialHost(hostLower: String): Boolean {
        return officialTrustedHosts.any { hostLower == it || hostLower.endsWith(".$it") }
    }

    private fun isAdOrFraudUrl(urlLower: String, hostLower: String): Boolean {
        if (urlLower.isBlank()) return false
        if (isFeedBlockedHost(hostLower)) return true
        if (looksLikeSuspiciousCampaignHost(hostLower)) return true
        if (hasAdMarkers(urlLower)) return true
        if (containsRiskKeywords("$urlLower $hostLower")) return true
        val adPatterns = adPatternProvider()
        if (adPatterns.any { pattern -> hostLower == pattern || hostLower.contains(pattern) || urlLower.contains(pattern) }) return true
        if (urlLower.contains("ad_group_id=") || urlLower.contains("creative_id=") || urlLower.contains("auction_id=")) return true
        if (urlLower.contains("impression-") || urlLower.contains("beacon") || urlLower.contains("clickid") || urlLower.contains("utm_")) return true
        if (urlLower.contains("play.google.com/store/apps") || urlLower.contains("market://details")) return true
        return false
    }

    private fun looksLikeSuspiciousCampaignHost(hostLower: String): Boolean {
        if (hostLower.isBlank()) return false
        if (hostLower.contains("plx193.") || hostLower.contains("77rpfhk425.") || hostLower.contains("ppv99b.") || hostLower.contains("qifei")) return true
        if (hostLower.contains("-rp.") || hostLower.contains(".rp-")) return true
        return Regex("""(^|[.])\d{2,4}rp[a-z0-9-]*[.]""").containsMatchIn(hostLower)
    }

    private fun hasAdMarkers(urlLower: String): Boolean {
        return urlLower.contains("/mintegral/") ||
            urlLower.contains("/event/vast/") ||
            urlLower.contains("liftoff") ||
            urlLower.contains("adexp") ||
            urlLower.contains("doubleclick") ||
            urlLower.contains("pagead/adview") ||
            urlLower.contains("adnw_sync")
    }

    private fun isTrustedHostAdEndpoint(urlLower: String, hostLower: String): Boolean {
        if (hostLower.isBlank() || urlLower.isBlank()) return false
        if (hostLower.contains("googleadservices.com") || hostLower.contains("doubleclick.net")) return true
        if (hostLower.endsWith(".facebook.com") || hostLower == "facebook.com") {
            if (urlLower.contains("/adnw") || urlLower.contains("adnw_sync")) return true
        }
        if (hostLower == "graph.facebook.com" || hostLower.endsWith(".graph.facebook.com")) {
            if (urlLower.contains("/app/mobile_sdk_gk") || urlLower.contains("/app/model_asset")) return true
        }
        return false
    }

    private fun looksLikeMalwareDownload(urlLower: String, hostLower: String, mime: String): Boolean {
        val normalizedMime = mime.lowercase(Locale.US)
        val apkLike = urlLower.contains(".apk") ||
            urlLower.contains("download") ||
            urlLower.contains("install") ||
            normalizedMime.contains("application/vnd.android.package-archive")
        val knownHost = knownMalwareHosts.any { hostLower == it || hostLower.endsWith(".$it") || hostLower.contains(it) }
        return knownHost || (apkLike && containsRiskKeywords("$urlLower $hostLower"))
    }

    private fun containsRiskKeywords(text: String): Boolean {
        val lower = text.lowercase(Locale.US)
        return highRiskKeywordSet.any { lower.contains(it) }
    }

    private fun isFeedBlockedHost(hostLower: String): Boolean {
        if (hostLower.isBlank()) return false
        val feed = externalBlockedHostProvider()
        if (feed.isEmpty()) return false
        var candidate = hostLower
        while (true) {
            if (feed.contains(candidate)) return true
            val dot = candidate.indexOf('.')
            if (dot <= 0 || dot >= candidate.length - 1) return false
            candidate = candidate.substring(dot + 1)
        }
    }

    private fun parseHost(raw: String): String {
        if (raw.isBlank()) return ""
        return runCatching { URI(raw).host.orEmpty() }
            .getOrDefault("")
    }

    private fun parseScheme(raw: String): String {
        if (raw.isBlank()) return ""
        return runCatching { URI(raw).scheme.orEmpty().lowercase(Locale.US) }
            .getOrDefault("")
    }

    private fun parsePath(raw: String): String {
        if (raw.isBlank()) return ""
        return runCatching { URI(raw).path.orEmpty().lowercase(Locale.US) }
            .getOrDefault("")
    }

    private fun normalizeHost(host: String): String {
        if (host.isBlank()) return ""
        return runCatching {
            IDN.toASCII(host.trim().trim('.').lowercase(Locale.US), IDN.ALLOW_UNASSIGNED)
                .trim()
                .trim('.')
                .lowercase(Locale.US)
        }.getOrDefault(host.trim().trim('.').lowercase(Locale.US))
    }

    private fun rememberDecision(cacheKey: String, decision: DecisionResult) {
        if (decisionCache.size > 5000) decisionCache.clear()
        decisionCache[cacheKey] = decision
    }
}
