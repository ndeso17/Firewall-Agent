package com.mrksvt.firewallagent

import android.content.Context
import android.util.Log
import java.net.HttpURLConnection
import java.net.IDN
import java.net.URL
import java.util.Locale

object BlacklistFeedSync {
    private const val PREF = "adguard_dns"
    private const val KEY_CSV = "external_block_domains_csv"
    private const val KEY_UPDATED_AT = "external_block_domains_updated_at"
    private const val REFRESH_INTERVAL_MS = 6 * 60 * 60 * 1000L
    private const val MAX_DOMAINS = 15_000

    private val feedUrls = listOf(
        "https://github.com/fabriziosalmi/blacklists/releases/download/latest/rpz_blacklist.txt",
        "https://github.com/fabriziosalmi/blacklists/releases/download/latest/blacklist.txt",
    )

    fun syncIfDue(context: Context, force: Boolean = false): Set<String> {
        val pref = context.getSharedPreferences(PREF, Context.MODE_PRIVATE)
        val now = System.currentTimeMillis()
        val last = pref.getLong(KEY_UPDATED_AT, 0L)
        if (!force && now - last < REFRESH_INTERVAL_MS) {
            return loadCached(context)
        }

        val merged = linkedSetOf<String>()
        feedUrls.forEach { url ->
            val body = downloadText(url) ?: return@forEach
            parseDomainList(body).forEach { host ->
                if (merged.size >= MAX_DOMAINS) return@forEach
                merged += host
            }
        }

        if (merged.isEmpty()) {
            Log.w("FA.BlacklistFeed", "feed sync empty; keep cached list")
            return loadCached(context)
        }

        pref.edit()
            .putString(KEY_CSV, merged.joinToString(","))
            .putLong(KEY_UPDATED_AT, now)
            .apply()
        Log.i("FA.BlacklistFeed", "feed sync ok domains=${merged.size}")
        return merged
    }

    fun loadCached(context: Context): Set<String> {
        val pref = context.getSharedPreferences(PREF, Context.MODE_PRIVATE)
        val csv = pref.getString(KEY_CSV, "").orEmpty()
        if (csv.isBlank()) return emptySet()
        return csv.split(',')
            .map { normalizeHost(it) }
            .filter { it.isNotBlank() }
            .toSet()
    }

    private fun downloadText(url: String): String? {
        return runCatching {
            val conn = (URL(url).openConnection() as HttpURLConnection).apply {
                connectTimeout = 12000
                readTimeout = 15000
                instanceFollowRedirects = true
                requestMethod = "GET"
                setRequestProperty("User-Agent", "FirewallAgent/1.0")
            }
            conn.inputStream.bufferedReader().use { it.readText() }
        }.onFailure {
            Log.w("FA.BlacklistFeed", "download failed url=$url err=${it.message}")
        }.getOrNull()
    }

    private fun parseDomainList(raw: String): Set<String> {
        if (raw.isBlank()) return emptySet()
        val out = linkedSetOf<String>()
        raw.lineSequence().forEach { line ->
            if (out.size >= MAX_DOMAINS) return@forEach
            val trimmed = line.trim()
            if (trimmed.isBlank()) return@forEach
            if (trimmed.startsWith("#") || trimmed.startsWith(";")) return@forEach
            if (trimmed.startsWith("$")) return@forEach

            val firstToken = trimmed.split(Regex("\\s+")).firstOrNull().orEmpty()
            val host = normalizeHost(firstToken)
            if (host.isBlank()) return@forEach
            out += host
        }
        return out
    }

    private fun normalizeHost(raw: String): String {
        val stripped = raw.trim()
            .removePrefix("||")
            .removePrefix(".")
            .removePrefix("*.")
            .trim()
            .trim('.')
            .lowercase(Locale.US)
            .substringBefore('^')
            .substringBefore('/')
            .substringBefore(':')
        if (stripped.isBlank()) return ""
        if (stripped == "localhost") return ""
        if (!stripped.contains('.')) return ""
        if (stripped.any { it == ' ' || it == '\t' }) return ""
        return runCatching { IDN.toASCII(stripped, IDN.ALLOW_UNASSIGNED).lowercase(Locale.US) }
            .getOrDefault(stripped)
    }
}

