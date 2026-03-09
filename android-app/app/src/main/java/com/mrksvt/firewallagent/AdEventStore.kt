package com.mrksvt.firewallagent

import android.content.Context
import org.json.JSONObject
import java.io.File
import java.time.Instant
import java.time.LocalDate
import java.time.LocalDateTime
import java.time.ZoneId
import java.util.Locale

object AdEventStore {
    private const val FILE_NAME = "adguard_event_store.jsonl"
    private const val MAX_EVENTS = 120_000

    data class StoredEvent(
        val ts: Long,
        val packageName: String,
        val status: String,
        val host: String,
        val signature: String,
    )

    fun mergeCurrentLog(context: Context, raw: String): List<StoredEvent> {
        val existing = loadEvents(context).toMutableList()
        val existingKeys = existing.asSequence().map { it.signature }.toHashSet()
        parseRaw(raw).forEach { event ->
            if (existingKeys.add(event.signature)) {
                existing += event
            }
        }
        val normalized = existing
            .sortedBy { it.ts }
            .let { events ->
                if (events.size > MAX_EVENTS) events.takeLast(MAX_EVENTS) else events
            }
        saveEvents(context, normalized)
        return normalized
    }

    fun loadEvents(context: Context): List<StoredEvent> {
        val file = File(context.filesDir, FILE_NAME)
        if (!file.exists()) return emptyList()
        return file.readLines()
            .mapNotNull { line ->
                runCatching {
                    val o = JSONObject(line)
                    StoredEvent(
                        ts = o.optLong("ts", 0L),
                        packageName = o.optString("pkg", "").trim(),
                        status = o.optString("status", "").trim().lowercase(Locale.ROOT),
                        host = o.optString("host", "").trim().lowercase(Locale.ROOT),
                        signature = o.optString("sig", "").trim(),
                    )
                }.getOrNull()
            }
            .filter { it.ts > 0L && it.packageName.isNotBlank() && it.status.isNotBlank() && it.signature.isNotBlank() }
    }

    private fun saveEvents(context: Context, events: List<StoredEvent>) {
        val file = File(context.filesDir, FILE_NAME)
        val body = buildString {
            events.forEach { event ->
                append(
                    JSONObject()
                        .put("ts", event.ts)
                        .put("pkg", event.packageName)
                        .put("status", event.status)
                        .put("host", event.host)
                        .put("sig", event.signature)
                        .toString(),
                )
                append('\n')
            }
        }
        file.writeText(body)
    }

    private fun parseRaw(raw: String): List<StoredEvent> {
        if (raw.isBlank()) return emptyList()
        val zone = ZoneId.systemDefault()
        val now = Instant.now()
        return raw.lineSequence()
            .mapNotNull { parseLine(it, now, zone) }
            .toList()
    }

    private fun parseLine(line: String, now: Instant, zone: ZoneId): StoredEvent? {
        val lower = line.lowercase(Locale.ROOT)
        val status = when {
            lower.contains("fa.dnshidehook") && lower.contains(" faked ") -> "faked"
            lower.contains("fa.hybridadhook net observe ") -> "observe"
            lower.contains("fa.hybridadhook") && (
                lower.contains(" net blocked ") ||
                    lower.contains(" blocked ") ||
                    lower.contains(" intercepted request")
                ) -> "blocked"
            else -> return null
        }
        val policyPkg = extractKv(line, "policy_pkg")
        val pkgFromKv = extractKv(line, "pkg")
        val pkgFromIn = Regex("""\bin\s+([a-zA-Z0-9._]+)""")
            .find(line)
            ?.groupValues
            ?.getOrNull(1)
            ?.trim()
            .orEmpty()
        val rawPkg = when {
            policyPkg.isNotBlank() -> policyPkg
            pkgFromKv.isNotBlank() -> pkgFromKv
            else -> pkgFromIn
        }
        val pkg = when {
            rawPkg == "com.google.android.webview" && policyPkg.isNotBlank() -> policyPkg
            else -> rawPkg
        }
        if (pkg.isBlank() || pkg == "com.google.android.gms") return null
        val ts = parseTimestamp(line, now, zone)?.toEpochMilli() ?: return null
        val host = extractHost(line)
        val signature = "${ts}_${pkg}_${status}_${host}_${line.hashCode()}"
        return StoredEvent(
            ts = ts,
            packageName = pkg,
            status = status,
            host = host,
            signature = signature,
        )
    }

    private fun extractHost(line: String): String {
        Regex("""host=([A-Za-z0-9._-]+)""").find(line)?.groupValues?.getOrNull(1)?.let {
            return it.trim().lowercase(Locale.ROOT)
        }
        Regex("""https?://([A-Za-z0-9._-]+)""").find(line)?.groupValues?.getOrNull(1)?.let {
            return it.trim().lowercase(Locale.ROOT)
        }
        Regex("""\bfor\s+([A-Za-z0-9._-]+)\s+in\b""").find(line)?.groupValues?.getOrNull(1)?.let {
            return it.trim().lowercase(Locale.ROOT)
        }
        return "-"
    }

    private fun extractKv(line: String, key: String): String {
        return Regex("""\b$key=([A-Za-z0-9._-]+)""")
            .find(line)
            ?.groupValues
            ?.getOrNull(1)
            ?.trim()
            .orEmpty()
    }

    private fun parseTimestamp(line: String, now: Instant, zone: ZoneId): Instant? {
        val full = Regex("""\[\s*(\d{4})-(\d{2})-(\d{2})T(\d{2}):(\d{2}):(\d{2})""").find(line)
        if (full != null) {
            val y = full.groupValues[1].toIntOrNull() ?: return null
            val mo = full.groupValues[2].toIntOrNull() ?: return null
            val d = full.groupValues[3].toIntOrNull() ?: return null
            val h = full.groupValues[4].toIntOrNull() ?: return null
            val mi = full.groupValues[5].toIntOrNull() ?: return null
            val s = full.groupValues[6].toIntOrNull() ?: return null
            return runCatching { LocalDateTime.of(y, mo, d, h, mi, s).atZone(zone).toInstant() }.getOrNull()
        }

        val short = Regex("""^\s*(\d{2})-(\d{2})\s+(\d{2}):(\d{2}):(\d{2})""").find(line) ?: return null
        val yearNow = LocalDate.now(zone).year
        val mo = short.groupValues[1].toIntOrNull() ?: return null
        val d = short.groupValues[2].toIntOrNull() ?: return null
        val h = short.groupValues[3].toIntOrNull() ?: return null
        val mi = short.groupValues[4].toIntOrNull() ?: return null
        val s = short.groupValues[5].toIntOrNull() ?: return null
        val candidate = runCatching { LocalDateTime.of(yearNow, mo, d, h, mi, s).atZone(zone).toInstant() }.getOrNull() ?: return null
        return if (candidate.epochSecond > now.epochSecond + 36 * 3600L) {
            runCatching { LocalDateTime.of(yearNow - 1, mo, d, h, mi, s).atZone(zone).toInstant() }.getOrNull()
        } else {
            candidate
        }
    }
}
