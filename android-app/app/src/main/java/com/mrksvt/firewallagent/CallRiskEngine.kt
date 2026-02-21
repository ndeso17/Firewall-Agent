package com.mrksvt.firewallagent

import android.content.Context
import android.provider.CallLog
import org.json.JSONArray
import org.json.JSONObject

data class RiskEntry(
    val number: String,
    val score: Int,
    val calls: Int,
    val missed: Int,
    val shortCalls: Int,
    val lastEpochMs: Long,
)

data class RiskReport(
    val analyzed: Int,
    val risky: List<RiskEntry>,
    val autoAdded: List<String>,
)

object CallRiskEngine {
    fun analyzeAndSync(context: Context): RiskReport {
        val cfgPref = context.getSharedPreferences("call_guard", Context.MODE_PRIVATE)
        val cfg = runCatching { JSONObject(cfgPref.getString("config", "{}").orEmpty()) }.getOrElse { JSONObject() }
        val whitelist = parseSet(cfg.optString("whitelist_csv", ""))
        val blacklist = parseSet(cfg.optString("blacklist_csv", ""))
        val autoSync = cfg.optBoolean("auto_risk_autosync", false)
        val threshold = cfg.optInt("auto_risk_threshold", 70).coerceIn(1, 100)
        val now = System.currentTimeMillis()
        val horizon = now - (7L * 24L * 60L * 60L * 1000L)

        val map = linkedMapOf<String, MutableStat>()
        val cursor = context.contentResolver.query(
            CallLog.Calls.CONTENT_URI,
            arrayOf(
                CallLog.Calls.NUMBER,
                CallLog.Calls.TYPE,
                CallLog.Calls.DURATION,
                CallLog.Calls.DATE,
            ),
            "${CallLog.Calls.DATE} >= ?",
            arrayOf(horizon.toString()),
            "${CallLog.Calls.DATE} DESC",
        )
        cursor?.use { c ->
            val idxNum = c.getColumnIndex(CallLog.Calls.NUMBER)
            val idxType = c.getColumnIndex(CallLog.Calls.TYPE)
            val idxDur = c.getColumnIndex(CallLog.Calls.DURATION)
            val idxDate = c.getColumnIndex(CallLog.Calls.DATE)
            while (c.moveToNext()) {
                val raw = if (idxNum >= 0) c.getString(idxNum) else ""
                val number = normalize(raw.orEmpty())
                if (number.isBlank()) continue
                val type = if (idxType >= 0) c.getInt(idxType) else 0
                val dur = if (idxDur >= 0) c.getLong(idxDur) else 0L
                val date = if (idxDate >= 0) c.getLong(idxDate) else 0L

                val stat = map.getOrPut(number) { MutableStat() }
                stat.calls++
                stat.lastEpochMs = maxOf(stat.lastEpochMs, date)
                if (type == CallLog.Calls.MISSED_TYPE || type == CallLog.Calls.REJECTED_TYPE) stat.missed++
                if (dur in 0..8) stat.shortCalls++
            }
        }

        val risky = map.entries
            .asSequence()
            .filter { (num, _) -> !whitelist.contains(num) }
            .map { (num, st) ->
                val recencyBoost = if (now - st.lastEpochMs <= 24L * 60L * 60L * 1000L) 10 else 0
                val score = (st.missed * 18) + (st.shortCalls * 12) + (st.calls * 4) + recencyBoost
                RiskEntry(
                    number = num,
                    score = score.coerceAtMost(100),
                    calls = st.calls,
                    missed = st.missed,
                    shortCalls = st.shortCalls,
                    lastEpochMs = st.lastEpochMs,
                )
            }
            .filter { it.score >= threshold }
            .sortedByDescending { it.score }
            .take(30)
            .toList()

        val autoAdded = mutableListOf<String>()
        if (autoSync) {
            val merged = blacklist.toMutableSet()
            risky.forEach { r ->
                if (!merged.contains(r.number)) {
                    merged += r.number
                    autoAdded += r.number
                }
            }
            if (autoAdded.isNotEmpty()) {
                val newCfg = JSONObject(cfg.toString())
                newCfg.put("blacklist_csv", merged.joinToString(","))
                val arr = JSONArray()
                merged.sorted().forEach { arr.put(it) }
                newCfg.put("blacklist", arr)
                cfgPref.edit().putString("config", newCfg.toString()).apply()
                val riskyMap = risky.associateBy { it.number }
                autoAdded.forEach { num ->
                    CallDatasetStore.recordAutoRiskSyncLabel(
                        context = context,
                        number = num,
                        score = riskyMap[num]?.score ?: threshold,
                    )
                }
            }
        }

        // Persist a small report for future UI/ML hook.
        val rep = JSONObject()
            .put("ts", now)
            .put("threshold", threshold)
            .put("auto_sync", autoSync)
            .put("analyzed_numbers", map.size)
            .put("auto_added", JSONArray().apply { autoAdded.forEach { put(it) } })
            .put(
                "risky",
                JSONArray().apply {
                    risky.forEach {
                        put(
                            JSONObject()
                                .put("number", it.number)
                                .put("score", it.score)
                                .put("calls", it.calls)
                                .put("missed", it.missed)
                                .put("short_calls", it.shortCalls),
                        )
                    }
                },
            )
        cfgPref.edit().putString("last_risk_report", rep.toString()).apply()

        return RiskReport(
            analyzed = map.size,
            risky = risky,
            autoAdded = autoAdded,
        )
    }

    private fun parseSet(csv: String): Set<String> {
        if (csv.isBlank()) return emptySet()
        return csv.split(',').map { normalize(it) }.filter { it.isNotBlank() }.toSet()
    }

    private fun normalize(raw: String): String = raw.filter { it.isDigit() }

    private class MutableStat {
        var calls: Int = 0
        var missed: Int = 0
        var shortCalls: Int = 0
        var lastEpochMs: Long = 0L
    }
}
