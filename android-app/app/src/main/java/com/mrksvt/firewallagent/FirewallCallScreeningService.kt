package com.mrksvt.firewallagent

import android.telecom.Call
import android.telecom.CallScreeningService
import java.io.File
import org.json.JSONObject

class FirewallCallScreeningService : CallScreeningService() {
    override fun onScreenCall(callDetails: Call.Details) {
        // Only handle incoming calls.
        if (callDetails.callDirection != Call.Details.DIRECTION_INCOMING) {
            allow(callDetails)
            return
        }

        val number = normalize(callDetails.handle?.schemeSpecificPart.orEmpty())
        val cfg = loadConfig()
        val blockUnknown = cfg.optBoolean("block_unknown", false)
        val whitelist = parseSet(cfg.optString("whitelist_csv", ""))
        val blacklist = parseSet(cfg.optString("blacklist_csv", ""))

        val shouldBlock = when {
            number.isBlank() -> blockUnknown
            blacklist.contains(number) -> true
            whitelist.contains(number) -> false
            blockUnknown -> true
            else -> false
        }
        val reason = when {
            number.isBlank() && blockUnknown -> "unknown_number"
            blacklist.contains(number) -> "blacklist"
            whitelist.contains(number) -> "whitelist"
            blockUnknown -> "unknown_policy"
            else -> "allow"
        }

        if (shouldBlock) {
            val response = CallResponse.Builder()
                .setDisallowCall(true)
                .setRejectCall(true)
                .setSkipCallLog(false)
                .setSkipNotification(false)
                .build()
            respondToCall(callDetails, response)
            NotifyHelper.ensureChannel(this)
            NotifyHelper.post(
                context = this,
                title = "Call Guard",
                content = "Panggilan diblokir ($reason) nomor: ${if (number.isBlank()) "unknown" else number}",
                id = (10000 + (System.currentTimeMillis() % 8999).toInt()),
            )
            logEvent(number = number, blocked = true, reason = reason)
            CallDatasetStore.recordScreeningEvent(
                context = this,
                number = number,
                blocked = true,
                reason = reason,
                blockUnknown = blockUnknown,
                whitelistHit = whitelist.contains(number),
                blacklistHit = blacklist.contains(number),
            )
            appendBlockedLog(number = number, reason = reason)
        } else {
            allow(callDetails)
            logEvent(number = number, blocked = false, reason = reason)
            CallDatasetStore.recordScreeningEvent(
                context = this,
                number = number,
                blocked = false,
                reason = reason,
                blockUnknown = blockUnknown,
                whitelistHit = whitelist.contains(number),
                blacklistHit = blacklist.contains(number),
            )
        }
    }

    private fun allow(callDetails: Call.Details) {
        respondToCall(callDetails, CallResponse.Builder().build())
    }

    private fun loadConfig(): JSONObject {
        val pref = getSharedPreferences("call_guard", MODE_PRIVATE)
        val raw = pref.getString("config", null).orEmpty()
        return runCatching { JSONObject(raw) }.getOrElse { JSONObject() }
    }

    private fun parseSet(csv: String): Set<String> {
        if (csv.isBlank()) return emptySet()
        return csv.split(',')
            .map { normalize(it) }
            .filter { it.isNotBlank() }
            .toSet()
    }

    private fun normalize(raw: String): String {
        val trimmed = raw.trim()
        if (trimmed.isBlank()) return ""
        return trimmed.filter { it.isDigit() }
    }

    private fun logEvent(number: String, blocked: Boolean, reason: String) {
        val pref = getSharedPreferences("call_guard", MODE_PRIVATE)
        val arr = runCatching {
            val existing = pref.getString("events", "[]").orEmpty()
            org.json.JSONArray(existing)
        }.getOrElse { org.json.JSONArray() }

        val item = org.json.JSONObject()
            .put("ts", System.currentTimeMillis())
            .put("number", number)
            .put("blocked", blocked)
            .put("reason", reason)
        arr.put(item)

        // Keep last 200 events.
        val trimmed = org.json.JSONArray()
        val start = (arr.length() - 200).coerceAtLeast(0)
        for (i in start until arr.length()) trimmed.put(arr.getJSONObject(i))
        pref.edit().putString("events", trimmed.toString()).apply()
    }

    private fun appendBlockedLog(number: String, reason: String) {
        val file = File(filesDir, "call_guard_blocked.log")
        val line = JSONObject()
            .put("ts", System.currentTimeMillis())
            .put("number", if (number.isBlank()) "unknown" else number)
            .put("reason", reason)
            .toString()
        runCatching {
            file.appendText("$line\n")
            // Keep log bounded to ~1 MB.
            if (file.length() > 1024 * 1024) {
                val keep = file.readLines().takeLast(1500)
                file.writeText(keep.joinToString("\n", postfix = "\n"))
            }
        }
    }
}
