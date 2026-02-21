package com.mrksvt.firewallagent

import android.content.Context
import org.json.JSONObject
import java.io.File

object CallDatasetStore {
    private const val DATASET_FILE = "call_guard_dataset.jsonl"
    private const val MAX_BYTES = 2L * 1024L * 1024L
    private const val KEEP_LINES = 4000

    fun recordManualLabel(
        context: Context,
        number: String,
        isSpam: Boolean,
        source: String,
    ) {
        val normalized = normalize(number)
        if (normalized.isBlank()) return
        val item = JSONObject()
            .put("ts", System.currentTimeMillis())
            .put("event", "manual_label")
            .put("number", normalized)
            .put("label", if (isSpam) "spam" else "ham")
            .put("label_value", if (isSpam) 1 else 0)
            .put("source", source)
        append(context, item)
    }

    fun recordScreeningEvent(
        context: Context,
        number: String,
        blocked: Boolean,
        reason: String,
        blockUnknown: Boolean,
        whitelistHit: Boolean,
        blacklistHit: Boolean,
    ) {
        val normalized = normalize(number)
        val labelValue = when {
            blacklistHit -> 1
            whitelistHit -> 0
            normalized.isBlank() -> if (blockUnknown) 1 else -1
            else -> -1
        }
        val item = JSONObject()
            .put("ts", System.currentTimeMillis())
            .put("event", "screening")
            .put("number", normalized)
            .put("blocked", blocked)
            .put("reason", reason)
            .put("feature_block_unknown", blockUnknown)
            .put("feature_whitelist_hit", whitelistHit)
            .put("feature_blacklist_hit", blacklistHit)
            .put("label", when (labelValue) {
                1 -> "spam"
                0 -> "ham"
                else -> "unlabeled"
            })
            .put("label_value", labelValue)
        append(context, item)
    }

    fun recordAutoRiskSyncLabel(context: Context, number: String, score: Int) {
        val normalized = normalize(number)
        if (normalized.isBlank()) return
        val item = JSONObject()
            .put("ts", System.currentTimeMillis())
            .put("event", "risk_autosync")
            .put("number", normalized)
            .put("label", "spam")
            .put("label_value", 1)
            .put("risk_score", score.coerceIn(0, 100))
            .put("source", "call_risk_engine")
        append(context, item)
    }

    fun file(context: Context): File = File(context.filesDir, DATASET_FILE)

    fun count(context: Context): Int {
        return runCatching {
            val f = file(context)
            if (!f.exists()) 0 else f.readLines().size
        }.getOrDefault(0)
    }

    private fun append(context: Context, obj: JSONObject) {
        val f = file(context)
        runCatching {
            f.appendText(obj.toString() + "\n")
            if (f.length() > MAX_BYTES) {
                val keep = f.readLines().takeLast(KEEP_LINES)
                f.writeText(keep.joinToString("\n", postfix = "\n"))
            }
        }
    }

    private fun normalize(raw: String): String = raw.filter { it.isDigit() }
}

