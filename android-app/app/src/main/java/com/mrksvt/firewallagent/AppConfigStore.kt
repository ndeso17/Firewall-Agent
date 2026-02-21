package com.mrksvt.firewallagent

import android.content.Context
import org.json.JSONObject

object AppConfigStore {
    private const val PREFS_NAME = "firewall_agent_native"
    private const val KEY_PREFERENCES = "preferences_json"
    private const val KEY_MODEL_UPDATE = "model_update_json"
    private const val KEY_RULE_ACTIONS = "rules_actions_log"

    private fun prefs(context: Context) = context.getSharedPreferences(PREFS_NAME, Context.MODE_PRIVATE)

    fun loadPreferences(context: Context): JSONObject {
        val raw = prefs(context).getString(KEY_PREFERENCES, null)
        return if (raw.isNullOrBlank()) defaultPreferences() else JSONObject(raw)
    }

    fun savePreferences(context: Context, value: JSONObject) {
        prefs(context).edit().putString(KEY_PREFERENCES, value.toString()).apply()
    }

    fun loadModelUpdate(context: Context): JSONObject {
        val raw = prefs(context).getString(KEY_MODEL_UPDATE, null)
        return if (raw.isNullOrBlank()) defaultModelUpdate() else JSONObject(raw)
    }

    fun saveModelUpdate(context: Context, value: JSONObject) {
        prefs(context).edit().putString(KEY_MODEL_UPDATE, value.toString()).apply()
    }

    fun appendRuleAction(context: Context, line: String) {
        val current = prefs(context).getString(KEY_RULE_ACTIONS, "").orEmpty()
        val merged = (current + "\n" + line).trim()
        prefs(context).edit().putString(KEY_RULE_ACTIONS, merged.takeLast(12_000)).apply()
    }

    fun loadRuleActions(context: Context): String =
        prefs(context).getString(KEY_RULE_ACTIONS, "").orEmpty()

    private fun defaultPreferences(): JSONObject = JSONObject()
        .put("mode", "audit")
        .put("malicious_threshold", 0.8)
        .put("uncertain_margin", 0.1)
        .put("cooldown_seconds", 120)
        .put("block_ttl_seconds", 1800)
        .put("ui_enable_notification", true)
        .put("ui_rules_progress", true)
        .put("ui_confirm_firewall", true)
        .put("ui_blacklist_default", "block")
        .put("ui_whitelist_default", "allow")
        .put("log_target", "NFLOG")
        .put("log_service", false)
        .put("log_show_hostname", false)
        .put("log_ping_timeout", 15)
        .put("profiles", "default,gaming,work")
        .put("active_profile", "default")
        .put("language", "id")

    private fun defaultModelUpdate(): JSONObject = JSONObject()
        .put("manifest_url", "")
        .put("onnx_url", "")
        .put("channel", "stable")
        .put("auto_update", false)
        .put("check_interval_minutes", 60)
}
