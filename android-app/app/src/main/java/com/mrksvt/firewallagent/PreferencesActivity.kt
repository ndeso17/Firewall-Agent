package com.mrksvt.firewallagent

import android.os.Bundle
import android.widget.ArrayAdapter
import android.widget.Spinner
import androidx.appcompat.app.AppCompatActivity
import androidx.lifecycle.lifecycleScope
import com.mrksvt.firewallagent.databinding.ActivityPreferencesBinding
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext
import org.json.JSONObject

class PreferencesActivity : AppCompatActivity() {
    private lateinit var binding: ActivityPreferencesBinding

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        binding = ActivityPreferencesBinding.inflate(layoutInflater)
        setContentView(binding.root)

        binding.reloadBtn.setOnClickListener { loadPrefs() }
        binding.saveBtn.setOnClickListener { savePrefs() }
        loadPrefs()
    }

    private fun loadPrefs() {
        val prefs = AppConfigStore.loadPreferences(this)
        binding.uiNotification.isChecked = prefs.optBoolean("ui_enable_notification", true)
        binding.uiRulesProgress.isChecked = prefs.optBoolean("ui_rules_progress", true)
        binding.uiConfirmFirewall.isChecked = prefs.optBoolean("ui_confirm_firewall", true)
        setSpinnerValue(binding.blacklistSpinner, prefs.optString("ui_blacklist_default", "block"))
        setSpinnerValue(binding.whitelistSpinner, prefs.optString("ui_whitelist_default", "allow"))
        setSpinnerValue(binding.logTargetSpinner, prefs.optString("log_target", "NFLOG"))
        binding.logService.isChecked = prefs.optBoolean("log_service", false)
        binding.logHostname.isChecked = prefs.optBoolean("log_show_hostname", false)
        binding.logPingTimeout.setText(prefs.optInt("log_ping_timeout", 15).toString())
        setSpinnerValue(binding.modeSpinner, prefs.optString("mode", "audit"))
        binding.thresholdInput.setText(prefs.optDouble("malicious_threshold", 0.8).toString())
        binding.uncertainMarginInput.setText(prefs.optDouble("uncertain_margin", 0.1).toString())
        binding.cooldownInput.setText(prefs.optInt("cooldown_seconds", 120).toString())
        binding.ttlInput.setText(prefs.optInt("block_ttl_seconds", 1800).toString())
        setSpinnerValue(binding.languageSpinner, prefs.optString("language", "id"))
        binding.outputText.text = "Loaded preferences."
    }

    private fun savePrefs() {
        val value = JSONObject()
            .put("ui_enable_notification", binding.uiNotification.isChecked)
            .put("ui_rules_progress", binding.uiRulesProgress.isChecked)
            .put("ui_confirm_firewall", binding.uiConfirmFirewall.isChecked)
            .put("ui_blacklist_default", binding.blacklistSpinner.selectedItem.toString())
            .put("ui_whitelist_default", binding.whitelistSpinner.selectedItem.toString())
            .put("log_target", binding.logTargetSpinner.selectedItem.toString())
            .put("log_service", binding.logService.isChecked)
            .put("log_show_hostname", binding.logHostname.isChecked)
            .put("log_ping_timeout", binding.logPingTimeout.text?.toString()?.toIntOrNull() ?: 15)
            .put("mode", binding.modeSpinner.selectedItem.toString())
            .put("malicious_threshold", binding.thresholdInput.text?.toString()?.toDoubleOrNull() ?: 0.8)
            .put("uncertain_margin", binding.uncertainMarginInput.text?.toString()?.toDoubleOrNull() ?: 0.1)
            .put("cooldown_seconds", binding.cooldownInput.text?.toString()?.toIntOrNull() ?: 120)
            .put("block_ttl_seconds", binding.ttlInput.text?.toString()?.toIntOrNull() ?: 1800)
            .put("profiles", AppConfigStore.loadPreferences(this).optString("profiles", "default,gaming,work"))
            .put("active_profile", AppConfigStore.loadPreferences(this).optString("active_profile", "default"))
            .put("language", binding.languageSpinner.selectedItem.toString())

        AppConfigStore.savePreferences(this, value)

        lifecycleScope.launch {
            val mode = value.optString("mode", "audit")
            val result = withContext(Dispatchers.IO) { RootFirewallController.setMode(mode) }
            binding.outputText.text = buildString {
                appendLine("Preferences saved.")
                appendLine("Mode sync: exit=${result.code}")
                if (result.stdout.isNotBlank()) appendLine(result.stdout)
                if (result.stderr.isNotBlank()) appendLine(result.stderr)
            }
        }
    }

    private fun setSpinnerValue(spinner: Spinner, value: String) {
        val adapter = spinner.adapter as? ArrayAdapter<*> ?: return
        for (i in 0 until adapter.count) {
            if (adapter.getItem(i).toString().equals(value, ignoreCase = true)) {
                spinner.setSelection(i)
                return
            }
        }
    }
}
