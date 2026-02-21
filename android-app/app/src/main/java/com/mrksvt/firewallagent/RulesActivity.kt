package com.mrksvt.firewallagent

import android.os.Bundle
import android.widget.Toast
import androidx.appcompat.app.AppCompatActivity
import androidx.lifecycle.lifecycleScope
import com.mrksvt.firewallagent.databinding.ActivityRulesBinding
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext
import java.io.File
import java.time.Instant

class RulesActivity : AppCompatActivity() {
    private lateinit var binding: ActivityRulesBinding

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        binding = ActivityRulesBinding.inflate(layoutInflater)
        setContentView(binding.root)

        binding.refreshBtn.setOnClickListener { loadRules() }
        binding.approveBtn.setOnClickListener { approveBlock() }
        binding.rejectBtn.setOnClickListener { rejectAllow() }
        binding.exportPromptBtn.setOnClickListener { exportPrompt() }
        loadRules()
    }

    private fun approveBlock() {
        val uid = binding.uidInput.text?.toString()?.trim().orEmpty()
        if (uid.isBlank()) {
            Toast.makeText(this, "Isi UID dulu", Toast.LENGTH_SHORT).show()
            return
        }
        lifecycleScope.launch {
            val cmd = "iptables -I OUTPUT -m owner --uid-owner $uid -j REJECT"
            val result = withContext(Dispatchers.IO) { RootFirewallController.runRaw(cmd) }
            AppConfigStore.appendRuleAction(this@RulesActivity, "approve/block uid=$uid at=${Instant.now()}")
            showResult("Approve/Block UID $uid", result)
            loadRules()
        }
    }

    private fun rejectAllow() {
        val uid = binding.uidInput.text?.toString()?.trim().orEmpty()
        if (uid.isBlank()) {
            Toast.makeText(this, "Isi UID dulu", Toast.LENGTH_SHORT).show()
            return
        }
        lifecycleScope.launch {
            val cmd = "while iptables -C OUTPUT -m owner --uid-owner $uid -j REJECT >/dev/null 2>&1; do iptables -D OUTPUT -m owner --uid-owner $uid -j REJECT; done"
            val result = withContext(Dispatchers.IO) { RootFirewallController.runRaw(cmd) }
            AppConfigStore.appendRuleAction(this@RulesActivity, "reject/allow uid=$uid at=${Instant.now()}")
            showResult("Reject/Allow UID $uid", result)
            loadRules()
        }
    }

    private fun exportPrompt() {
        lifecycleScope.launch(Dispatchers.IO) {
            try {
                val rules = RootFirewallController.runRaw("iptables -S OUTPUT 2>&1")
                val payload = buildString {
                    appendLine("# Firewall Agent Prompt Export")
                    appendLine("generated_at=${Instant.now()}")
                    appendLine()
                    appendLine("# current rules")
                    appendLine(rules.stdout.ifBlank { rules.stderr.ifBlank { "(none)" } })
                    appendLine()
                    appendLine("# action history")
                    appendLine(AppConfigStore.loadRuleActions(this@RulesActivity).ifBlank { "(none)" })
                }

                val dir = getExternalFilesDir(null) ?: filesDir
                val file = File(dir, "firewall-prompt-${Instant.now().toString().replace(':', '-')}.txt")
                file.writeText(payload)
                withContext(Dispatchers.Main) {
                    Toast.makeText(this@RulesActivity, "Prompt exported: ${file.absolutePath}", Toast.LENGTH_LONG).show()
                }
            } catch (e: Exception) {
                withContext(Dispatchers.Main) {
                    Toast.makeText(this@RulesActivity, "Export gagal: ${e.message}", Toast.LENGTH_LONG).show()
                }
            }
        }
    }

    private fun loadRules() {
        lifecycleScope.launch {
            val rules = withContext(Dispatchers.IO) { RootFirewallController.runRaw("iptables -S OUTPUT 2>&1") }
            val actionHistory = AppConfigStore.loadRuleActions(this@RulesActivity)
            binding.outputText.text = buildString {
                appendLine("# iptables -S OUTPUT")
                appendLine(rules.stdout.ifBlank { rules.stderr.ifBlank { "(none)" } })
                appendLine()
                appendLine("# action history")
                append(actionHistory.ifBlank { "(none)" })
            }
        }
    }

    private fun showResult(title: String, result: ExecResult) {
        binding.outputText.text = buildString {
            appendLine(title)
            appendLine("exit=${result.code}")
            if (result.stdout.isNotBlank()) appendLine(result.stdout)
            if (result.stderr.isNotBlank()) appendLine(result.stderr)
        }
    }
}
