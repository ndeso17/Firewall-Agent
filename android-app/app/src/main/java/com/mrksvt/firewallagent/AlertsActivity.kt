package com.mrksvt.firewallagent

import android.graphics.Typeface
import android.os.Bundle
import android.view.ViewGroup
import android.widget.Button
import android.widget.LinearLayout
import android.widget.TextView
import android.widget.Toast
import androidx.appcompat.app.AppCompatActivity
import androidx.lifecycle.lifecycleScope
import com.mrksvt.firewallagent.databinding.ActivityAlertsBinding
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext

class AlertsActivity : AppCompatActivity() {
    private lateinit var binding: ActivityAlertsBinding
    private var allAlerts: List<AlertItem> = emptyList()

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        binding = ActivityAlertsBinding.inflate(layoutInflater)
        setContentView(binding.root)

        binding.refreshBtn.setOnClickListener { loadAlerts() }
        binding.searchInput.addTextChangedListener(SimpleTextWatcher { renderAlerts() })
        loadAlerts()
    }

    private fun loadAlerts() {
        lifecycleScope.launch {
            val log = withContext(Dispatchers.IO) { RootFirewallController.tailServiceLog(500).stdout }
            allAlerts = parseAlerts(log)
            renderAlerts()
        }
    }

    private fun renderAlerts() {
        val query = binding.searchInput.text?.toString()?.trim()?.lowercase().orEmpty()
        val target = if (query.isBlank()) {
            allAlerts
        } else {
            allAlerts.filter {
                "${it.incidentId} ${it.mode} ${it.uid} ${it.reason}".lowercase().contains(query)
            }
        }

        binding.listContainer.removeAllViews()
        if (target.isEmpty()) {
            val empty = TextView(this).apply {
                text = "Belum ada suspicious activity."
                setTextColor(0xFFE5E7EB.toInt())
                textSize = 16f
            }
            binding.listContainer.addView(empty)
            return
        }

        target.forEachIndexed { index, item ->
            binding.listContainer.addView(createAlertCard(index + 1, item))
        }
    }

    private fun createAlertCard(number: Int, item: AlertItem): LinearLayout {
        val card = LinearLayout(this).apply {
            orientation = LinearLayout.VERTICAL
            setPadding(20, 18, 20, 18)
            setBackgroundColor(0xFF1E1F24.toInt())
            val p = LinearLayout.LayoutParams(
                ViewGroup.LayoutParams.MATCH_PARENT,
                ViewGroup.LayoutParams.WRAP_CONTENT,
            )
            p.bottomMargin = 12
            layoutParams = p
        }

        fun line(text: String, bold: Boolean = false, color: Int = 0xFFE5E7EB.toInt()): TextView {
            return TextView(this).apply {
                this.text = text
                setTextColor(color)
                textSize = 15f
                if (bold) setTypeface(typeface, Typeface.BOLD)
            }
        }

        card.addView(line("[$number] ${item.incidentId}", bold = true))
        card.addView(line("Mode: ${item.mode} | UID: ${item.uid} | Score: ${item.score}", color = 0xFFB8C0CC.toInt()))
        card.addView(line("Kategori: ${item.category}", color = 0xFFFCD34D.toInt()))
        card.addView(line("Keterangan: ${item.description}", color = 0xFFD1D5DB.toInt()))
        card.addView(line("Decision: ${item.decision} | Planned: ${item.plannedAction}", color = 0xFF9CA3AF.toInt()))

        val btn = Button(this).apply {
            text = if (item.uid == "-") "UID Tidak Tersedia" else "Execute Block"
            isAllCaps = false
            isEnabled = item.uid != "-"
            setOnClickListener { executeBlock(item) }
        }
        card.addView(btn)
        return card
    }

    private fun executeBlock(item: AlertItem) {
        if (item.uid == "-") return
        lifecycleScope.launch {
            val uid = item.uid.toIntOrNull()
            if (uid == null) {
                Toast.makeText(this@AlertsActivity, "UID tidak valid", Toast.LENGTH_SHORT).show()
                return@launch
            }
            val cmd = "iptables -I OUTPUT -m owner --uid-owner $uid -j REJECT"
            val result = withContext(Dispatchers.IO) { RootFirewallController.runRaw(cmd) }
            val message = if (result.ok) "Block untuk UID $uid berhasil" else "Gagal block UID $uid"
            if (result.ok) {
                AppConfigStore.appendRuleAction(this@AlertsActivity, "approve:$uid:${item.incidentId}")
                NotifyHelper.post(this@AlertsActivity, "Firewall Agent", message, 1400 + (uid % 500))
            }
            Toast.makeText(this@AlertsActivity, message, Toast.LENGTH_SHORT).show()
        }
    }

    private fun parseAlerts(log: String): List<AlertItem> {
        val lines = log.lines().filter { it.contains("[runner]") }.takeLast(120).reversed()
        return lines.mapIndexed { idx, line ->
            val mode = extract(line, "mode=([^ ]+)") ?: "audit"
            val uid = extract(line, "uid=([^ ]+)") ?: "-"
            val score = extract(line, "score=([^ ]+)") ?: "0"
            val reason = extract(line, "reason=([^ ]+)") ?: "suspicious_activity"
            val decision = extract(line, "decision=([^ ]+)") ?: "log_only"
            val incidentId = extract(line, "incident=([^ ]+)") ?: "incident_$idx"
            val category = when {
                reason.contains("trojan", true) -> "Trojan"
                reason.contains("spy", true) -> "Spyware"
                reason.contains("ransom", true) -> "Ransomware"
                reason.contains("virus", true) || reason.contains("worm", true) -> "Virus/Worm"
                else -> "Suspicious Activity"
            }
            AlertItem(
                incidentId = incidentId,
                mode = mode,
                uid = uid,
                score = score,
                reason = reason,
                decision = decision,
                plannedAction = if (decision == "block_uid") "block_uid" else "block_uid",
                category = category,
                description = "Aktivitas jaringan mencurigakan, potensi malware/spyware/trojan.",
            )
        }
    }

    private fun extract(text: String, pattern: String): String? {
        val match = Regex(pattern).find(text) ?: return null
        return match.groupValues.getOrNull(1)
    }
}

data class AlertItem(
    val incidentId: String,
    val mode: String,
    val uid: String,
    val score: String,
    val reason: String,
    val decision: String,
    val plannedAction: String,
    val category: String,
    val description: String,
)
