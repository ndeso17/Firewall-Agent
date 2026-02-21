package com.mrksvt.firewallagent

import android.graphics.Color
import android.graphics.Typeface
import android.os.Bundle
import android.view.Gravity
import android.view.View
import android.widget.ImageView
import android.widget.LinearLayout
import android.widget.TextView
import androidx.appcompat.app.AppCompatActivity
import androidx.core.content.ContextCompat
import androidx.lifecycle.lifecycleScope
import com.mrksvt.firewallagent.databinding.ActivitySecurityStatsBinding
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext
import org.json.JSONArray
import org.json.JSONObject
import java.io.File
import java.time.Instant
import java.time.LocalDate
import java.time.LocalDateTime
import java.time.ZoneId
import java.time.format.DateTimeFormatter
import kotlin.math.ln
import kotlin.math.pow

class SecurityStatsActivity : AppCompatActivity() {
    private lateinit var binding: ActivitySecurityStatsBinding
    private var selectedPeriod = Period.P24H

    private enum class Period { P24H, P7D }

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        binding = ActivitySecurityStatsBinding.inflate(layoutInflater)
        setContentView(binding.root)

        binding.refreshBtn.setOnClickListener { refreshStats() }
        binding.period24Btn.setOnClickListener {
            selectedPeriod = Period.P24H
            updatePeriodButtons()
            refreshStats()
        }
        binding.period7dBtn.setOnClickListener {
            selectedPeriod = Period.P7D
            updatePeriodButtons()
            refreshStats()
        }
        updatePeriodButtons()
        refreshStats()
    }

    private fun updatePeriodButtons() {
        val onBg = Color.parseColor("#16A34A")
        val offBg = Color.parseColor("#334155")
        val onTx = Color.parseColor("#FFFFFF")
        val offTx = Color.parseColor("#CBD5E1")
        val p24 = selectedPeriod == Period.P24H
        binding.period24Btn.setBackgroundColor(if (p24) onBg else offBg)
        binding.period24Btn.setTextColor(if (p24) onTx else offTx)
        binding.period7dBtn.setBackgroundColor(if (!p24) onBg else offBg)
        binding.period7dBtn.setTextColor(if (!p24) onTx else offTx)
    }

    private fun refreshStats() {
        lifecycleScope.launch {
            binding.malwareSummaryText.text = "Loading..."
            binding.adSummaryText.text = "Loading..."
            binding.callSummaryText.text = "Loading..."

            val stats = withContext(Dispatchers.IO) { collectStats() }
            binding.malwareSummaryText.text = buildMalwareText(stats)
            binding.adSummaryText.text = buildAdText(stats)
            binding.callSummaryText.text = buildCallText(stats)
            binding.malwareLogText.text = stats.malwareLogs.ifBlank { "-" }
            binding.callLogText.text = stats.callLogs.ifBlank { "-" }
            binding.lastUpdatedText.text = "Last update: ${nowHuman()}"
            renderTrend(stats)
            renderCallPie(stats)
            renderAdAppList(stats.adApps)
        }
    }

    private fun renderTrend(stats: SecurityStats) {
        val zone = ZoneId.systemDefault()
        when (selectedPeriod) {
            Period.P24H -> {
                binding.malwareTrendChart.setData(
                    values = stats.malware24h.map { it.toFloat() },
                    startText = "24h ago",
                    endText = "Now",
                    unit = "count",
                    colorHex = "#EF4444",
                )
                binding.adsTrendChart.setData(
                    values = stats.ads24h.map { it.toFloat() },
                    startText = "24h ago",
                    endText = "Now",
                    unit = "count",
                    colorHex = "#22C55E",
                )
            }
            Period.P7D -> {
                val start = LocalDate.now(zone).minusDays(6).format(DateTimeFormatter.ofPattern("dd/MM"))
                val end = LocalDate.now(zone).format(DateTimeFormatter.ofPattern("dd/MM"))
                binding.malwareTrendChart.setData(
                    values = stats.malware7d.map { it.toFloat() },
                    startText = start,
                    endText = end,
                    unit = "count",
                    colorHex = "#F97316",
                )
                binding.adsTrendChart.setData(
                    values = stats.ads7d.map { it.toFloat() },
                    startText = start,
                    endText = end,
                    unit = "count",
                    colorHex = "#06B6D4",
                )
            }
        }
    }

    private fun renderCallPie(stats: SecurityStats) {
        binding.callGuardPieChart.setData(
            items = listOf(
                SecurityPieChartView.Slice("Blocked", stats.callBlockedAuto.toFloat(), "#EF4444"),
                SecurityPieChartView.Slice("Reject Manual", stats.callManualReject.toFloat(), "#F59E0B"),
                SecurityPieChartView.Slice("Accepted", stats.callAccepted.toFloat(), "#22C55E"),
            ),
            center = "${stats.callTotal}",
        )
    }

    private fun renderAdAppList(items: List<AdAppStat>) {
        val container = binding.adAppListContainer
        container.removeAllViews()
        binding.adAppEmptyText.visibility = if (items.isEmpty()) View.VISIBLE else View.GONE
        if (items.isEmpty()) return

        items.take(20).forEach { item ->
            val row = LinearLayout(this).apply {
                orientation = LinearLayout.HORIZONTAL
                gravity = Gravity.CENTER_VERTICAL
                setPadding(dp(2), dp(6), dp(2), dp(6))
            }

            val icon = ImageView(this).apply {
                layoutParams = LinearLayout.LayoutParams(dp(28), dp(28))
                setImageDrawable(
                    runCatching { packageManager.getApplicationIcon(item.packageName) }.getOrElse {
                        ContextCompat.getDrawable(this@SecurityStatsActivity, android.R.drawable.sym_def_app_icon)
                    },
                )
            }

            val nameAndPkg = LinearLayout(this).apply {
                orientation = LinearLayout.VERTICAL
                layoutParams = LinearLayout.LayoutParams(0, LinearLayout.LayoutParams.WRAP_CONTENT, 1f).apply {
                    marginStart = dp(10)
                }
            }

            val nameTv = TextView(this).apply {
                text = item.appName
                setTextColor(Color.parseColor("#E5E7EB"))
                textSize = 14f
                setTypeface(typeface, Typeface.BOLD)
            }
            val pkgTv = TextView(this).apply {
                text = item.packageName
                setTextColor(Color.parseColor("#9CA3AF"))
                textSize = 12f
            }
            nameAndPkg.addView(nameTv)
            nameAndPkg.addView(pkgTv)

            val countTv = TextView(this).apply {
                text = "${item.blockedCount} query"
                setTextColor(Color.parseColor("#22C55E"))
                textSize = 13f
                setTypeface(typeface, Typeface.BOLD)
            }

            row.addView(icon)
            row.addView(nameAndPkg)
            row.addView(countTv)
            container.addView(row)
        }
    }

    private fun collectStats(): SecurityStats {
        val tail = RootFirewallController.runRaw("tail -n 1600 /data/local/tmp/firewall_agent/logs/controller.log 2>/dev/null")
        val lines = tail.stdout.lines().filter { it.contains("[runner]") }

        var totalIncidents = 0
        var malwareLike = 0
        var blocked = 0
        var trojan = 0
        var spyware = 0
        var virus = 0
        var ransomware = 0

        val now = Instant.now()
        val malware24h = IntArray(24)
        val malware7d = IntArray(7)
        val malwareLogLines = mutableListOf<String>()

        lines.forEach { line ->
            totalIncidents++
            val reason = Regex("reason=([^ ]+)").find(line)?.groupValues?.getOrNull(1)?.lowercase().orEmpty()
            val uid = Regex("uid=([^ ]+)").find(line)?.groupValues?.getOrNull(1).orEmpty()
            val decision = Regex("decision=([^ ]+)").find(line)?.groupValues?.getOrNull(1)?.lowercase().orEmpty()
            if (decision == "block_uid") blocked++

            var flagged = false
            if (reason.contains("trojan")) {
                trojan++
                flagged = true
            }
            if (reason.contains("spy")) {
                spyware++
                flagged = true
            }
            if (reason.contains("virus") || reason.contains("worm")) {
                virus++
                flagged = true
            }
            if (reason.contains("ransom")) {
                ransomware++
                flagged = true
            }
            if (reason.contains("malware")) flagged = true
            if (flagged) {
                malwareLike++
                parseIncidentTime(line)?.let { ts ->
                    val h = ((now.epochSecond - ts.epochSecond) / 3600).toInt()
                    if (h in 0..23) malware24h[23 - h]++
                    val d = ((now.epochSecond - ts.epochSecond) / 86400).toInt()
                    if (d in 0..6) malware7d[6 - d]++
                    malwareLogLines += "${fmtTs(ts)} | uid=$uid | reason=$reason | decision=$decision"
                }
            }
        }

        val adsDrop = RootFirewallController.runRaw(
            "iptables -L FA_ADS -v -n 2>/dev/null | awk 'BEGIN{pk=0;by=0} /DROP/{pk+=$1;by+=$2} END{printf \"%d %d\", pk, by}'",
        )
        val adParts = adsDrop.stdout.trim().split(Regex("\\s+"))
        val adPackets = adParts.getOrNull(0)?.toLongOrNull() ?: 0L
        val adBytes = adParts.getOrNull(1)?.toLongOrNull() ?: 0L

        val adEvents = RootFirewallController.runRaw(
            "grep -h 'FA.HybridAdHook' /data/adb/lspd/log/modules_*.log 2>/dev/null | tail -n 30000",
        )
        val ads24h = IntArray(24)
        val ads7d = IntArray(7)
        var adQueryBlocked = 0
        val adCounts = linkedMapOf<String, Int>()
        adEvents.stdout.lines().forEach { line ->
            val lower = line.lowercase()
            val isBlockedEvent = lower.contains("fa.hybridadhook blocked ") || lower.contains("fa.hybridadhook intercepted request")
            if (!isBlockedEvent) return@forEach
            adQueryBlocked++
            parseAdEventTime(line, now, ZoneId.systemDefault())?.let { ts ->
                val h = ((now.epochSecond - ts.epochSecond) / 3600).toInt()
                if (h in 0..23) ads24h[23 - h]++
                val d = ((now.epochSecond - ts.epochSecond) / 86400).toInt()
                if (d in 0..6) ads7d[6 - d]++
            }
            val pkg = parseAdPackage(line)
            if (!pkg.isNullOrBlank()) adCounts[pkg] = (adCounts[pkg] ?: 0) + 1
        }
        val adAppStats = adCounts.entries
            .sortedByDescending { it.value }
            .map { (pkg, count) ->
                AdAppStat(
                    packageName = pkg,
                    appName = runCatching {
                        val ai = packageManager.getApplicationInfo(pkg, 0)
                        packageManager.getApplicationLabel(ai).toString()
                    }.getOrDefault(pkg),
                    blockedCount = count,
                )
            }

        val callStats = collectCallStats()

        return SecurityStats(
            totalIncidents = totalIncidents,
            malwareLike = malwareLike,
            blockedByMl = blocked,
            trojan = trojan,
            spyware = spyware,
            virus = virus,
            ransomware = ransomware,
            adQueryBlocked = adQueryBlocked,
            adPacketsBlocked = adPackets,
            adBytesBlocked = adBytes,
            malware24h = malware24h.toList(),
            malware7d = malware7d.toList(),
            ads24h = ads24h.toList(),
            ads7d = ads7d.toList(),
            callTotal = callStats.total,
            callBlockedAuto = callStats.blockedAuto,
            callManualReject = callStats.manualReject,
            callAccepted = callStats.accepted,
            malwareLogs = malwareLogLines.takeLast(12).joinToString("\n"),
            adApps = adAppStats,
            callLogs = callStats.logs.takeLast(12).joinToString("\n"),
            rawDebug = buildString {
                appendLine("runner_lines=${lines.size}")
                appendLine("ads_drop_raw=${adsDrop.stdout.trim().ifBlank { "(empty)" }}")
                appendLine("ad_hook_events=${adQueryBlocked}")
                appendLine("call_events_total=${callStats.total}")
                if (tail.stderr.isNotBlank()) appendLine("tail_err=${tail.stderr.trim()}")
                if (adsDrop.stderr.isNotBlank()) appendLine("ads_err=${adsDrop.stderr.trim()}")
                if (adEvents.stderr.isNotBlank()) appendLine("ads_hook_err=${adEvents.stderr.trim()}")
            }.trim(),
        )
    }

    private fun parseIncidentTime(line: String): Instant? {
        val incident = Regex("incident=([0-9]{8}T[0-9]{6}Z)").find(line)?.groupValues?.getOrNull(1) ?: return null
        return runCatching {
            Instant.from(DateTimeFormatter.ofPattern("yyyyMMdd'T'HHmmss'Z'").parse(incident))
        }.getOrNull()
    }

    private fun parseAdEventTime(line: String, now: Instant, zone: ZoneId): Instant? {
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

        // Fallback for logcat-style timestamp: "MM-DD HH:mm:ss.SSS"
        val short = Regex("""^\s*(\d{2})-(\d{2})\s+(\d{2}):(\d{2}):(\d{2})""").find(line) ?: return null
        val yearNow = LocalDate.now(zone).year
        val mo = short.groupValues[1].toIntOrNull() ?: return null
        val d = short.groupValues[2].toIntOrNull() ?: return null
        val h = short.groupValues[3].toIntOrNull() ?: return null
        val mi = short.groupValues[4].toIntOrNull() ?: return null
        val s = short.groupValues[5].toIntOrNull() ?: return null
        val candidate = runCatching { LocalDateTime.of(yearNow, mo, d, h, mi, s).atZone(zone).toInstant() }.getOrNull() ?: return null
        // Handle year rollover near new year.
        return if (candidate.epochSecond > now.epochSecond + 36 * 3600L) {
            runCatching { LocalDateTime.of(yearNow - 1, mo, d, h, mi, s).atZone(zone).toInstant() }.getOrNull()
        } else {
            candidate
        }
    }

    private fun buildMalwareText(s: SecurityStats): String = buildString {
        appendLine("Total suspicious incidents: ${s.totalIncidents}")
        appendLine("Malware/Virus-like incidents: ${s.malwareLike}")
        appendLine("Action blocked by ML: ${s.blockedByMl}")
        appendLine()
        appendLine("Trojan: ${s.trojan}")
        appendLine("Spyware: ${s.spyware}")
        appendLine("Virus/Worm: ${s.virus}")
        append("Ransomware: ${s.ransomware}")
    }

    private fun buildAdText(s: SecurityStats): String = buildString {
        appendLine("Blocked ad queries (Hybrid Hook): ${s.adQueryBlocked}")
        appendLine("Blocked ad packets (FA_ADS DROP): ${s.adPacketsBlocked}")
        appendLine("Blocked ad traffic size: ${humanBytes(s.adBytesBlocked)}")
        append("Mode: hybrid (LSPosed hook + firewall + ML scoring)")
    }

    private fun parseAdPackage(line: String): String? {
        val pkg = Regex("""\bin\s+([a-zA-Z0-9._]+)""").find(line)?.groupValues?.getOrNull(1)?.trim().orEmpty()
        if (pkg.isBlank()) return null
        if (pkg == "com.google.android.webview") return null
        if (pkg == "com.google.android.gms") return null
        return pkg
    }

    private fun buildCallText(s: SecurityStats): String = buildString {
        appendLine("Total telepon masuk: ${s.callTotal}")
        appendLine("Blokir otomatis: ${s.callBlockedAuto}")
        appendLine("Reject manual (blacklist): ${s.callManualReject}")
        append("Accepted: ${s.callAccepted}")
    }

    private fun collectCallStats(): CallStats {
        val pref = getSharedPreferences("call_guard", MODE_PRIVATE)
        val raw = pref.getString("events", "[]").orEmpty()
        val arr = runCatching { JSONArray(raw) }.getOrElse { JSONArray() }
        val nowMs = System.currentTimeMillis()
        val periodMs = if (selectedPeriod == Period.P24H) 24L * 3600_000L else 7L * 24L * 3600_000L
        var total = 0
        var blockedAuto = 0
        var manualReject = 0
        var accepted = 0
        val logs = mutableListOf<String>()

        for (i in 0 until arr.length()) {
            val o = arr.optJSONObject(i) ?: continue
            val ts = o.optLong("ts", 0L)
            if (ts <= 0L || (nowMs - ts) > periodMs) continue
            val blocked = o.optBoolean("blocked", false)
            val reason = o.optString("reason", "unknown")
            val number = o.optString("number", "unknown").ifBlank { "unknown" }
            total++
            when {
                !blocked -> accepted++
                reason == "blacklist" -> manualReject++
                else -> blockedAuto++
            }
            logs += "${fmtTs(Instant.ofEpochMilli(ts))} | $number | ${if (blocked) "blocked" else "accepted"} | $reason"
        }

        if (logs.isEmpty()) {
            val f = File(filesDir, "call_guard_blocked.log")
            if (f.exists()) {
                f.readLines().takeLast(12).forEach { ln ->
                    val o = runCatching { JSONObject(ln) }.getOrNull() ?: return@forEach
                    val ts = o.optLong("ts", 0L)
                    if (ts > 0L) {
                        logs += "${fmtTs(Instant.ofEpochMilli(ts))} | ${o.optString("number", "unknown")} | blocked | ${o.optString("reason", "unknown")}"
                    }
                }
            }
        }

        return CallStats(
            total = total,
            blockedAuto = blockedAuto,
            manualReject = manualReject,
            accepted = accepted,
            logs = logs,
        )
    }

    private fun fmtTs(ts: Instant): String {
        val fmt = DateTimeFormatter.ofPattern("MM-dd HH:mm:ss")
        return fmt.format(ts.atZone(ZoneId.systemDefault()))
    }

    private fun humanBytes(bytes: Long): String {
        if (bytes <= 0L) return "0 B"
        val units = arrayOf("B", "KB", "MB", "GB", "TB")
        val digitGroups = (ln(bytes.toDouble()) / ln(1024.0)).toInt().coerceAtMost(units.lastIndex)
        val value = bytes / 1024.0.pow(digitGroups.toDouble())
        return "%.2f %s".format(value, units[digitGroups])
    }

    private fun nowHuman(): String {
        val fmt = DateTimeFormatter.ofPattern("yyyy-MM-dd HH:mm:ss")
        return fmt.format(Instant.now().atZone(ZoneId.systemDefault()))
    }

    private fun dp(v: Int): Int = (v * resources.displayMetrics.density).toInt()
}

private data class CallStats(
    val total: Int,
    val blockedAuto: Int,
    val manualReject: Int,
    val accepted: Int,
    val logs: List<String>,
)

data class AdAppStat(
    val packageName: String,
    val appName: String,
    val blockedCount: Int,
)

data class SecurityStats(
    val totalIncidents: Int,
    val malwareLike: Int,
    val blockedByMl: Int,
    val trojan: Int,
    val spyware: Int,
    val virus: Int,
    val ransomware: Int,
    val adQueryBlocked: Int,
    val adPacketsBlocked: Long,
    val adBytesBlocked: Long,
    val malware24h: List<Int>,
    val malware7d: List<Int>,
    val ads24h: List<Int>,
    val ads7d: List<Int>,
    val callTotal: Int,
    val callBlockedAuto: Int,
    val callManualReject: Int,
    val callAccepted: Int,
    val malwareLogs: String,
    val adApps: List<AdAppStat>,
    val callLogs: String,
    val rawDebug: String,
)
