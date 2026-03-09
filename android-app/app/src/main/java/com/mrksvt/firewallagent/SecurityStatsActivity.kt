package com.mrksvt.firewallagent

import android.Manifest
import android.content.ContentValues
import android.content.Intent
import android.content.pm.PackageManager
import android.graphics.Color
import android.graphics.Typeface
import android.net.Uri
import android.os.Build
import android.os.Bundle
import android.os.Environment
import android.provider.MediaStore
import android.provider.ContactsContract
import android.view.Gravity
import android.view.View
import android.widget.ImageView
import android.widget.LinearLayout
import android.widget.TextView
import android.widget.Toast
import androidx.appcompat.app.AppCompatActivity
import androidx.core.content.ContextCompat
import androidx.lifecycle.lifecycleScope
import com.mrksvt.firewallagent.databinding.ActivitySecurityStatsBinding
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.async
import kotlinx.coroutines.coroutineScope
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
    private lateinit var loadingDialog: LoadingDialogController
    private var selectedPeriod = Period.P24H
    private var selectedAdPackage: String? = null
    private var latestStats: SecurityStats? = null
    private val snapshotPref by lazy { getSharedPreferences("fa_security_stats_cache", MODE_PRIVATE) }

    private enum class Period { P24H, P7D }

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        binding = ActivitySecurityStatsBinding.inflate(layoutInflater)
        setContentView(binding.root)
        loadingDialog = LoadingDialogController(this)

        binding.refreshBtn.setOnClickListener { refreshStats(showSuccessDialog = true) }
        binding.period24Btn.setOnClickListener {
            selectedPeriod = Period.P24H
            updatePeriodButtons()
            refreshStats(showSuccessDialog = false)
        }
        binding.period7dBtn.setOnClickListener {
            selectedPeriod = Period.P7D
            updatePeriodButtons()
            refreshStats(showSuccessDialog = false)
        }
        binding.exportCallGuardCsvBtn.setOnClickListener { exportCallGuardLogsCsv() }
        binding.exportCallGuardJsonBtn.setOnClickListener { exportCallGuardLogsJson() }
        binding.networkLogTableBtn.setOnClickListener {
            startActivity(Intent(this, NetworkLogTableActivity::class.java))
        }
        updatePeriodButtons()
        refreshStats(showSuccessDialog = true)
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

    private fun refreshStats(showSuccessDialog: Boolean) {
        lifecycleScope.launch {
            if (showSuccessDialog) {
                loadingDialog.showProgress(
                    title = "Security Stats",
                    processed = 8,
                    total = 100,
                    phase = "Memuat snapshot cache...",
                )
            }
            val hasCached = renderCachedSnapshotIfAny()
            if (!hasCached) {
                binding.malwareSummaryText.text = "Loading..."
                binding.adSummaryText.text = "Loading..."
                binding.callSummaryText.text = "Loading..."
            }
            if (showSuccessDialog) {
                loadingDialog.updateProgress(
                    title = "Security Stats",
                    processed = 34,
                    total = 100,
                    phase = "Membaca event log...",
                )
            }

            val stats = withContext(Dispatchers.IO) { collectStats() }
            if (showSuccessDialog) {
                loadingDialog.updateProgress(
                    title = "Security Stats",
                    processed = 72,
                    total = 100,
                    phase = "Menyusun ringkasan statistik...",
                )
            }
            latestStats = stats
            binding.malwareSummaryText.text = buildMalwareText(stats)
            binding.adSummaryText.text = buildAdText(stats)
            binding.adStatusTotalsText.text = buildAdStatusTotalsText(stats.adStatusTotals)
            binding.callSummaryText.text = buildCallText(stats)
            binding.malwareLogText.text = stats.malwareLogs.ifBlank { "-" }
            binding.callLogText.text = stats.callLogs.ifBlank { "-" }
            binding.lastUpdatedText.text = "Last update: ${nowHuman()}"
            renderTrend(stats)
            renderCallPie(stats)
            renderAdAppList(stats.adApps)
            renderSelectedAdApp(stats)
            saveSnapshotUi(
                malware = binding.malwareSummaryText.text?.toString().orEmpty(),
                ad = binding.adSummaryText.text?.toString().orEmpty(),
                call = binding.callSummaryText.text?.toString().orEmpty(),
                last = binding.lastUpdatedText.text?.toString().orEmpty(),
            )
            if (showSuccessDialog) {
                loadingDialog.updateProgress(
                    title = "Security Stats",
                    processed = 100,
                    total = 100,
                    phase = "Finalisasi...",
                )
                loadingDialog.dismissProgress()
                loadingDialog.showSuccess(
                    title = "Security Stats Ready",
                    message = "Data statistik berhasil dimuat.",
                )
            }
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
        if (items.isEmpty()) {
            selectedAdPackage = null
            return
        }
        if (selectedAdPackage.isNullOrBlank() || items.none { it.packageName == selectedAdPackage }) {
            selectedAdPackage = items.firstOrNull()?.packageName
        }

        items.take(20).forEach { item ->
            val row = LinearLayout(this).apply {
                orientation = LinearLayout.HORIZONTAL
                gravity = Gravity.CENTER_VERTICAL
                setPadding(dp(2), dp(6), dp(2), dp(6))
                setBackgroundColor(if (item.packageName == selectedAdPackage) Color.parseColor("#16213E") else Color.TRANSPARENT)
                isClickable = true
                isFocusable = true
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
                text = "${item.totalCount} query"
                setTextColor(Color.parseColor("#22C55E"))
                textSize = 13f
                setTypeface(typeface, Typeface.BOLD)
            }

            row.setOnClickListener {
                selectedAdPackage = item.packageName
                latestStats?.let { stats ->
                    renderAdAppList(stats.adApps)
                    renderSelectedAdApp(stats)
                }
            }
            row.addView(icon)
            row.addView(nameAndPkg)
            row.addView(countTv)
            container.addView(row)
        }
    }

    private fun renderSelectedAdApp(stats: SecurityStats) {
        val item = stats.adApps.firstOrNull { it.packageName == selectedAdPackage }
        if (item == null) {
            binding.adAppDetailTitleText.text = "Pilih aplikasi untuk melihat sebaran status."
            binding.adAppDetailSummaryText.text = "-"
            binding.adAppPieChart.setData(emptyList(), "-")
            return
        }
        binding.adAppDetailTitleText.text = "${item.appName} (${item.packageName})"
        binding.adAppDetailSummaryText.text = buildString {
            appendLine("Total event: ${item.totalCount}")
            item.statusCounts.entries.sortedByDescending { it.value }.forEachIndexed { index, entry ->
                val prefix = if (index == 0) "" else " | "
                append(prefix)
                append("${statusLabel(entry.key)}: ${entry.value}")
            }
        }.trim()
        val statusOrder = linkedSetOf("blocked", "faked", "observe")
        statusOrder.addAll(item.statusCounts.keys)
        val slices = statusOrder.mapNotNull { key ->
            val count = item.statusCounts[key] ?: 0
            if (count <= 0) null else SecurityPieChartView.Slice(statusLabel(key), count.toFloat(), statusColor(key))
        }
        binding.adAppPieChart.setData(
            items = slices,
            center = item.totalCount.toString(),
        )
    }

    private fun collectStats(): SecurityStats {
        val (tailRaw, adsDrop, adEventsRaw, callStats) = runBlockingCollectInputs()
        val lines = tailRaw.lines().filter { it.contains("[runner]") }

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

        val adParts = adsDrop.stdout.trim().split(Regex("\\s+"))
        val adPackets = adParts.getOrNull(0)?.toLongOrNull() ?: 0L
        val adBytes = adParts.getOrNull(1)?.toLongOrNull() ?: 0L

        val ads24h = IntArray(24)
        val ads7d = IntArray(7)
        var adQueryBlocked = 0
        val adStatusTotals = linkedMapOf<String, Int>()
        val allAdEvents = AdEventStore.mergeCurrentLog(applicationContext, adEventsRaw)
        val adByPkg = linkedMapOf<String, MutableMap<String, Int>>()
        val nowMs = System.currentTimeMillis()
        val adPeriodMs = if (selectedPeriod == Period.P24H) 24L * 3600_000L else 7L * 24L * 3600_000L
        allAdEvents.forEach { event ->
            if (event.ts <= 0L || (nowMs - event.ts) > adPeriodMs) return@forEach
            adStatusTotals[event.status] = (adStatusTotals[event.status] ?: 0) + 1
            if (event.status == "blocked") {
                adQueryBlocked++
                val ts = Instant.ofEpochMilli(event.ts)
                val h = ((now.epochSecond - ts.epochSecond) / 3600).toInt()
                if (h in 0..23) ads24h[23 - h]++
                val d = ((now.epochSecond - ts.epochSecond) / 86400).toInt()
                if (d in 0..6) ads7d[6 - d]++
            }
            val perStatus = adByPkg.getOrPut(event.packageName) { linkedMapOf() }
            perStatus[event.status] = (perStatus[event.status] ?: 0) + 1
        }
        val adAppStats = adByPkg.entries
            .map { (pkg, statusCounts) ->
                AdAppStat(
                    packageName = pkg,
                    appName = runCatching {
                        val ai = packageManager.getApplicationInfo(pkg, 0)
                        packageManager.getApplicationLabel(ai).toString()
                    }.getOrDefault(pkg),
                    totalCount = statusCounts.values.sum(),
                    statusCounts = statusCounts.toMap(),
                )
            }
            .sortedByDescending { it.totalCount }

        return SecurityStats(
            totalIncidents = totalIncidents,
            malwareLike = malwareLike,
            blockedByMl = blocked,
            trojan = trojan,
            spyware = spyware,
            virus = virus,
            ransomware = ransomware,
            adQueryBlocked = adQueryBlocked,
            adStatusTotals = adStatusTotals.toMap(),
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
            callLogs = buildCallLogTable(callStats.logs.takeLast(12)),
            rawDebug = buildString {
                appendLine("runner_lines=${lines.size}")
                appendLine("ads_drop_raw=${adsDrop.stdout.trim().ifBlank { "(empty)" }}")
                appendLine("ad_hook_events=${allAdEvents.size}")
                appendLine("call_events_total=${callStats.total}")
                if (adsDrop.stderr.isNotBlank()) appendLine("ads_err=${adsDrop.stderr.trim()}")
            }.trim(),
        )
    }

    private fun runBlockingCollectInputs(): QuadInputs = kotlinx.coroutines.runBlocking {
        coroutineScope {
            val tailDef = async(Dispatchers.IO) {
                LogSnapshotCache.getControllerRunnerTail(applicationContext, maxLines = 1600)
            }
            val adsDropDef = async(Dispatchers.IO) {
                RootFirewallController.runRaw(
                    "iptables -L FA_ADS -v -n 2>/dev/null | awk 'BEGIN{pk=0;by=0} /DROP/{pk+=$1;by+=$2} END{printf \"%d %d\", pk, by}'",
                )
            }
            val adEventsDef = async(Dispatchers.IO) {
                LogSnapshotCache.getHybridAdEvents(applicationContext, maxLines = 40000)
            }
            val callStatsDef = async(Dispatchers.IO) { collectCallStats() }

            QuadInputs(
                tailRaw = tailDef.await(),
                adsDrop = adsDropDef.await(),
                adEventsRaw = adEventsDef.await(),
                callStats = callStatsDef.await(),
            )
        }
    }

    private data class QuadInputs(
        val tailRaw: String,
        val adsDrop: ExecResult,
        val adEventsRaw: String,
        val callStats: CallStats,
    )

    private fun renderCachedSnapshotIfAny(): Boolean {
        val malware = snapshotPref.getString("malware", "").orEmpty()
        val ad = snapshotPref.getString("ad", "").orEmpty()
        val call = snapshotPref.getString("call", "").orEmpty()
        val last = snapshotPref.getString("last", "").orEmpty()
        if (malware.isBlank() && ad.isBlank() && call.isBlank()) return false
        if (malware.isNotBlank()) binding.malwareSummaryText.text = malware
        if (ad.isNotBlank()) binding.adSummaryText.text = ad
        if (call.isNotBlank()) binding.callSummaryText.text = call
        if (last.isNotBlank()) binding.lastUpdatedText.text = "$last (cached)"
        return true
    }

    private fun saveSnapshotUi(
        malware: String,
        ad: String,
        call: String,
        last: String,
    ) {
        snapshotPref.edit()
            .putString("malware", malware)
            .putString("ad", ad)
            .putString("call", call)
            .putString("last", last)
            .apply()
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

    private fun buildAdStatusTotalsText(totals: Map<String, Int>): String {
        if (totals.isEmpty()) return "-"
        val ordered = linkedSetOf("blocked", "faked", "observe").apply { addAll(totals.keys) }
        return ordered.mapNotNull { key ->
            val value = totals[key] ?: 0
            if (value <= 0) null else "${statusLabel(key)}: $value"
        }.joinToString(" | ").ifBlank { "-" }
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
        val canReadContacts = ContextCompat.checkSelfPermission(this, Manifest.permission.READ_CONTACTS) == PackageManager.PERMISSION_GRANTED
        val nameCache = linkedMapOf<String, String>()
        var total = 0
        var blockedAuto = 0
        var manualReject = 0
        var accepted = 0
        val logs = mutableListOf<CallLogRow>()

        for (i in 0 until arr.length()) {
            val o = arr.optJSONObject(i) ?: continue
            val ts = o.optLong("ts", 0L)
            if (ts <= 0L || (nowMs - ts) > periodMs) continue
            val blocked = o.optBoolean("blocked", false)
            val reason = o.optString("reason", "unknown")
            val number = o.optString("number", "unknown").ifBlank { "unknown" }
            val normalizedNumber = normalizePhone(number)
            val displayNumber = normalizedNumber.ifBlank { "unknown" }
            val name = resolveCallerName(displayNumber, canReadContacts, nameCache)
            total++
            when {
                !blocked -> accepted++
                reason == "blacklist" -> manualReject++
                else -> blockedAuto++
            }
            logs += CallLogRow(
                date = fmtTs(Instant.ofEpochMilli(ts)),
                name = name,
                number = displayNumber,
                status = if (blocked) "blocked" else "accepted",
                policy = reason,
            )
        }

        if (logs.isEmpty()) {
            val f = File(filesDir, "call_guard_blocked.log")
            if (f.exists()) {
                f.readLines().takeLast(12).forEach { ln ->
                    val o = runCatching { JSONObject(ln) }.getOrNull() ?: return@forEach
                    val ts = o.optLong("ts", 0L)
                    if (ts > 0L) {
                        val number = o.optString("number", "unknown").ifBlank { "unknown" }
                        val normalizedNumber = normalizePhone(number)
                        val displayNumber = normalizedNumber.ifBlank { "unknown" }
                        val name = resolveCallerName(displayNumber, canReadContacts, nameCache)
                        logs += CallLogRow(
                            date = fmtTs(Instant.ofEpochMilli(ts)),
                            name = name,
                            number = displayNumber,
                            status = "blocked",
                            policy = o.optString("reason", "unknown"),
                        )
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

    private fun resolveCallerName(number: String, canReadContacts: Boolean, cache: MutableMap<String, String>): String {
        val key = number.ifBlank { "unknown" }
        cache[key]?.let { return it }
        val fallback = spamAliasFromNumber(number)
        if (!canReadContacts || key == "unknown") {
            cache[key] = fallback
            return fallback
        }
        val name = runCatching {
            val uri = Uri.withAppendedPath(ContactsContract.PhoneLookup.CONTENT_FILTER_URI, Uri.encode(number))
            contentResolver.query(
                uri,
                arrayOf(ContactsContract.PhoneLookup.DISPLAY_NAME),
                null,
                null,
                null,
            )?.use { c ->
                if (!c.moveToFirst()) return@use null
                val idx = c.getColumnIndex(ContactsContract.PhoneLookup.DISPLAY_NAME)
                if (idx >= 0) c.getString(idx) else null
            }
        }.getOrNull()
        val resolved = name?.takeIf { it.isNotBlank() } ?: fallback
        cache[key] = resolved
        return resolved
    }

    private fun spamAliasFromNumber(number: String): String {
        val digits = normalizePhone(number)
        val suffix = when {
            digits.length >= 4 -> digits.takeLast(4)
            digits.isBlank() -> "0000"
            else -> digits.padStart(4, '0')
        }
        return "spam$suffix"
    }

    private fun normalizePhone(raw: String): String = raw.filter { it.isDigit() }

    private fun buildCallLogTable(rows: List<CallLogRow>): String {
        if (rows.isEmpty()) return "-"
        val header = listOf("No", "Date", "Nama", "Nomor", "Status", "Policy")
        val indexed = rows.mapIndexed { idx, r ->
            listOf(
                (idx + 1).toString(),
                r.date,
                r.name,
                r.number,
                r.status,
                r.policy,
            )
        }
        val allRows = listOf(header) + indexed
        val widths = IntArray(header.size) { col -> allRows.maxOf { fitCallCol(it[col], col).length } }

        fun formatRow(cols: List<String>): String =
            cols.mapIndexed { i, v -> fitCallCol(v, i).padEnd(widths[i], ' ') }.joinToString(" | ")

        val separator = widths.joinToString("-+-") { "-".repeat(it) }
        return buildString {
            appendLine(formatRow(header))
            appendLine(separator)
            indexed.forEach { appendLine(formatRow(it)) }
        }.trimEnd()
    }

    private fun fitCallCol(value: String, col: Int): String {
        val max = when (col) {
            0 -> 4
            1 -> 14
            2 -> 20
            3 -> 16
            4 -> 8
            else -> 16
        }
        return if (value.length <= max) value else value.take(max - 3) + "..."
    }

    private fun exportCallGuardLogsCsv() {
        lifecycleScope.launch {
            val rows = withContext(Dispatchers.IO) { collectCallStats().logs }
            if (rows.isEmpty()) {
                Toast.makeText(this@SecurityStatsActivity, "Tidak ada Call Guard log.", Toast.LENGTH_SHORT).show()
                return@launch
            }
            val out = withContext(Dispatchers.IO) {
                val ts = DateTimeFormatter.ofPattern("yyyyMMdd-HHmmss")
                    .format(Instant.now().atZone(ZoneId.systemDefault()))
                val fileName = "security_stats_call_guard_$ts.csv"
                val csv = buildString {
                    appendLine("no,date,nama,nomor,status,policy")
                    rows.forEachIndexed { idx, r ->
                        appendLine(
                            listOf(
                                (idx + 1).toString(),
                                r.date,
                                r.name,
                                r.number,
                                r.status,
                                r.policy,
                            ).joinToString(",") { escapeCsv(it) },
                        )
                    }
                }
                saveExportToDocuments(
                    fileName = fileName,
                    mimeType = "text/csv",
                    content = csv,
                )
            }
            if (out != null) {
                Toast.makeText(
                    this@SecurityStatsActivity,
                    "CSV disimpan: ${out.displayPath}",
                    Toast.LENGTH_LONG,
                ).show()
            } else {
                Toast.makeText(this@SecurityStatsActivity, "Export CSV gagal", Toast.LENGTH_LONG).show()
            }
        }
    }

    private fun exportCallGuardLogsJson() {
        lifecycleScope.launch {
            val rows = withContext(Dispatchers.IO) { collectCallStats().logs }
            if (rows.isEmpty()) {
                Toast.makeText(this@SecurityStatsActivity, "Tidak ada Call Guard log.", Toast.LENGTH_SHORT).show()
                return@launch
            }
            val out = withContext(Dispatchers.IO) {
                val ts = DateTimeFormatter.ofPattern("yyyyMMdd-HHmmss")
                    .format(Instant.now().atZone(ZoneId.systemDefault()))
                val fileName = "security_stats_call_guard_$ts.json"
                val arr = JSONArray()
                rows.forEachIndexed { idx, r ->
                    arr.put(
                        JSONObject()
                            .put("no", idx + 1)
                            .put("date", r.date)
                            .put("nama", r.name)
                            .put("nomor", r.number)
                            .put("status", r.status)
                            .put("policy", r.policy),
                    )
                }
                saveExportToDocuments(
                    fileName = fileName,
                    mimeType = "application/json",
                    content = arr.toString(2),
                )
            }
            if (out != null) {
                Toast.makeText(
                    this@SecurityStatsActivity,
                    "JSON disimpan: ${out.displayPath}",
                    Toast.LENGTH_LONG,
                ).show()
            } else {
                Toast.makeText(this@SecurityStatsActivity, "Export JSON gagal", Toast.LENGTH_LONG).show()
            }
        }
    }

    private fun saveExportToDocuments(fileName: String, mimeType: String, content: String): ExportResult? {
        return runCatching {
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.Q) {
                val values = ContentValues().apply {
                    put(MediaStore.MediaColumns.DISPLAY_NAME, fileName)
                    put(MediaStore.MediaColumns.MIME_TYPE, mimeType)
                    put(MediaStore.MediaColumns.RELATIVE_PATH, "${Environment.DIRECTORY_DOCUMENTS}/FirewallAgent")
                    put(MediaStore.MediaColumns.IS_PENDING, 1)
                }
                val uri = contentResolver.insert(MediaStore.Files.getContentUri("external"), values) ?: return@runCatching null
                contentResolver.openOutputStream(uri)?.use { it.write(content.toByteArray()) }
                values.clear()
                values.put(MediaStore.MediaColumns.IS_PENDING, 0)
                contentResolver.update(uri, values, null, null)
                ExportResult(
                    uri = uri,
                    displayPath = "Documents/FirewallAgent/$fileName",
                )
            } else {
                @Suppress("DEPRECATION")
                val dir = File(Environment.getExternalStoragePublicDirectory(Environment.DIRECTORY_DOCUMENTS), "FirewallAgent")
                if (!dir.exists()) dir.mkdirs()
                val file = File(dir, fileName)
                file.writeText(content)
                ExportResult(
                    uri = Uri.fromFile(file),
                    displayPath = file.absolutePath,
                )
            }
        }.getOrNull()
    }

    private fun escapeCsv(value: String): String {
        val escaped = value.replace("\"", "\"\"")
        return "\"$escaped\""
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

    private fun statusLabel(status: String): String = when (status.lowercase()) {
        "blocked" -> "Blocked"
        "faked" -> "Faked"
        "observe" -> "Observe"
        else -> status.replaceFirstChar { if (it.isLowerCase()) it.titlecase() else it.toString() }
    }

    private fun statusColor(status: String): String = when (status.lowercase()) {
        "blocked" -> "#EF4444"
        "faked" -> "#F59E0B"
        "observe" -> "#06B6D4"
        else -> "#22C55E"
    }

    private fun dp(v: Int): Int = (v * resources.displayMetrics.density).toInt()
}

private data class CallStats(
    val total: Int,
    val blockedAuto: Int,
    val manualReject: Int,
    val accepted: Int,
    val logs: List<CallLogRow>,
)

private data class CallLogRow(
    val date: String,
    val name: String,
    val number: String,
    val status: String,
    val policy: String,
)

private data class ExportResult(
    val uri: Uri,
    val displayPath: String,
)

data class AdAppStat(
    val packageName: String,
    val appName: String,
    val totalCount: Int,
    val statusCounts: Map<String, Int>,
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
    val adStatusTotals: Map<String, Int>,
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
