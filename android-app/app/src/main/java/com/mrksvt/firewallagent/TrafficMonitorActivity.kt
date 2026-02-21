package com.mrksvt.firewallagent

import android.graphics.drawable.Drawable
import android.content.Intent
import android.os.Bundle
import android.widget.AdapterView
import android.widget.ArrayAdapter
import androidx.appcompat.app.AppCompatActivity
import androidx.lifecycle.lifecycleScope
import androidx.recyclerview.widget.LinearLayoutManager
import com.mrksvt.firewallagent.databinding.ActivityTrafficMonitorBinding
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.Job
import kotlinx.coroutines.delay
import kotlinx.coroutines.isActive
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext

class TrafficMonitorActivity : AppCompatActivity() {
    private enum class Source { WIFI, CELLULAR, VPN, LAN, TOR }

    private lateinit var binding: ActivityTrafficMonitorBinding
    private var monitorJob: Job? = null
    private val uidNameCache = linkedMapOf<Int, String>()
    private val uidPkgCache = linkedMapOf<Int, String>()
    private val uidIconCache = linkedMapOf<Int, Drawable?>()
    private var uidCacheBuilt = false
    private var lastSample: TotalsSample? = null
    private var selectedSource: Source = Source.WIFI
    private lateinit var usageAdapter: TrafficAppUsageAdapter

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        binding = ActivityTrafficMonitorBinding.inflate(layoutInflater)
        setContentView(binding.root)
        usageAdapter = TrafficAppUsageAdapter(
            onDownloadClick = { item -> openFlowLog(item, "download") },
            onUploadClick = { item -> openFlowLog(item, "upload") },
        )
        binding.perAppRecycler.layoutManager = LinearLayoutManager(this)
        binding.perAppRecycler.adapter = usageAdapter
        setupSourceSpinner()
        binding.refreshBtn.setOnClickListener { refreshOnce() }
    }

    override fun onStart() {
        super.onStart()
        startMonitor()
    }

    override fun onStop() {
        monitorJob?.cancel()
        monitorJob = null
        super.onStop()
    }

    private fun startMonitor() {
        monitorJob?.cancel()
        monitorJob = lifecycleScope.launch {
            while (isActive) {
                refreshOnce()
                delay(1200)
            }
        }
    }

    private fun refreshOnce() {
        lifecycleScope.launch {
            val sample = withContext(Dispatchers.IO) { readTotalsSample() }
            val perUid = withContext(Dispatchers.IO) { readTopUidUsage() }
            val totals = formatTotals(sample, selectedSource)
            binding.totalText.text = totals
            usageAdapter.submitList(perUid)
            binding.perAppEmpty.visibility = if (perUid.isEmpty()) android.view.View.VISIBLE else android.view.View.GONE
            binding.trafficChart.setSourceLabel(sourceLabel(selectedSource))

            val prev = lastSample
            if (prev != null && sample.epochMs > prev.epochMs) {
                val dt = ((sample.epochMs - prev.epochMs).coerceAtLeast(1L)).toFloat() / 1000f
                val current = sourceBytes(sample, selectedSource)
                val previous = sourceBytes(prev, selectedSource)
                val rxKBps = (current.first - previous.first).toFloat() / dt / 1024f
                val txKBps = (current.second - previous.second).toFloat() / dt / 1024f
                binding.trafficChart.pushPoint(rxKBps, txKBps)
            }
            lastSample = sample
        }
    }

    private fun readTotalsSample(): TotalsSample {
        val cmd = "cat /proc/net/dev 2>/dev/null"
        val result = RootFirewallController.runRaw(cmd)
        if (!result.ok || result.stdout.isBlank()) {
            return TotalsSample(0L, 0L, 0L, 0L, 0L, 0L, 0L, 0L, 0L, 0L, System.currentTimeMillis())
        }

        var totalRx = 0L
        var totalTx = 0L
        var wifiRx = 0L
        var wifiTx = 0L
        var cellRx = 0L
        var cellTx = 0L
        var vpnRx = 0L
        var vpnTx = 0L
        var lanRx = 0L
        var lanTx = 0L
        var torRx = 0L
        var torTx = 0L
        result.stdout.lineSequence()
            .drop(2)
            .forEach { line ->
                val parts = line.replace(":", " ").trim().split(Regex("\\s+"))
                if (parts.size >= 10) {
                    val iface = parts[0]
                    val rx = parts.getOrNull(1)?.toLongOrNull() ?: 0L
                    val tx = parts.getOrNull(9)?.toLongOrNull() ?: 0L
                    totalRx += rx
                    totalTx += tx
                    if (iface.startsWith("wlan")) {
                        wifiRx += rx
                        wifiTx += tx
                    }
                    if (
                        iface.startsWith("rmnet") ||
                        iface.startsWith("ccmni") ||
                        iface.startsWith("pdp") ||
                        iface.startsWith("clat")
                    ) {
                        cellRx += rx
                        cellTx += tx
                    }
                    if (
                        iface.startsWith("tun") ||
                        iface.startsWith("ppp") ||
                        iface.startsWith("wg")
                    ) {
                        vpnRx += rx
                        vpnTx += tx
                    }
                    if (iface == "lo") {
                        lanRx += rx
                        lanTx += tx
                    }
                    if (iface.startsWith("tor") || iface.contains("onion", ignoreCase = true)) {
                        torRx += rx
                        torTx += tx
                    }
                }
            }
        return TotalsSample(
            totalRx,
            totalTx,
            wifiRx,
            wifiTx,
            cellRx,
            cellTx,
            vpnRx,
            vpnTx,
            lanRx + torRx, // proxy tor via loopback when tor iface not exposed by ROM.
            lanTx + torTx,
            System.currentTimeMillis(),
        )
    }

    private fun formatTotals(sample: TotalsSample, source: Source): String {
        val selected = sourceBytes(sample, source)
        return "${sourceLabel(source)} Download/Upload: ${human(selected.first)} / ${human(selected.second)}\n" +
            "Total Download/Upload: ${human(sample.totalRx)} / ${human(sample.totalTx)}"
    }

    private fun readTopUidUsage(): List<TrafficAppUsage> {
        val rawQtag = RootFirewallController.runRaw("cat /proc/net/xt_qtaguid/stats 2>/dev/null")
        if (rawQtag.ok && rawQtag.stdout.isNotBlank()) {
            val parsed = parseQtaguidRaw(rawQtag.stdout)
            if (parsed.isNotEmpty()) {
                return parsed.entries
                    .sortedByDescending { it.value.first + it.value.second }
                    .take(12)
                    .map { (uid, v) ->
                        TrafficAppUsage(
                            uid = uid,
                            appName = uidName(uid),
                            packageName = uidPackage(uid),
                            downloadBytes = v.first,
                            uploadBytes = v.second,
                            icon = uidIcon(uid),
                        )
                    }
            }
        }

        val qtaguidCmd = """
            cat /proc/net/xt_qtaguid/stats 2>/dev/null | tail -n +2 | \
            awk '{rx[$4]+=$6; tx[$4]+=$8} END {for (u in rx) printf "%s %s %s\n",u,rx[u],tx[u]}' | \
            sort -k2 -nr | head -n 12
        """.trimIndent()
        var result = RootFirewallController.runRaw(qtaguidCmd)
        if (!result.ok || result.stdout.isBlank()) {
            // Android modern fallback: parse raw dumpsys netstats in Kotlin (more robust across ROM formats).
            val dumpsys = RootFirewallController.runRaw("dumpsys netstats detail 2>/dev/null; cmd netstats detail 2>/dev/null")
            val fromDumpsys = parseUidBytesFromDumpsys(dumpsys.stdout)
            if (fromDumpsys.isNotEmpty()) {
                return fromDumpsys.entries
                    .sortedByDescending { it.value.first + it.value.second }
                    .take(12)
                    .map { (uid, v) ->
                        TrafficAppUsage(
                            uid = uid,
                            appName = uidName(uid),
                            packageName = uidPackage(uid),
                            downloadBytes = v.first,
                            uploadBytes = v.second,
                            icon = uidIcon(uid),
                        )
                    }
            }

            // Last fallback: active connections per UID (realtime activity proxy).
            val connCmd = """
                (cat /proc/net/tcp /proc/net/tcp6 /proc/net/udp /proc/net/udp6 2>/dev/null) | \
                awk 'NR>1 && NF>=8 {u[$8]++} END {for (k in u) printf "%s %s\n",k,u[k]}' | \
                sort -k2 -nr | head -n 12
            """.trimIndent()
            val conn = RootFirewallController.runRaw(connCmd)
            if (conn.ok && conn.stdout.isNotBlank()) {
                val items = conn.stdout.lineSequence().mapNotNull { row ->
                    val p = row.trim().split(Regex("\\s+"))
                    if (p.size < 2) return@mapNotNull null
                    val uid = p[0].toIntOrNull() ?: return@mapNotNull null
                    val count = p[1].toLongOrNull() ?: 0L
                    TrafficAppUsage(
                        uid = uid,
                        appName = uidName(uid),
                        packageName = uidPackage(uid),
                        downloadBytes = count,
                        uploadBytes = 0L,
                        icon = uidIcon(uid),
                    )
                }.toList()
                if (items.isNotEmpty()) return items
            }

            return emptyList()
        }

        val items = mutableListOf<TrafficAppUsage>()
        result.stdout.lineSequence().forEach { row ->
            val p = row.trim().split(Regex("\\s+"))
            if (p.size < 3) return@forEach
            val uid = p[0].toIntOrNull() ?: return@forEach
            val rx = p[1].toLongOrNull() ?: 0L
            val tx = p[2].toLongOrNull() ?: 0L
            items += TrafficAppUsage(
                uid = uid,
                appName = uidName(uid),
                packageName = uidPackage(uid),
                downloadBytes = rx,
                uploadBytes = tx,
                icon = uidIcon(uid),
            )
        }
        return items
    }

    private fun parseQtaguidRaw(text: String): Map<Int, Pair<Long, Long>> {
        val map = linkedMapOf<Int, Pair<Long, Long>>()
        text.lineSequence().drop(1).forEach { row ->
            val p = row.trim().split(Regex("\\s+"))
            if (p.size < 8) return@forEach
            val uid = p.getOrNull(3)?.toIntOrNull() ?: return@forEach
            val rx = p.getOrNull(5)?.toLongOrNull() ?: 0L
            val tx = p.getOrNull(7)?.toLongOrNull() ?: 0L
            val prev = map[uid]
            map[uid] = (prev?.first ?: 0L) + rx to (prev?.second ?: 0L) + tx
        }
        return map
    }

    private fun parseUidBytesFromDumpsys(text: String): Map<Int, Pair<Long, Long>> {
        if (text.isBlank()) return emptyMap()
        val map = linkedMapOf<Int, Pair<Long, Long>>()
        val reInline = Regex("uid[:=](\\d+).*?(?:rxBytes|rb)[:=](\\d+).*?(?:txBytes|tb)[:=](\\d+)")
        val reUid = Regex("uid[:=](\\d+)")
        val reBytes = Regex("(?:rxBytes|rb)[:=](\\d+).*?(?:txBytes|tb)[:=](\\d+)")
        var currentUid: Int? = null
        text.lineSequence().forEach { line ->
            val inline = reInline.find(line)
            if (inline != null) {
                val uid = inline.groupValues[1].toIntOrNull() ?: return@forEach
                val rx = inline.groupValues[2].toLongOrNull() ?: 0L
                val tx = inline.groupValues[3].toLongOrNull() ?: 0L
                val prev = map[uid]
                map[uid] = (prev?.first ?: 0L) + rx to (prev?.second ?: 0L) + tx
                currentUid = uid
                return@forEach
            }
            reUid.find(line)?.groupValues?.getOrNull(1)?.toIntOrNull()?.let { currentUid = it }
            val uid = currentUid ?: return@forEach
            val bytes = reBytes.find(line) ?: return@forEach
            val rx = bytes.groupValues[1].toLongOrNull() ?: 0L
            val tx = bytes.groupValues[2].toLongOrNull() ?: 0L
            val prev = map[uid]
            map[uid] = (prev?.first ?: 0L) + rx to (prev?.second ?: 0L) + tx
        }
        return map
    }

    private fun uidName(uid: Int): String {
        uidNameCache[uid]?.let { return it }
        if (!uidCacheBuilt) {
            packageManager.getInstalledPackages(0).forEach { p ->
                val u = p.applicationInfo?.uid ?: return@forEach
                if (!uidNameCache.containsKey(u)) {
                    uidNameCache[u] = p.applicationInfo?.loadLabel(packageManager)?.toString() ?: p.packageName
                }
                if (!uidPkgCache.containsKey(u)) {
                    uidPkgCache[u] = p.packageName
                }
                if (!uidIconCache.containsKey(u)) {
                    uidIconCache[u] = runCatching { p.applicationInfo?.loadIcon(packageManager) }.getOrNull()
                }
            }
            uidCacheBuilt = true
        }
        val found = uidNameCache[uid] ?: "unknown"
        uidNameCache[uid] = found
        return found
    }

    private fun uidPackage(uid: Int): String {
        uidName(uid)
        return uidPkgCache[uid] ?: "uid:$uid"
    }

    private fun uidIcon(uid: Int): Drawable? {
        uidName(uid)
        return uidIconCache[uid]
    }

    private fun human(v: Long): String {
        if (v < 1024L) return "${v}B"
        val kb = v / 1024.0
        if (kb < 1024.0) return String.format("%.1fKB", kb)
        val mb = kb / 1024.0
        if (mb < 1024.0) return String.format("%.1fMB", mb)
        return String.format("%.2fGB", mb / 1024.0)
    }

    private fun openFlowLog(item: TrafficAppUsage, direction: String) {
        startActivity(
            Intent(this, TrafficFlowLogActivity::class.java)
                .putExtra(TrafficFlowLogActivity.EXTRA_UID, item.uid)
                .putExtra(TrafficFlowLogActivity.EXTRA_APP_NAME, item.appName)
                .putExtra(TrafficFlowLogActivity.EXTRA_APP_PKG, item.packageName)
                .putExtra(TrafficFlowLogActivity.EXTRA_DIRECTION, direction),
        )
    }

    private fun sourceBytes(sample: TotalsSample, source: Source): Pair<Long, Long> = when (source) {
        Source.WIFI -> sample.wifiRx to sample.wifiTx
        Source.CELLULAR -> sample.cellRx to sample.cellTx
        Source.VPN -> sample.vpnRx to sample.vpnTx
        Source.LAN -> sample.lanRx to sample.lanTx
        Source.TOR -> sample.lanRx to sample.lanTx
    }

    private fun sourceLabel(source: Source): String = when (source) {
        Source.WIFI -> "WiFi"
        Source.CELLULAR -> "Seluler"
        Source.VPN -> "VPN"
        Source.LAN -> "LAN"
        Source.TOR -> "TOR"
    }

    private fun setupSourceSpinner() {
        val labels = listOf("WiFi", "Seluler", "VPN", "LAN", "TOR")
        binding.sourceSpinner.adapter = ArrayAdapter(this, android.R.layout.simple_spinner_dropdown_item, labels)
        binding.sourceSpinner.onItemSelectedListener = object : AdapterView.OnItemSelectedListener {
            override fun onItemSelected(parent: AdapterView<*>?, view: android.view.View?, position: Int, id: Long) {
                selectedSource = when (position) {
                    1 -> Source.CELLULAR
                    2 -> Source.VPN
                    3 -> Source.LAN
                    4 -> Source.TOR
                    else -> Source.WIFI
                }
                binding.trafficChart.resetSeries()
                lastSample = null
                refreshOnce()
            }
            override fun onNothingSelected(parent: AdapterView<*>?) = Unit
        }
    }

    private data class TotalsSample(
        val totalRx: Long,
        val totalTx: Long,
        val wifiRx: Long,
        val wifiTx: Long,
        val cellRx: Long,
        val cellTx: Long,
        val vpnRx: Long,
        val vpnTx: Long,
        val lanRx: Long,
        val lanTx: Long,
        val epochMs: Long,
    )

}
