package com.mrksvt.firewallagent

import android.os.Bundle
import android.widget.CheckBox
import android.widget.LinearLayout
import android.widget.TextView
import android.widget.Toast
import androidx.appcompat.app.AppCompatActivity
import androidx.core.content.ContextCompat
import androidx.lifecycle.lifecycleScope
import com.mrksvt.firewallagent.databinding.ActivityAdsMatcherBinding
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext
import java.net.URI

class AdsMatcherActivity : AppCompatActivity() {
    private lateinit var binding: ActivityAdsMatcherBinding
    private var latestMatcherCandidates: List<MatcherCandidate> = emptyList()
    private var logOffset = 0
    private var logTotalLines = -1

    private val adHostPatterns = listOf(
        "doubleclick.net",
        "googleads.g.doubleclick.net",
        "adservice.google.com",
        "adservice.google.",
        "googlesyndication.com",
        "admob.com",
        "unityads.",
        "applovin.",
        "ironsource.",
        "startappservice.",
        "inmobi.",
        "mintegral.",
        "vungle.com",
        "chartboost.",
        "adsystem.",
        "ads.",
        "adnxs.com",
        "criteo.com",
    )

    private data class MatcherCandidate(
        val host: String,
        val statusCounts: Map<String, Int>,
        val alreadyMatched: Boolean,
    ) {
        val totalCount: Int get() = statusCounts.values.sum()
    }

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        binding = ActivityAdsMatcherBinding.inflate(layoutInflater)
        setContentView(binding.root)

        binding.backBtn.setOnClickListener { finish() }
        binding.customPatternsSaveBtn.setOnClickListener { markSelectedAsBlacklist() }
        binding.customPatternsPreviewBtn.setOnClickListener { markSelectedAsWhitelist() }
        binding.customPatternsLoadLogBtn.setOnClickListener { loadMatcherCandidatesFromLogs() }
        binding.customPatternsAddSelectedBtn.setOnClickListener { clearSelectedFromLists() }
        binding.customPatternsAutoSelectBtn.setOnClickListener { autoSelectNewMatcherCandidates() }
        binding.viewBlacklistBtn.setOnClickListener { renderCustomListItems(AdsMatcherStore.loadBlacklist(this).toList(), "Blacklist") }
        binding.viewWhitelistBtn.setOnClickListener { renderCustomListItems(AdsMatcherStore.loadWhitelist(this).toList(), "Whitelist") }

        loadCustomMatchers()
        renderMatcherCandidates(emptyList())
    }

    private fun buildMergedAdPatterns(): List<String> {
        val hookTail = RootFirewallController.runRaw(
            "tail -n 5000 /data/adb/lspd/log/modules_*.log 2>/dev/null | " +
                "grep -E 'FA.HybridAdHook|FA.DnsHideHook' | " +
                "grep -Ei 'blocked|intercepted|observe|net observe|net blocked' || true",
        )
        AdEventStore.mergeCurrentLog(this, hookTail.stdout)
        val generated = AdMlScorer.buildMlPatternsFromEvents(
            this,
            adHostPatterns,
            maxDynamic = 80,
            minScore = 0.56,
        ) + AdMlScorer.buildMlPatterns(
            staticPatterns = adHostPatterns,
            hybridLogRaw = hookTail.stdout,
            maxDynamic = 80,
            minScore = 0.62,
        )
        if (generated.isNotEmpty()) AdMlScorer.saveDynamicPatterns(this, generated)
        val persisted = AdMlScorer.loadDynamicPatterns(this)
        val customBlacklist = AdsMatcherStore.loadBlacklist(this)
        val customWhitelist = AdsMatcherStore.loadWhitelist(this)
        val external = BlacklistFeedSync.loadCached(this).toList()
        return AdsMatcherStore.mergeBlockedPatterns(
            base = adHostPatterns,
            dynamic = persisted,
            blacklist = customBlacklist,
            external = external,
            whitelist = customWhitelist,
        )
    }

    private fun loadCustomMatchers() {
        lifecycleScope.launch(Dispatchers.IO) {
            val legacy = AdMlScorer.loadUserPatterns(this@AdsMatcherActivity)
            val currentBlacklist = AdsMatcherStore.loadBlacklist(this@AdsMatcherActivity)
            if (legacy.isNotEmpty() && currentBlacklist.isEmpty()) {
                AdsMatcherStore.saveBlacklist(this@AdsMatcherActivity, legacy.toSet())
            }
            val blacklist = AdsMatcherStore.loadBlacklist(this@AdsMatcherActivity)
            val whitelist = AdsMatcherStore.loadWhitelist(this@AdsMatcherActivity)
            withContext(Dispatchers.Main) {
                renderCustomPatternStatus(blacklist, whitelist)
            }
        }
    }

    private fun loadMatcherCandidatesFromLogs() {
        if (logTotalLines >= 0 && logOffset >= logTotalLines) {
            Toast.makeText(this, "Semua log telah dipindai ($logTotalLines baris).", Toast.LENGTH_SHORT).show()
            return
        }
        lifecycleScope.launch {
            binding.outputText.text = "Memindai 100 log kandidat dari bawah (FIFO)... Offset: $logOffset"
            val candidates = withContext(Dispatchers.IO) {
                if (logTotalLines < 0) {
                    val rawWc = RootFirewallController.runRaw("cat /data/adb/lspd/log/modules_*.log 2>/dev/null | wc -l").stdout.trim()
                    logTotalLines = rawWc.toIntOrNull() ?: 0
                }
                
                if (logTotalLines <= 0 || logOffset >= logTotalLines) {
                    return@withContext null
                }

                val chunk = 100
                val startLine = (logTotalLines - logOffset - chunk + 1).coerceAtLeast(1)
                val fetchCount = if (logTotalLines - logOffset < chunk) (logTotalLines - logOffset).coerceAtLeast(0) else chunk
                val rawStdout = if (fetchCount > 0) {
                    RootFirewallController.runRaw(
                        "tail -n +$startLine /data/adb/lspd/log/modules_*.log 2>/dev/null | head -n $fetchCount | grep -h -E 'FA.HybridAdHook|FA.DnsHideHook'"
                    ).stdout
                } else ""
                logOffset += fetchCount
                val events = AdEventStore.mergeCurrentLog(this@AdsMatcherActivity, rawStdout)
                val blacklist = AdsMatcherStore.loadBlacklist(this@AdsMatcherActivity)
                val whitelist = AdsMatcherStore.loadWhitelist(this@AdsMatcherActivity)
                val normalizedBlacklist = blacklist.map { AdsMatcherStore.normalize(it) }.toSet()
                val normalizedWhitelist = whitelist.map { AdsMatcherStore.normalize(it) }.toSet()
                val existing = (
                    adHostPatterns + 
                    AdMlScorer.loadDynamicPatterns(this@AdsMatcherActivity) + 
                    blacklist +
                    whitelist +
                    BlacklistFeedSync.loadCached(this@AdsMatcherActivity)
                ).map { AdsMatcherStore.normalize(it) }.toSet()
                val grouped = linkedMapOf<String, MutableMap<String, Int>>()
                events.forEach { event ->
                    val host = AdsMatcherStore.normalize(event.host.trim().lowercase())
                    if (host.isBlank() || host == "-") return@forEach
                    grouped.getOrPut(host) { linkedMapOf() }[event.status] =
                        (grouped.getOrPut(host) { linkedMapOf() }[event.status] ?: 0) + 1
                }
                rawStdout.lineSequence().forEach { line ->
                    val lower = line.lowercase()
                    val status = when {
                        lower.contains("status=blocked") || lower.contains(" net blocked ") || lower.contains(" blocked ") -> "blocked"
                        lower.contains("status=acc") || lower.contains(" net event ") -> "acc"
                        else -> ""
                    }
                    if (status.isBlank()) return@forEach
                    val url = Regex("""\burl=([^\s]+)""").find(line)?.groupValues?.getOrNull(1).orEmpty()
                    if (url.isBlank()) return@forEach
                    extractAdPathTokens(url).forEach { token ->
                        val n = AdsMatcherStore.normalize(token)
                        if (n.isNotBlank()) {
                            grouped.getOrPut(n) { linkedMapOf() }[status] =
                                (grouped.getOrPut(n) { linkedMapOf() }[status] ?: 0) + 1
                        }
                    }
                }
                grouped.entries
                    .filterNot { (host, _) ->
                        val n = AdsMatcherStore.normalize(host)
                        n in normalizedBlacklist || n in normalizedWhitelist
                    }
                    .map { (host, statusCounts) ->
                        val n = AdsMatcherStore.normalize(host)
                        MatcherCandidate(host = host, statusCounts = statusCounts.toMap(), alreadyMatched = n in existing)
                    }
                    .sortedWith(compareByDescending<MatcherCandidate> { it.totalCount }.thenBy { it.host })
                    .take(100)
            }
            if (candidates == null) {
                binding.outputText.text = "Pemindaian selesai: semua log telah dipindai ($logTotalLines baris)."
                return@launch
            }
            latestMatcherCandidates = candidates
            renderMatcherCandidates(candidates)
            binding.outputText.text = "Kandidat dari log: ${candidates.size} host/token"
        }
    }

    private fun markSelectedAsBlacklist() {
        val wasBlacklist = binding.customPatternsLogEmptyText.text.toString().contains("Blacklist")
        val wasWhitelist = binding.customPatternsLogEmptyText.text.toString().contains("Whitelist")

        val selected = mutableListOf<String>()
        for (i in 0 until binding.customPatternsLogContainer.childCount) {
            val row = binding.customPatternsLogContainer.getChildAt(i) as? LinearLayout ?: continue
            val top = row.getChildAt(0) as? LinearLayout ?: continue
            val cb = top.getChildAt(0) as? CheckBox ?: continue
            if (cb.isChecked) selected += (cb.tag as? String ?: continue)
        }
        if (selected.isEmpty()) {
            Toast.makeText(this, "Tidak ada host/token yang dipilih.", Toast.LENGTH_SHORT).show()
            return
        }
        val blacklist = AdsMatcherStore.loadBlacklist(this).toMutableSet()
        val whitelist = AdsMatcherStore.loadWhitelist(this).toMutableSet()
        selected.forEach {
            blacklist += it
            whitelist -= it
        }
        AdsMatcherStore.saveBlacklist(this, blacklist)
        AdsMatcherStore.saveWhitelist(this, whitelist)
        renderCustomPatternStatus(blacklist, whitelist)
        
        if (wasBlacklist) {
            renderCustomListItems(blacklist.toList(), "Blacklist")
        } else if (wasWhitelist) {
            renderCustomListItems(whitelist.toList(), "Whitelist")
        } else {
            latestMatcherCandidates = latestMatcherCandidates.filterNot { it.host in selected }
            renderMatcherCandidates(latestMatcherCandidates)
        }
        Toast.makeText(this, "${selected.size} host disimpan ke blacklist.", Toast.LENGTH_SHORT).show()
    }

    private fun markSelectedAsWhitelist() {
        val wasBlacklist = binding.customPatternsLogEmptyText.text.toString().contains("Blacklist")
        val wasWhitelist = binding.customPatternsLogEmptyText.text.toString().contains("Whitelist")

        val selected = mutableListOf<String>()
        for (i in 0 until binding.customPatternsLogContainer.childCount) {
            val row = binding.customPatternsLogContainer.getChildAt(i) as? LinearLayout ?: continue
            val top = row.getChildAt(0) as? LinearLayout ?: continue
            val cb = top.getChildAt(0) as? CheckBox ?: continue
            if (cb.isChecked) selected += (cb.tag as? String ?: continue)
        }
        if (selected.isEmpty()) {
            Toast.makeText(this, "Tidak ada host/token yang dipilih.", Toast.LENGTH_SHORT).show()
            return
        }
        val blacklist = AdsMatcherStore.loadBlacklist(this).toMutableSet()
        val whitelist = AdsMatcherStore.loadWhitelist(this).toMutableSet()
        selected.forEach {
            whitelist += it
            blacklist -= it
        }
        AdsMatcherStore.saveBlacklist(this, blacklist)
        AdsMatcherStore.saveWhitelist(this, whitelist)
        renderCustomPatternStatus(blacklist, whitelist)
        
        if (wasBlacklist) {
            renderCustomListItems(blacklist.toList(), "Blacklist")
        } else if (wasWhitelist) {
            renderCustomListItems(whitelist.toList(), "Whitelist")
        } else {
            latestMatcherCandidates = latestMatcherCandidates.filterNot { it.host in selected }
            renderMatcherCandidates(latestMatcherCandidates)
        }
        Toast.makeText(this, "${selected.size} host disimpan ke whitelist.", Toast.LENGTH_SHORT).show()
    }

    private fun clearSelectedFromLists() {
        val wasBlacklist = binding.customPatternsLogEmptyText.text.toString().contains("Blacklist")
        val wasWhitelist = binding.customPatternsLogEmptyText.text.toString().contains("Whitelist")

        val selected = mutableListOf<String>()
        for (i in 0 until binding.customPatternsLogContainer.childCount) {
            val row = binding.customPatternsLogContainer.getChildAt(i) as? LinearLayout ?: continue
            val top = row.getChildAt(0) as? LinearLayout ?: continue
            val cb = top.getChildAt(0) as? CheckBox ?: continue
            if (cb.isChecked) selected += (cb.tag as? String ?: continue)
        }
        if (selected.isEmpty()) {
            Toast.makeText(this, "Tidak ada host/token yang dipilih.", Toast.LENGTH_SHORT).show()
            return
        }
        val blacklist = AdsMatcherStore.loadBlacklist(this).toMutableSet()
        val whitelist = AdsMatcherStore.loadWhitelist(this).toMutableSet()
        selected.forEach {
            blacklist -= it
            whitelist -= it
        }
        AdsMatcherStore.saveBlacklist(this, blacklist)
        AdsMatcherStore.saveWhitelist(this, whitelist)
        renderCustomPatternStatus(blacklist, whitelist)
        
        if (wasBlacklist) {
            renderCustomListItems(blacklist.toList(), "Blacklist")
        } else if (wasWhitelist) {
            renderCustomListItems(whitelist.toList(), "Whitelist")
        } else {
            latestMatcherCandidates = latestMatcherCandidates.filterNot { it.host in selected }
            renderMatcherCandidates(latestMatcherCandidates)
        }
        Toast.makeText(this, "Status host terpilih dibersihkan.", Toast.LENGTH_SHORT).show()
    }

    private fun autoSelectNewMatcherCandidates() {
        var selectedCount = 0
        for (i in 0 until binding.customPatternsLogContainer.childCount) {
            val row = binding.customPatternsLogContainer.getChildAt(i) as? LinearLayout ?: continue
            val top = row.getChildAt(0) as? LinearLayout ?: continue
            val cb = top.getChildAt(0) as? CheckBox ?: continue
            if (!cb.isChecked) {
                cb.isChecked = true
                selectedCount++
            }
        }
        Toast.makeText(this, "Auto pilih: $selectedCount host.", Toast.LENGTH_SHORT).show()
    }

    private fun renderCustomPatternStatus(blacklist: Set<String>, whitelist: Set<String>) {
        binding.customPatternsStatusText.text = "Memperbarui info matcher..."
        lifecycleScope.launch {
            val merged = withContext(Dispatchers.IO) { buildMergedAdPatterns() }
            binding.customPatternsStatusText.text = buildString {
                appendLine("Blacklist: ${blacklist.size}")
                appendLine("Whitelist: ${whitelist.size}")
                appendLine("Matcher aktif (efektif): ${merged.size}")
                appendLine()
                appendLine("Top blacklist:")
                blacklist.take(10).forEach { appendLine("• $it") }
                if (blacklist.isEmpty()) appendLine("-")
                appendLine()
                appendLine("Top whitelist:")
                whitelist.take(10).forEach { appendLine("• $it") }
                if (whitelist.isEmpty()) appendLine("-")
            }.trimEnd()
        }
    }

    private fun renderMatcherCandidates(candidates: List<MatcherCandidate>) {
        val blacklist = AdsMatcherStore.loadBlacklist(this)
        val whitelist = AdsMatcherStore.loadWhitelist(this)
        val container = binding.customPatternsLogContainer
        container.removeAllViews()
        binding.customPatternsLogEmptyText.text = if (candidates.isEmpty()) {
            "Belum ada kandidat host/token dari log."
        } else {
            "Pilih host/token dari log, lalu set sebagai blacklist/whitelist:"
        }
        latestMatcherCandidates = candidates
        if (candidates.isEmpty()) return

        candidates.forEach { item ->
            val row = LinearLayout(this).apply {
                orientation = LinearLayout.VERTICAL
                setPadding(0, dp(4), 0, dp(4))
            }
            val top = LinearLayout(this).apply { orientation = LinearLayout.HORIZONTAL }
            val cb = CheckBox(this).apply {
                text = item.host
                tag = item.host
                val status = when {
                    item.host in blacklist -> "BLACKLIST"
                    item.host in whitelist -> "WHITELIST"
                    item.alreadyMatched -> "ACTIVE"
                    else -> "NEW"
                }
                text = "${item.host} [$status]"
                setTextColor(0xFFE5E7EB.toInt())
                buttonTintList = ContextCompat.getColorStateList(this@AdsMatcherActivity, android.R.color.holo_green_light)
            }
            val stats = TextView(this).apply {
                text = item.statusCounts.entries
                    .sortedByDescending { it.value }
                    .joinToString(" | ") { "${it.key}:${it.value}" }
                setTextColor(0xFF9CA3AF.toInt())
                textSize = 11f
                setPadding(dp(32), 0, 0, 0)
            }
            top.addView(cb)
            row.addView(top)
            row.addView(stats)
            container.addView(row)
        }
    }

    private fun renderCustomListItems(items: List<String>, title: String) {
        val container = binding.customPatternsLogContainer
        container.removeAllViews()
        binding.customPatternsLogEmptyText.text = if (items.isEmpty()) {
            "List $title kosong."
        } else {
            "Item dalam $title (Pilih untuk memindahkan status):"
        }
        
        items.forEach { itemHost ->
            val row = LinearLayout(this).apply {
                orientation = LinearLayout.VERTICAL
                setPadding(0, dp(4), 0, dp(4))
            }
            val top = LinearLayout(this).apply { orientation = LinearLayout.HORIZONTAL }
            val cb = CheckBox(this).apply {
                text = itemHost
                tag = itemHost
                setTextColor(0xFFE5E7EB.toInt())
                buttonTintList = ContextCompat.getColorStateList(this@AdsMatcherActivity, android.R.color.holo_blue_light)
            }
            top.addView(cb)
            row.addView(top)
            container.addView(row)
        }
    }

    private fun extractAdPathTokens(urlRaw: String): List<String> {
        if (urlRaw.isBlank()) return emptyList()
        val lower = urlRaw.lowercase()
        val tokenHits = linkedSetOf<String>()
        val markers = listOf(
            "pagead", "adview", "adnw_sync2", "adnw", "doubleclick", "googleads",
            "adservice", "googlesyndication", "adx", "omsdk", "mraid", "vast",
            "beacon", "interstitial", "rewarded", "reward", "tracking", "clickid", "utm_",
        )
        markers.forEach { marker -> if (lower.contains(marker)) tokenHits += marker }
        runCatching {
            val uri = URI(urlRaw)
            val path = uri.path.orEmpty().lowercase()
            if (path.isNotBlank()) {
                path.split('/').forEach { seg ->
                    val s = seg.trim()
                    if (s.length >= 4 && markers.any { s.contains(it) }) tokenHits += s
                }
            }
        }
        return tokenHits.toList()
    }

    private fun dp(v: Int): Int = (v * resources.displayMetrics.density).toInt()
}
