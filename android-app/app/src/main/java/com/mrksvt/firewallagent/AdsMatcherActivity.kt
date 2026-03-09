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
        binding.customPatternsSaveBtn.setOnClickListener { saveCustomMatchers() }
        binding.customPatternsPreviewBtn.setOnClickListener { previewCustomMatchers() }
        binding.customPatternsLoadLogBtn.setOnClickListener { loadMatcherCandidatesFromLogs() }
        binding.customPatternsAddSelectedBtn.setOnClickListener { appendSelectedMatcherCandidates() }
        binding.customPatternsAutoSelectBtn.setOnClickListener { autoSelectNewMatcherCandidates() }

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
        val custom = AdMlScorer.loadUserPatterns(this)
        val external = BlacklistFeedSync.loadCached(this).toList()
        return AdMlScorer.mergePatterns(
            AdMlScorer.mergePatterns(AdMlScorer.mergePatterns(adHostPatterns, persisted), custom),
            external,
        )
    }

    private fun loadCustomMatchers() {
        val current = AdMlScorer.loadUserPatterns(this)
        if (current.isNotEmpty()) binding.customPatternsInput.setText(current.joinToString("\n"))
        renderCustomPatternStatus(current)
    }

    private fun loadMatcherCandidatesFromLogs() {
        lifecycleScope.launch {
            binding.outputText.text = "Memindai host kandidat dari log HybridAdHook..."
            val candidates = withContext(Dispatchers.IO) {
                val raw = RootFirewallController.runRaw(
                    "grep -h -E 'FA.HybridAdHook|FA.DnsHideHook' /data/adb/lspd/log/modules_*.log 2>/dev/null | tail -n 40000",
                )
                val events = AdEventStore.mergeCurrentLog(this@AdsMatcherActivity, raw.stdout)
                val existing = buildMergedAdPatterns().toSet()
                val grouped = linkedMapOf<String, MutableMap<String, Int>>()
                events.forEach { event ->
                    val host = event.host.trim().lowercase()
                    if (host.isBlank() || host == "-") return@forEach
                    grouped.getOrPut(host) { linkedMapOf() }[event.status] =
                        (grouped.getOrPut(host) { linkedMapOf() }[event.status] ?: 0) + 1
                }
                raw.stdout.lineSequence().forEach { line ->
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
                        grouped.getOrPut(token) { linkedMapOf() }[status] =
                            (grouped.getOrPut(token) { linkedMapOf() }[status] ?: 0) + 1
                    }
                }
                grouped.entries
                    .map { (host, statusCounts) ->
                        MatcherCandidate(host = host, statusCounts = statusCounts.toMap(), alreadyMatched = host in existing)
                    }
                    .sortedWith(compareByDescending<MatcherCandidate> { it.totalCount }.thenBy { it.host })
                    .take(100)
            }
            latestMatcherCandidates = candidates
            renderMatcherCandidates(candidates)
            binding.outputText.text = "Kandidat dari log: ${candidates.size} host/token"
        }
    }

    private fun appendSelectedMatcherCandidates() {
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
        val existing = parsePatternInput(binding.customPatternsInput.text?.toString().orEmpty()).toMutableList()
        selected.forEach { host -> if (host !in existing) existing += host }
        binding.customPatternsInput.setText(existing.joinToString("\n"))
        renderCustomPatternStatus(existing)
        Toast.makeText(this, "${selected.size} matcher ditambahkan.", Toast.LENGTH_SHORT).show()
    }

    private fun autoSelectNewMatcherCandidates() {
        var selectedCount = 0
        for (i in 0 until binding.customPatternsLogContainer.childCount) {
            val row = binding.customPatternsLogContainer.getChildAt(i) as? LinearLayout ?: continue
            val top = row.getChildAt(0) as? LinearLayout ?: continue
            val cb = top.getChildAt(0) as? CheckBox ?: continue
            if (cb.isEnabled && !cb.isChecked) {
                cb.isChecked = true
                selectedCount++
            }
        }
        Toast.makeText(this, "Auto pilih: $selectedCount matcher baru.", Toast.LENGTH_SHORT).show()
    }

    private fun saveCustomMatchers() {
        lifecycleScope.launch {
            val patterns = parsePatternInput(binding.customPatternsInput.text?.toString().orEmpty())
            AdMlScorer.saveUserPatterns(this@AdsMatcherActivity, patterns)
            renderCustomPatternStatus(patterns)
            Toast.makeText(this@AdsMatcherActivity, "Ads Matcher disimpan: ${patterns.size}", Toast.LENGTH_SHORT).show()
        }
    }

    private fun previewCustomMatchers() {
        lifecycleScope.launch {
            val merged = withContext(Dispatchers.IO) { buildMergedAdPatterns() }
            binding.outputText.text = buildString {
                appendLine("=== Matcher Aktif (${merged.size}) ===")
                merged.take(150).forEach { appendLine(it) }
                if (merged.size > 150) appendLine("... ${merged.size - 150} matcher lain")
            }
            renderCustomPatternStatus(AdMlScorer.loadUserPatterns(this@AdsMatcherActivity))
        }
    }

    private fun renderCustomPatternStatus(custom: List<String>) {
        binding.customPatternsStatusText.text = buildString {
            appendLine("Custom matcher tersimpan: ${custom.size}")
            if (custom.isEmpty()) {
                appendLine("Belum ada matcher tambahan.")
            } else {
                custom.take(20).forEach { appendLine("• $it") }
                if (custom.size > 20) appendLine("... ${custom.size - 20} matcher lain")
            }
        }.trimEnd()
    }

    private fun renderMatcherCandidates(candidates: List<MatcherCandidate>) {
        val container = binding.customPatternsLogContainer
        container.removeAllViews()
        binding.customPatternsLogEmptyText.text = if (candidates.isEmpty()) {
            "Belum ada kandidat host/token dari log."
        } else {
            "Pilih host/token dari log untuk ditambahkan ke matcher:"
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
                isEnabled = !item.alreadyMatched
                if (item.alreadyMatched) {
                    text = "${item.host} (sudah aktif)"
                    setTextColor(0xFF6B7280.toInt())
                } else {
                    setTextColor(0xFFE5E7EB.toInt())
                }
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

    private fun parsePatternInput(raw: String): List<String> {
        return raw.split(Regex("[,\\n]+"))
            .map { it.trim().lowercase() }
            .map {
                when {
                    it.startsWith("http://") || it.startsWith("https://") -> runCatching { URI(it).host.orEmpty() }.getOrDefault("")
                    else -> it
                }
            }
            .map { it.removePrefix("www.") }
            .map { it.filter { ch -> ch.isLetterOrDigit() || ch == '.' || ch == '-' || ch == '_' || ch == '/' } }
            .filter { it.isNotBlank() }
            .distinct()
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
