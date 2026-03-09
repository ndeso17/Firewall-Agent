package com.mrksvt.firewallagent

import android.graphics.Color
import android.graphics.Typeface
import android.os.Bundle
import android.text.Editable
import android.text.TextWatcher
import android.view.Gravity
import android.widget.ArrayAdapter
import android.widget.CheckBox
import android.widget.LinearLayout
import android.widget.TableRow
import android.widget.TextView
import androidx.appcompat.app.AlertDialog
import androidx.appcompat.app.AppCompatActivity
import androidx.lifecycle.lifecycleScope
import com.mrksvt.firewallagent.databinding.ActivityNetworkLogTableBinding
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext
import java.net.URI
import java.util.Locale
import kotlin.math.ceil

class NetworkLogTableActivity : AppCompatActivity() {
    private lateinit var binding: ActivityNetworkLogTableBinding
    private lateinit var loadingDialog: LoadingDialogController
    private val headerBg = Color.parseColor("#1F2937")
    private val rowEvenBg = Color.parseColor("#0F172A")
    private val rowOddBg = Color.parseColor("#111827")
    private val textSecondary = Color.parseColor("#D1D5DB")
    private val textMuted = Color.parseColor("#9CA3AF")
    private val blockedColor = Color.parseColor("#FCA5A5")
    private val allowColor = Color.parseColor("#86EFAC")

    private val pageSizeItems = listOf(10, 25, 50, 100, -1)
    private var allRows: List<RowAgg> = emptyList()
    private var filteredRows: List<RowAgg> = emptyList()
    private var pageSize: Int = 25
    private var currentPage: Int = 1
    private var searchQuery: String = ""
    private val anomalyPref by lazy { getSharedPreferences("ml_anomaly_marks", MODE_PRIVATE) }
    private val anomalyMarkKey = "marked_keys"
    private val anomalyMarks = mutableSetOf<String>()
    private val rowCachePref by lazy { getSharedPreferences("fa_network_table_cache", MODE_PRIVATE) }
    private val rowCacheKey = "rows_v1"

    data class RowAgg(
        val aggKey: String,
        var lastTime: String,
        var pkg: String,
        val address: String,
        var sampleUrl: String,
        var kind: String,
        var request: String,
        var method: String,
        var sizeBytes: Long,
        var status: String,
        var reason: String,
        var count: Int,
    )

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        binding = ActivityNetworkLogTableBinding.inflate(layoutInflater)
        setContentView(binding.root)
        loadingDialog = LoadingDialogController(this)
        setupControls()
        binding.refreshBtn.setOnClickListener { refresh(showSuccessDialog = true) }
        refresh(showSuccessDialog = true)
    }

    private fun setupControls() {
        val labels = listOf("10", "25", "50", "100", "Semua")
        val adapter = ArrayAdapter(this, android.R.layout.simple_spinner_item, labels)
        adapter.setDropDownViewResource(android.R.layout.simple_spinner_dropdown_item)
        binding.pageSizeSpinner.adapter = adapter
        binding.pageSizeSpinner.setSelection(1, false)
        binding.pageSizeSpinner.setOnItemSelectedListener(object : android.widget.AdapterView.OnItemSelectedListener {
            override fun onItemSelected(parent: android.widget.AdapterView<*>?, view: android.view.View?, position: Int, id: Long) {
                pageSize = pageSizeItems.getOrElse(position) { 25 }
                currentPage = 1
                applyFiltersAndRender()
            }
            override fun onNothingSelected(parent: android.widget.AdapterView<*>?) = Unit
        })

        binding.searchInput.addTextChangedListener(object : TextWatcher {
            override fun beforeTextChanged(s: CharSequence?, start: Int, count: Int, after: Int) = Unit
            override fun onTextChanged(s: CharSequence?, start: Int, before: Int, count: Int) = Unit
            override fun afterTextChanged(s: Editable?) {
                searchQuery = s?.toString().orEmpty().trim().lowercase(Locale.US)
                currentPage = 1
                applyFiltersAndRender()
            }
        })

        binding.prevPageBtn.setOnClickListener {
            if (currentPage > 1) {
                currentPage--
                renderCurrentPage()
            }
        }
        binding.nextPageBtn.setOnClickListener {
            val totalPage = totalPages()
            if (currentPage < totalPage) {
                currentPage++
                renderCurrentPage()
            }
        }
    }

    private fun refresh(showSuccessDialog: Boolean) {
        lifecycleScope.launch {
            if (showSuccessDialog) {
                loadingDialog.showProgress(
                    title = "Traffic Table",
                    processed = 10,
                    total = 100,
                    phase = "Membaca cache lokal...",
                )
            }
            binding.statusText.text = "Loading network logs..."
            anomalyMarks.clear()
            anomalyMarks.addAll(loadMarkedAnomalies())

            val cachedRows = withContext(Dispatchers.IO) { loadCachedRows() }
            if (cachedRows.isNotEmpty()) {
                allRows = cachedRows
                currentPage = 1
                applyFiltersAndRender()
                binding.statusText.text = "Loaded cached rows: ${cachedRows.size}, syncing latest..."
            }
            if (showSuccessDialog) {
                loadingDialog.updateProgress(
                    title = "Traffic Table",
                    processed = 44,
                    total = 100,
                    phase = "Mengagregasi network events...",
                )
            }

            val rows = withContext(Dispatchers.IO) { loadAndAggregate() }
            if (rows.isNotEmpty()) {
                withContext(Dispatchers.IO) { saveCachedRows(rows) }
            }
            allRows = rows
            currentPage = 1
            applyFiltersAndRender()
            if (showSuccessDialog) {
                loadingDialog.updateProgress(
                    title = "Traffic Table",
                    processed = 100,
                    total = 100,
                    phase = "Finalisasi...",
                )
                loadingDialog.dismissProgress()
                loadingDialog.showSuccess(
                    title = "Traffic Log Ready",
                    message = "Data tabel traffic berhasil dimuat.",
                )
            }
        }
    }

    private fun loadAndAggregate(): List<RowAgg> {
        val raw = LogSnapshotCache.getHybridNetEvents(applicationContext, maxLines = 60000)
        if (raw.isBlank()) return emptyList()

        val byAddress = linkedMapOf<String, RowAgg>()
        raw.lineSequence().forEach { line ->
            val ts = extractTimestamp(line)
            val pkg = extractField(line, "pkg").ifBlank { "-" }
            val url = extractField(line, "url")
            val host = extractField(line, "host")
            val address = when {
                host.isNotBlank() -> host.lowercase(Locale.US)
                url.isNotBlank() -> runCatching { URI(url).host.orEmpty().lowercase(Locale.US) }
                    .getOrDefault(url.lowercase(Locale.US))
                else -> "-"
            }
            if (address.isBlank() || address == "-") return@forEach

            val kind = extractField(line, "type").ifBlank { "unknown" }
            val request = extractField(line, "request").ifBlank { "download" }
            val method = extractField(line, "method").ifBlank { "UNKNOWN" }
            val size = extractField(line, "size").toLongOrNull() ?: -1L
            val status = extractField(line, "status").lowercase(Locale.US)
            val reason = extractField(line, "reason").ifBlank { "-" }
            val key = listOf(pkg, address, kind, status).joinToString("|")

            val row = byAddress.getOrPut(key) {
                RowAgg(
                    aggKey = key,
                    lastTime = ts,
                    pkg = pkg,
                    address = address,
                    sampleUrl = url,
                    kind = kind,
                    request = request,
                    method = method,
                    sizeBytes = 0L,
                    status = status,
                    reason = reason,
                    count = 0,
                )
            }
            row.lastTime = ts.ifBlank { row.lastTime }
            if (url.isNotBlank()) row.sampleUrl = url
            row.kind = mergeLabel(row.kind, kind)
            row.request = mergeLabel(row.request, request)
            row.method = mergeLabel(row.method, method)
            row.status = mergeLabel(row.status, status)
            row.reason = mergeLabel(row.reason, reason)
            if (size > 0L) row.sizeBytes += size
            row.count++
        }

        return byAddress.values.sortedWith(compareByDescending<RowAgg> { it.count }.thenBy { it.address })
    }

    private fun applyFiltersAndRender() {
        filteredRows = if (searchQuery.isBlank()) {
            allRows
        } else {
            allRows.filter { row ->
                val haystack = listOf(
                    row.pkg,
                    row.address,
                    row.sampleUrl,
                    row.kind,
                    row.request,
                    row.method,
                    row.status,
                    row.reason,
                ).joinToString(" ").lowercase(Locale.US)
                haystack.contains(searchQuery)
            }
        }
        val totalPage = totalPages()
        if (currentPage > totalPage) currentPage = totalPage
        if (currentPage < 1) currentPage = 1
        renderCurrentPage()
    }

    private fun renderCurrentPage() {
        val totalPage = totalPages()
        val pageRows = pagedRows()
        renderTable(pageRows)

        val blockedCount = filteredRows.count { it.status.equals("blocked", true) || it.status == "mixed" }
        val allowedCount = filteredRows.count { it.status.equals("acc", true) || it.status.equals("allow", true) }
        val sizeLabel = if (pageSize <= 0) "all" else pageSize.toString()
        binding.statusText.text =
            "Rows: ${filteredRows.size}/${allRows.size} | Blocked: $blockedCount | Allowed: $allowedCount | Size: $sizeLabel"
        renderPageWindowControls(currentPage, totalPage)
        binding.prevPageBtn.isEnabled = currentPage > 1
        binding.nextPageBtn.isEnabled = currentPage < totalPage
    }

    private fun totalPages(): Int {
        if (filteredRows.isEmpty()) return 1
        if (pageSize <= 0) return 1
        return ceil(filteredRows.size.toDouble() / pageSize.toDouble()).toInt().coerceAtLeast(1)
    }

    private fun pagedRows(): List<RowAgg> {
        if (filteredRows.isEmpty()) return emptyList()
        if (pageSize <= 0) return filteredRows
        val from = ((currentPage - 1) * pageSize).coerceAtLeast(0)
        if (from >= filteredRows.size) return emptyList()
        val to = (from + pageSize).coerceAtMost(filteredRows.size)
        return filteredRows.subList(from, to)
    }

    private fun renderTable(rows: List<RowAgg>) {
        binding.table.removeAllViews()
        binding.table.isShrinkAllColumns = false
        binding.table.isStretchAllColumns = false
        addHeaderRow()
        rows.forEachIndexed { index, row ->
            val tr = TableRow(this)
            tr.setBackgroundColor(if (index % 2 == 0) rowEvenBg else rowOddBg)
            val fullHost = row.address.ifBlank { "-" }
            val fullUrl = row.sampleUrl.ifBlank { "-" }
            val shortHost = shortenForTable(normalizeCompact(fullHost), 15)
            val shortUrl = shortenForTable(normalizeCompact(fullUrl), 15)
            val shortType = shortenForTable(row.kind, 15)
            tr.addView(cell(row.lastTime.ifBlank { "-" }, false, 128))
            tr.addView(cell(row.pkg, false, 190))
            tr.addView(clickableCell(shortHost, false, 124, fullHost, "Host lengkap"))
            tr.addView(clickableCell(shortUrl, false, 124, fullUrl, "URL lengkap"))
            tr.addView(cell(row.request, false, 104))
            tr.addView(cell(row.method, false, 100))
            tr.addView(cell(shortType, false, 86))
            tr.addView(cell(human(row.sizeBytes), true, 94))
            tr.addView(statusCell(row.status))
            tr.addView(actionCell(row))
            tr.addView(cell(row.reason, false, 200, 2))
            tr.addView(cell(row.count.toString(), true, 74))
            binding.table.addView(tr)
        }
    }

    private fun addHeaderRow() {
        val tr = TableRow(this).apply {
            setBackgroundColor(headerBg)
        }
        tr.addView(header("Time", 128))
        tr.addView(header("Package", 190))
        tr.addView(header("Host", 124))
        tr.addView(header("URL", 124))
        tr.addView(header("Request", 104))
        tr.addView(header("Method", 100))
        tr.addView(header("Type", 86))
        tr.addView(header("Size", 94))
        tr.addView(header("Status", 92))
        tr.addView(header("Aksi", 74, Gravity.CENTER))
        tr.addView(header("Reason", 200))
        tr.addView(header("Count", 74, Gravity.END))
        binding.table.addView(tr)
    }

    private fun actionCell(row: RowAgg): CheckBox {
        return CheckBox(this).apply {
            minWidth = dp(74)
            gravity = Gravity.CENTER
            buttonTintList = android.content.res.ColorStateList.valueOf(Color.parseColor("#F59E0B"))
            setPadding(dp(8), dp(8), dp(8), dp(8))
            setOnCheckedChangeListener(null)
            isChecked = anomalyMarks.contains(row.aggKey)
            setOnCheckedChangeListener { _, checked ->
                if (checked) anomalyMarks.add(row.aggKey) else anomalyMarks.remove(row.aggKey)
                saveMarkedAnomalies()
            }
        }
    }

    private fun header(text: String, widthDp: Int, gravity: Int = Gravity.START): TextView {
        return TextView(this).apply {
            this.text = text
            setTextColor(Color.WHITE)
            textSize = 12f
            setTypeface(typeface, Typeface.BOLD)
            setPadding(dp(8), dp(2), dp(8), dp(2))
            minWidth = dp(widthDp)
            this.gravity = Gravity.CENTER_VERTICAL or gravity
        }
    }

    private fun cell(text: String, right: Boolean, widthDp: Int, maxLines: Int = 1): TextView {
        return TextView(this).apply {
            this.text = text
            setTextColor(textSecondary)
            textSize = 12f
            setPadding(dp(8), dp(8), dp(8), dp(8))
            minWidth = dp(widthDp)
            gravity = Gravity.CENTER_VERTICAL or if (right) Gravity.END else Gravity.START
            isSingleLine = maxLines == 1
            this.maxLines = maxLines
            ellipsize = android.text.TextUtils.TruncateAt.END
        }
    }

    private fun statusCell(status: String): TextView {
        val normalized = status.lowercase(Locale.US)
        val label = when {
            normalized == "acc" -> "allow"
            normalized.isBlank() -> "-"
            else -> normalized
        }
        return cell(label, false, 92).apply {
            setTextColor(
                when (normalized) {
                    "blocked" -> blockedColor
                    "acc", "allow", "allowlisted", "allow-intent" -> allowColor
                    "mixed" -> Color.parseColor("#FDE68A")
                    else -> textMuted
                },
            )
            setTypeface(typeface, Typeface.BOLD)
        }
    }

    private fun clickableCell(text: String, right: Boolean, widthDp: Int, fullValue: String, title: String): TextView {
        return cell(text, right, widthDp).apply {
            setTextColor(Color.parseColor("#93C5FD"))
            isClickable = true
            isFocusable = true
            setOnClickListener {
                AlertDialog.Builder(this@NetworkLogTableActivity)
                    .setTitle(title)
                    .setMessage(fullValue)
                    .setPositiveButton("Tutup", null)
                    .show()
            }
        }
    }

    private fun saveMarkedAnomalies() {
        anomalyPref.edit().putStringSet(anomalyMarkKey, anomalyMarks.toSet()).apply()
    }

    private fun loadMarkedAnomalies(): Set<String> {
        return anomalyPref.getStringSet(anomalyMarkKey, emptySet())?.toSet().orEmpty()
    }

    private fun saveCachedRows(rows: List<RowAgg>) {
        val arr = org.json.JSONArray()
        rows.take(800).forEach { row ->
            arr.put(
                org.json.JSONObject()
                    .put("k", row.aggKey)
                    .put("t", row.lastTime)
                    .put("p", row.pkg)
                    .put("h", row.address)
                    .put("u", row.sampleUrl)
                    .put("y", row.kind)
                    .put("r", row.request)
                    .put("m", row.method)
                    .put("s", row.sizeBytes)
                    .put("st", row.status)
                    .put("rs", row.reason)
                    .put("c", row.count),
            )
        }
        rowCachePref.edit().putString(rowCacheKey, arr.toString()).apply()
    }

    private fun loadCachedRows(): List<RowAgg> {
        val raw = rowCachePref.getString(rowCacheKey, "").orEmpty()
        if (raw.isBlank()) return emptyList()
        val arr = runCatching { org.json.JSONArray(raw) }.getOrNull() ?: return emptyList()
        val out = ArrayList<RowAgg>(arr.length())
        for (i in 0 until arr.length()) {
            val o = arr.optJSONObject(i) ?: continue
            out += RowAgg(
                aggKey = o.optString("k"),
                lastTime = o.optString("t"),
                pkg = o.optString("p"),
                address = o.optString("h"),
                sampleUrl = o.optString("u"),
                kind = o.optString("y"),
                request = o.optString("r"),
                method = o.optString("m"),
                sizeBytes = o.optLong("s", 0L),
                status = o.optString("st"),
                reason = o.optString("rs"),
                count = o.optInt("c", 0),
            )
        }
        return out
    }

    private fun extractField(line: String, key: String): String {
        return Regex("""\b$key=([^ ]+)""").find(line)?.groupValues?.getOrNull(1)?.trim().orEmpty()
    }

    private fun extractTimestamp(line: String): String {
        val m = Regex("""^\d\d-\d\d\s+\d\d:\d\d:\d\d\.\d\d\d""").find(line)?.value
        return m.orEmpty()
    }

    private fun mergeLabel(old: String, now: String): String {
        if (old.equals(now, true)) return old
        if (old == "mixed" || now == "mixed") return "mixed"
        return "mixed"
    }

    private fun normalizeCompact(raw: String): String {
        val trimmed = raw.trim()
        if (trimmed.isBlank()) return "-"
        return trimmed
            .replace(Regex("^[a-zA-Z][a-zA-Z0-9+.-]*://"), "")
            .removePrefix("//")
            .removePrefix("www.")
    }

    private fun shortenForTable(raw: String, maxLen: Int): String {
        if (raw.length <= maxLen) return raw
        if (maxLen <= 1) return "…"
        return raw.take(maxLen - 1) + "…"
    }

    private fun renderPageWindowControls(current: Int, total: Int) {
        val container = binding.pageNumberContainer
        container.removeAllViews()
        if (total <= 0) return

        val windowSize = 5
        val (start, end) = when {
            total <= windowSize -> 1 to total
            current <= 3 -> 1 to windowSize
            current >= total - 2 -> (total - windowSize + 1) to total
            else -> (current - 2) to (current + 2)
        }
        (start..end).forEach { page ->
            val tv = TextView(this).apply {
                text = page.toString()
                textSize = 14f
                setTypeface(typeface, Typeface.BOLD)
                setPadding(dp(6), dp(4), dp(6), dp(4))
                setTextColor(if (page == current) Color.parseColor("#E5E7EB") else Color.parseColor("#9CA3AF"))
                background = if (page == current) {
                    android.graphics.drawable.GradientDrawable().apply {
                        shape = android.graphics.drawable.GradientDrawable.RECTANGLE
                        cornerRadius = dp(4).toFloat()
                        setColor(Color.parseColor("#1F2937"))
                    }
                } else {
                    null
                }
                isClickable = true
                isFocusable = true
                setOnClickListener {
                    if (currentPage != page) {
                        currentPage = page
                        renderCurrentPage()
                    }
                }
            }
            container.addView(
                tv,
                LinearLayout.LayoutParams(LinearLayout.LayoutParams.WRAP_CONTENT, LinearLayout.LayoutParams.WRAP_CONTENT),
            )
        }
        if (end < total) {
            val dots = TextView(this).apply {
                text = "..."
                textSize = 14f
                setTypeface(typeface, Typeface.BOLD)
                setTextColor(Color.parseColor("#9CA3AF"))
                setPadding(dp(4), dp(4), dp(4), dp(4))
            }
            container.addView(
                dots,
                LinearLayout.LayoutParams(LinearLayout.LayoutParams.WRAP_CONTENT, LinearLayout.LayoutParams.WRAP_CONTENT),
            )
        }
    }

    private fun dp(v: Int): Int = (v * resources.displayMetrics.density).toInt()

    private fun human(v: Long): String {
        if (v <= 0L) return "-"
        if (v < 1024L) return "${v}B"
        val kb = v / 1024.0
        if (kb < 1024.0) return String.format(Locale.US, "%.1fKB", kb)
        val mb = kb / 1024.0
        if (mb < 1024.0) return String.format(Locale.US, "%.1fMB", mb)
        return String.format(Locale.US, "%.2fGB", mb / 1024.0)
    }
}
