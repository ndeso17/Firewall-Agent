package com.mrksvt.firewallagent

import android.app.ActivityManager
import android.content.pm.PackageManager
import android.graphics.drawable.Drawable
import android.os.Bundle
import android.widget.Toast
import androidx.appcompat.app.AppCompatActivity
import androidx.lifecycle.lifecycleScope
import androidx.recyclerview.widget.LinearLayoutManager
import com.mrksvt.firewallagent.databinding.ActivityRamOptimizerBinding
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext
import java.util.Locale

class RamOptimizerActivity : AppCompatActivity() {
    private lateinit var binding: ActivityRamOptimizerBinding
    private var items: List<RamAppRow> = emptyList()
    private lateinit var adapter: RamOptimizerAdapter
    private val selectedPackages = linkedSetOf<String>()
    private val appliedActionByPackage = linkedMapOf<String, String>()
    private val prefsName = "ram_optimizer_state"
    private val selectedKey = "selected_packages_csv"
    private val actionMapKey = "applied_action_json"

    data class RamAppRow(
        val packageName: String,
        val appName: String,
        val isRunning: Boolean,
        val ramMb: Double?,
        val selectable: Boolean,
        val icon: Drawable?,
        val ramLabel: String,
        val lastActionLabel: String,
    )

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        binding = ActivityRamOptimizerBinding.inflate(layoutInflater)
        setContentView(binding.root)
        restoreState()
        adapter = RamOptimizerAdapter(
            items = emptyList(),
            isChecked = { pkg -> selectedPackages.contains(pkg) },
            onCheckedChanged = { row, checked ->
                if (!row.selectable) return@RamOptimizerAdapter
                if (checked) selectedPackages += row.packageName else selectedPackages -= row.packageName
                persistState()
                binding.outputText.text = "Loaded: ${items.size} app(s) | Selected: ${selectedPackages.size}"
            },
        )
        binding.appsRecycler.layoutManager = LinearLayoutManager(this)
        binding.appsRecycler.adapter = adapter

        binding.refreshBtn.setOnClickListener { loadApps() }
        binding.forceStopBtn.setOnClickListener { applyAction("force-stop") }
        binding.freezeBtn.setOnClickListener { applyAction("freeze") }
        binding.unfreezeBtn.setOnClickListener { applyAction("unfreeze") }

        loadApps()
    }

    private fun loadApps() {
        lifecycleScope.launch {
            val loading = LoadingDialogController(this@RamOptimizerActivity)
            loading.showProgress(
                title = "RAM Optimizer",
                processed = 10,
                total = 100,
                phase = "Membaca cache daftar aplikasi...",
            )
            val cachedRows = withContext(Dispatchers.IO) { readRowsFromCache() }
            if (cachedRows.isNotEmpty()) {
                items = cachedRows
                adapter.submit(cachedRows)
                binding.outputText.text = "Loaded: ${cachedRows.size} app(s) | Selected: ${selectedPackages.size}"
                loading.updateProgress(
                    title = "RAM Optimizer",
                    processed = 70,
                    total = 100,
                    phase = "Memuat metadata proses berjalan...",
                )
                val enriched = withContext(Dispatchers.IO) { readRows() }
                items = enriched
                adapter.submit(enriched)
                binding.outputText.text = "Loaded: ${enriched.size} app(s) | Selected: ${selectedPackages.size}"
                loading.updateProgress(
                    title = "RAM Optimizer",
                    processed = 100,
                    total = 100,
                    phase = "Finalisasi...",
                )
                loading.dismissProgress()
                return@launch
            }
            loading.updateProgress(
                title = "RAM Optimizer",
                processed = 40,
                total = 100,
                phase = "Memuat daftar aplikasi penuh...",
            )
            val rows = withContext(Dispatchers.IO) { readRows() }
            items = rows
            adapter.submit(rows)
            binding.outputText.text = "Loaded: ${rows.size} app(s) | Selected: ${selectedPackages.size}"
            loading.updateProgress(
                title = "RAM Optimizer",
                processed = 100,
                total = 100,
                phase = "Finalisasi...",
            )
            loading.dismissProgress()
        }
    }

    private fun readRowsFromCache(): List<RamAppRow> {
        val runningInfo = readRunningPackages()
        val cached = AppMetaCacheStore.read(applicationContext)
        if (cached.isEmpty()) {
            val inventory = AppInventoryStore.read(applicationContext)
            if (inventory.isEmpty()) return emptyList()
            return inventory.entries
                .asSequence()
                .filter { it.value >= 10000 && it.key.isNotBlank() }
                .map { (pkg, _) ->
                    val runMeta = runningInfo[pkg]
                    val lastAction = appliedActionByPackage[pkg]
                    RamAppRow(
                        packageName = pkg,
                        appName = pkg,
                        isRunning = runMeta != null,
                        ramMb = runMeta?.ramMb,
                        selectable = pkg != packageName,
                        icon = AppIconCacheStore.load(applicationContext, pkg),
                        ramLabel = runMeta?.ramMb?.let { mb -> formatRam(mb) } ?: "-",
                        lastActionLabel = lastAction?.let { actionUiLabel(it) }.orEmpty(),
                    )
                }
                .sortedWith(compareByDescending<RamAppRow> { it.isRunning }.thenBy { it.appName.lowercase() })
                .toList()
        }
        return cached
            .asSequence()
            .filter { it.uid >= 10000 }
            .map { row ->
                val runMeta = runningInfo[row.packageName]
                val lastAction = appliedActionByPackage[row.packageName]
                RamAppRow(
                    packageName = row.packageName,
                    appName = row.appName.ifBlank { row.packageName },
                    isRunning = runMeta != null,
                    ramMb = runMeta?.ramMb,
                    selectable = row.packageName != packageName,
                    icon = AppIconCacheStore.load(applicationContext, row.packageName),
                    ramLabel = runMeta?.ramMb?.let { mb -> formatRam(mb) } ?: "-",
                    lastActionLabel = lastAction?.let { actionUiLabel(it) }.orEmpty(),
                )
            }
            .sortedWith(compareByDescending<RamAppRow> { it.isRunning }.thenBy { it.appName.lowercase() })
            .toList()
    }

    private fun readRows(): List<RamAppRow> {
        val pm = packageManager
        val runningInfo = readRunningPackages()
        val apps = pm.getInstalledApplications(PackageManager.GET_META_DATA)
            .asSequence()
            .filter { it.uid >= 10000 }
            .filter { pm.getLaunchIntentForPackage(it.packageName) != null }
            .map {
                val name = it.loadLabel(pm)?.toString()?.takeIf { n -> n.isNotBlank() } ?: it.packageName
                val runMeta = runningInfo[it.packageName]
                val lastAction = appliedActionByPackage[it.packageName]
                RamAppRow(
                    packageName = it.packageName,
                    appName = name,
                    isRunning = runMeta != null,
                    ramMb = runMeta?.ramMb,
                    selectable = it.packageName != packageName,
                    icon = runCatching { it.loadIcon(pm) }.getOrNull(),
                    ramLabel = runMeta?.ramMb?.let { mb -> formatRam(mb) } ?: "-",
                    lastActionLabel = lastAction?.let { actionUiLabel(it) }.orEmpty(),
                )
            }
            .sortedWith(compareByDescending<RamAppRow> { it.isRunning }.thenBy { it.appName.lowercase() })
            .toList()
        return apps
    }

    private data class RunMeta(val ramMb: Double?)

    private fun readRunningPackages(): Map<String, RunMeta> {
        val am = getSystemService(ACTIVITY_SERVICE) as? ActivityManager ?: return emptyMap()
        val out = linkedMapOf<String, RunMeta>()
        runCatching {
            val procList = am.runningAppProcesses.orEmpty()
            val pidToMemMb = linkedMapOf<Int, Double>()
            val pids = procList.map { it.pid }.filter { it > 0 }.toIntArray()
            if (pids.isNotEmpty()) {
                val memInfos = am.getProcessMemoryInfo(pids)
                memInfos.forEachIndexed { idx, info ->
                    val pid = pids.getOrNull(idx) ?: return@forEachIndexed
                    val totalPssKb = info.totalPss
                    if (totalPssKb > 0) {
                        pidToMemMb[pid] = totalPssKb.toDouble() / 1024.0
                    }
                }
            }
            procList.forEach { proc ->
                val mem = pidToMemMb[proc.pid]
                proc.pkgList?.forEach { pkg ->
                    val prev = out[pkg]?.ramMb
                    val chosen = when {
                        prev == null -> mem
                        mem == null -> prev
                        mem > prev -> mem
                        else -> prev
                    }
                    out[pkg] = RunMeta(chosen)
                }
            }
        }
        return out
    }

    private fun applyAction(action: String) {
        val selected = items.filter { it.selectable && it.packageName in selectedPackages }
        if (selected.isEmpty()) {
            Toast.makeText(this, "Pilih minimal 1 aplikasi.", Toast.LENGTH_SHORT).show()
            return
        }

        lifecycleScope.launch {
            val loading = LoadingDialogController(this@RamOptimizerActivity)
            loading.showProgress(
                title = "RAM Optimizer",
                processed = 5,
                total = selected.size + 2,
                phase = "Menyiapkan aksi $action...",
            )
            val result = withContext(Dispatchers.IO) {
                runActionForApps(selected, action) { done, total, pkg ->
                    runOnUiThread {
                        loading.updateProgress(
                            title = "RAM Optimizer",
                            processed = done + 1,
                            total = total + 2,
                            phase = "Memproses $pkg ($done/$total)",
                        )
                    }
                }
            }
            loading.updateProgress(
                title = "RAM Optimizer",
                processed = selected.size + 2,
                total = selected.size + 2,
                phase = "Finalisasi...",
            )
            loading.dismissProgress()
            loading.showSuccess(
                title = "RAM Optimizer Selesai",
                message = "${result.okCount}/${selected.size} aplikasi diproses.",
            )
            result.successPackages.forEach { pkg ->
                appliedActionByPackage[pkg] = action
            }
            persistState()
            binding.outputText.text = buildString {
                appendLine("Action: $action")
                appendLine("Success: ${result.okCount}/${selected.size}")
                if (result.failures.isNotEmpty()) {
                    appendLine("Failed:")
                    result.failures.take(10).forEach { appendLine("- $it") }
                }
            }.trim()
            loadApps()
        }
    }

    private data class ActionResult(
        val okCount: Int,
        val failures: List<String>,
        val successPackages: List<String>,
    )

    private fun runActionForApps(
        apps: List<RamAppRow>,
        action: String,
        onProgress: (done: Int, total: Int, pkg: String) -> Unit,
    ): ActionResult {
        var ok = 0
        val fails = mutableListOf<String>()
        val successPackages = mutableListOf<String>()
        val total = apps.size
        apps.forEachIndexed { index, app ->
            onProgress(index + 1, total, app.packageName)
            val cmd = when (action) {
                "force-stop" -> "am force-stop ${app.packageName}"
                "freeze" -> "cmd package suspend --user 0 ${app.packageName}"
                "unfreeze" -> "cmd package unsuspend --user 0 ${app.packageName}"
                else -> ""
            }
            if (cmd.isBlank()) return@forEachIndexed
            val r = RootFirewallController.runRaw(cmd)
            if (r.ok) {
                ok++
                successPackages += app.packageName
            } else {
                fails += "${app.packageName}: code=${r.code}"
            }
        }
        return ActionResult(okCount = ok, failures = fails, successPackages = successPackages)
    }

    private fun formatRam(mb: Double): String {
        return if (mb >= 1024.0) {
            String.format(Locale.US, "%.2f GB", mb / 1024.0)
        } else {
            String.format(Locale.US, "%.0f MB", mb)
        }
    }

    private fun actionUiLabel(action: String): String {
        return when (action) {
            "freeze" -> "FROZEN"
            "unfreeze" -> "UNFROZEN"
            "force-stop" -> "STOPPED"
            else -> action.uppercase(Locale.US)
        }
    }

    private fun restoreState() {
        val prefs = getSharedPreferences(prefsName, MODE_PRIVATE)
        val rawSelected = prefs.getString(selectedKey, "").orEmpty()
        selectedPackages.clear()
        if (rawSelected.isNotBlank()) {
            rawSelected.split(',')
                .map { it.trim() }
                .filter { it.isNotBlank() }
                .forEach { selectedPackages += it }
        }
        val rawAction = prefs.getString(actionMapKey, null)
        appliedActionByPackage.clear()
        if (!rawAction.isNullOrBlank()) {
            runCatching {
                val json = org.json.JSONObject(rawAction)
                json.keys().forEach { pkg ->
                    val action = json.optString(pkg, "")
                    if (pkg.isNotBlank() && action.isNotBlank()) {
                        appliedActionByPackage[pkg] = action
                    }
                }
            }
        }
    }

    private fun persistState() {
        val selectedCsv = selectedPackages.joinToString(",")
        val actionJson = org.json.JSONObject().apply {
            appliedActionByPackage.forEach { (pkg, action) -> put(pkg, action) }
        }.toString()
        getSharedPreferences(prefsName, MODE_PRIVATE)
            .edit()
            .putString(selectedKey, selectedCsv)
            .putString(actionMapKey, actionJson)
            .apply()
    }
}
