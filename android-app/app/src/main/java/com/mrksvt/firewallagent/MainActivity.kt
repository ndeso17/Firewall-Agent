package com.mrksvt.firewallagent

import android.Manifest
import android.content.BroadcastReceiver
import android.content.Context
import android.content.Intent
import android.content.IntentFilter
import android.content.pm.ApplicationInfo
import android.content.pm.PackageManager
import android.graphics.drawable.Drawable
import android.net.Uri
import android.os.Build
import android.os.Bundle
import android.os.Looper
import android.os.PowerManager
import android.provider.Settings
import android.telephony.TelephonyManager
import android.util.Log
import android.view.Menu
import android.view.MenuItem
import android.view.View
import android.widget.AdapterView
import android.widget.ArrayAdapter
import android.widget.EditText
import android.widget.LinearLayout
import android.widget.PopupMenu
import android.widget.ProgressBar
import android.widget.TextView
import android.widget.Toast
import androidx.activity.result.contract.ActivityResultContracts
import androidx.appcompat.app.AlertDialog
import androidx.appcompat.app.AppCompatActivity
import androidx.compose.animation.core.LinearOutSlowInEasing
import androidx.compose.animation.core.animateFloatAsState
import androidx.compose.animation.core.tween
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.material3.CircularProgressIndicator
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Text
import androidx.compose.material3.Surface
import androidx.compose.runtime.Composable
import androidx.compose.runtime.MutableState
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.core.content.ContextCompat
import androidx.lifecycle.lifecycleScope
import androidx.recyclerview.widget.LinearLayoutManager
import androidx.compose.ui.Alignment
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.platform.ComposeView
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import com.mrksvt.firewallagent.databinding.ActivityMainBinding
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.Job
import kotlinx.coroutines.isActive
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext
import org.json.JSONObject
import java.util.Locale
import kotlin.math.roundToInt

class MainActivity : AppCompatActivity() {
    private val tag = "FA.PackageAddedUI"
    private lateinit var binding: ActivityMainBinding
    private lateinit var adapter: AppRulesAdapter

    private var rootAvailable = false
    private var allApps: List<AppRuleEntry> = emptyList()
    private var currentFilter: String = "all"
    private var sortBy: String = "name"
    private var checkboxMode: String = "allow"
    private var searchQuery: String = ""
    private var visibleRows: List<AppRuleEntry> = emptyList()
    private var currentServiceState: String = "unknown"
    private var currentMlState: String = "unknown"
    private var currentFirewallEnabled: Boolean = false
    private var currentMode: String = "audit"
    private var currentProfile: String = "anlap"
    private val availableProfiles = mutableListOf<String>()
    private var suppressProfileSelection = false
    private val shadowPrefsName = "fw_shadow_rules"
    private val shadowKeyBlockedUids = "blocked_uids_csv"
    private val shadowKeyRuleState = "rule_state_json"
    private val profilePrefsName = "fw_profiles"
    private val profileListKey = "profiles_csv"
    private val profileActiveKey = "active_profile"
    private val knownPackagesPrefName = "fw_known_packages"
    private val knownPackagesKey = "known_csv"
    private val bulkPrefsName = "fw_bulk_snapshot"
    private val bulkSnapshotKey = "last_bulk_snapshot"
    private val sessionNewPackages = mutableListOf<String>()
    private var packageEventsRegistered = false
    private var applyProgressDialog: AlertDialog? = null
    private var applyProgressState: MutableState<ApplyProgressModel>? = null
    private var backendBusyDialog: AlertDialog? = null
    private var backendBusyDepth: Int = 0
    private var appInForeground: Boolean = false
    private var packageRefreshJob: Job? = null
    private var inventoryObserveJob: Job? = null
    private var lastPackageSnapshot: Set<String> = emptySet()
    private var lastInventoryVersion: Long = 0L
    private var appsReloadJob: Job? = null
    @Volatile private var appsLoadInProgress: Boolean = false
    @Volatile private var pendingAppsReload: Boolean = false
    private var lastProgressNotifProcessed: Int = -1
    private var lastProgressNotifAtMs: Long = 0L
    private var lastProgressUiProcessed: Int = -1
    private var lastProgressUiAtMs: Long = 0L
    private var applyInProgress: Boolean
        get() = applyState.inProgress
        set(value) {
            applyState.inProgress = value
        }
    private var latestApplyProgress: ApplyProgressModel
        get() = applyState.progress
        set(value) {
            applyState.progress = value
        }
    private var pendingApplySummary: PendingApplySummary?
        get() = applyState.pendingSummary
        set(value) {
            applyState.pendingSummary = value
        }

    private val notifPermLauncher = registerForActivityResult(
        ActivityResultContracts.RequestPermission(),
    ) { /* no-op */ }

    private val packageChangedReceiver = object : BroadcastReceiver() {
        override fun onReceive(context: Context, intent: Intent?) {
            val action = intent?.action ?: return
            val pkg = (
                intent.getStringExtra("pkg")
                    ?: intent.data?.schemeSpecificPart
            )?.trim().orEmpty()
            if (pkg.isBlank()) return
            when (action) {
                Intent.ACTION_PACKAGE_ADDED, FirewallKeepAliveService.ACTION_INTERNAL_PACKAGE_ADDED -> {
                    if (intent.getBooleanExtra(Intent.EXTRA_REPLACING, false)) return
                    val uid = intent.getIntExtra(
                        Intent.EXTRA_UID,
                        intent.getIntExtra("uid", -1),
                    )
                    lifecycleScope.launch {
                        withContext(Dispatchers.IO) {
                            writeDefaultDenyForPackageAllProfiles(pkg)
                            if (
                                uid > 0 &&
                                rootAvailable &&
                                currentFirewallEnabled &&
                                RootFirewallController.isManagedAppUid(uid)
                            ) {
                                val denyRule = AppNetRule(
                                    uid = uid,
                                    local = false,
                                    wifi = false,
                                    cellular = false,
                                    roaming = false,
                                    vpn = false,
                                    bluetooth = false,
                                    tor = false,
                                    download = false,
                                    upload = false,
                                )
                                RootFirewallController.applyAppRulesIncremental(
                                    upsertRules = listOf(denyRule),
                                    removeUids = emptySet(),
                                ) { _, _ -> }
                            }
                            markKnownPackagesAdded(setOf(pkg))
                        }
                        markPackageAsSessionNew(pkg)
                        upsertSinglePackageInMemory(pkg, uid)
                        if (action == FirewallKeepAliveService.ACTION_INTERNAL_PACKAGE_ADDED) {
                            Log.i(tag, "internal package added event pkg=$pkg uid=$uid")
                        }
                        refreshList()
                        requestInventorySync("package_added_verify:$pkg")
                    }
                }
                Intent.ACTION_PACKAGE_FULLY_REMOVED -> {
                    lifecycleScope.launch {
                        withContext(Dispatchers.IO) {
                            removeKnownPackage(pkg)
                        }
                        sessionNewPackages.remove(pkg)
                        allApps = allApps.filterNot { it.packageName == pkg }
                        refreshList()
                        requestInventorySync("package_removed_verify:$pkg")
                    }
                }
            }
        }
    }

    override fun onDestroy() {
        sessionNewPackages.clear()
        dismissApplyProgressDialog()
        dismissBackendBusyDialog()
        super.onDestroy()
    }

    override fun onStart() {
        super.onStart()
        appInForeground = true
        registerPackageEvents()
        startInventoryObserver()
        startPackageAutoRefresh()
        forceCleanupOrphansOnOpen()
        requestInventorySync("onStart")
        if (applyInProgress && applyProgressDialog == null) {
            showApplyProgressDialog(
                latestApplyProgress.processed,
                latestApplyProgress.totalUid,
                latestApplyProgress.totalApps,
            )
        }
        if (!applyInProgress && backendBusyDepth > 0 && backendBusyDialog == null) {
            showBackendBusyDialog()
        }
        pendingApplySummary?.let { pending ->
            pendingApplySummary = null
            showApplyResultDialog(pending.title, pending.message)
        }
    }

    override fun onStop() {
        appInForeground = false
        stopInventoryObserver()
        stopPackageAutoRefresh()
        unregisterPackageEvents()
        if (backendBusyDepth > 0) {
            dismissBackendBusyDialog()
        }
        if (applyInProgress) {
            dismissApplyProgressDialog()
        }
        super.onStop()
    }

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        binding = ActivityMainBinding.inflate(layoutInflater)
        setContentView(binding.root)

        RootFirewallController.init(applicationContext)
        NotifyHelper.ensureChannel(this)
        ensureKeepAliveService()
        promptIgnoreBatteryOptimizationIfNeeded()
        requestNotifIfNeeded()

        adapter = AppRulesAdapter(emptyList()) { saveAppPerm(it) }
        binding.appsRecycler.layoutManager = LinearLayoutManager(this)
        binding.appsRecycler.adapter = adapter
        binding.appsScroll.post { binding.appsScroll.scrollTo(0, 0) }

        initProfileUi()
        setSearchMode(false)

        binding.toolSearchBtn.setOnClickListener {
            setSearchMode(true)
        }
        binding.searchBackBtn.setOnClickListener {
            binding.searchTopInput.setText("")
            searchQuery = ""
            setSearchMode(false)
            refreshList()
        }
        binding.searchTopInput.addTextChangedListener(SimpleTextWatcher {
            searchQuery = binding.searchTopInput.text?.toString()?.trim().orEmpty()
            refreshList()
        })
        binding.toolSortBtn.setOnClickListener { openSortMenu() }
        binding.toolModeBtn.setOnClickListener { openModeMenu() }
        binding.toolMenuBtn.setOnClickListener { openMainMenu() }

        binding.filterGroup.setOnCheckedChangeListener { _, checkedId ->
            currentFilter = when (checkedId) {
                R.id.filterCore -> "core"
                R.id.filterSystem -> "system"
                R.id.filterUser -> "user"
                R.id.filterProtected -> "protected"
                else -> "all"
            }
            refreshList()
        }
        binding.statusFab.setOnClickListener { onStatusFabClicked() }

        handleLaunchIntent(intent)
        checkRootAndLoad()
    }

    private fun promptIgnoreBatteryOptimizationIfNeeded() {
        if (Build.VERSION.SDK_INT < Build.VERSION_CODES.M) return
        val pm = getSystemService(Context.POWER_SERVICE) as? PowerManager ?: return
        if (pm.isIgnoringBatteryOptimizations(packageName)) return

        val prefs = getSharedPreferences("fw_runtime", MODE_PRIVATE)
        if (prefs.getBoolean("battery_opt_prompt_shown", false)) return
        prefs.edit().putBoolean("battery_opt_prompt_shown", true).apply()

        AlertDialog.Builder(this)
            .setTitle("Optimasi Baterai")
            .setMessage(
                "Agar firewall stabil di latar belakang, izinkan Firewall Agent untuk mengabaikan optimasi baterai.",
            )
            .setPositiveButton("Izinkan") { _, _ ->
                openBatteryOptimizationSettings()
            }
            .setNegativeButton("Nanti", null)
            .show()
    }

    private fun openBatteryOptimizationSettings() {
        val specificIntent = Intent(Settings.ACTION_REQUEST_IGNORE_BATTERY_OPTIMIZATIONS).apply {
            data = Uri.parse("package:$packageName")
        }
        val globalIntent = Intent(Settings.ACTION_IGNORE_BATTERY_OPTIMIZATION_SETTINGS)

        val opened = runCatching {
            if (specificIntent.resolveActivity(packageManager) != null) {
                startActivity(specificIntent)
                true
            } else if (globalIntent.resolveActivity(packageManager) != null) {
                startActivity(globalIntent)
                false
            } else {
                false
            }
        }.getOrDefault(false)

        if (!opened) {
            Toast.makeText(
                this,
                "Menu khusus tidak tersedia. Buka manual: Settings > Battery > Battery optimization, lalu allow Firewall Agent.",
                Toast.LENGTH_LONG,
            ).show()
        }
    }

    override fun onNewIntent(intent: Intent) {
        super.onNewIntent(intent)
        setIntent(intent)
        handleLaunchIntent(intent)
    }

    private fun initProfileUi() {
        val pref = getSharedPreferences(profilePrefsName, MODE_PRIVATE)
        val raw = pref.getString(profileListKey, "anlap").orEmpty()
        val loaded = raw.split(',')
            .map { it.trim() }
            .filter { it.isNotBlank() }
            .distinct()
            .toMutableList()
        if (loaded.isEmpty()) loaded += "anlap"
        availableProfiles.clear()
        availableProfiles.addAll(loaded)
        val savedActive = pref.getString(profileActiveKey, loaded.first()).orEmpty().ifBlank { loaded.first() }
        currentProfile = if (savedActive in availableProfiles) savedActive else availableProfiles.first()
        persistProfileState()

        val spinnerAdapter = ArrayAdapter(
            this,
            android.R.layout.simple_spinner_item,
            availableProfiles,
        ).also { it.setDropDownViewResource(android.R.layout.simple_spinner_dropdown_item) }
        binding.profileSpinner.adapter = spinnerAdapter
        val idx = availableProfiles.indexOf(currentProfile).coerceAtLeast(0)
        suppressProfileSelection = true
        binding.profileSpinner.setSelection(idx)
        suppressProfileSelection = false
        binding.profileSpinner.onItemSelectedListener = object : AdapterView.OnItemSelectedListener {
            override fun onItemSelected(parent: AdapterView<*>?, view: View?, position: Int, id: Long) {
                if (suppressProfileSelection) return
                val selected = availableProfiles.getOrNull(position) ?: return
                if (selected == currentProfile) return
                switchProfile(selected)
            }
            override fun onNothingSelected(parent: AdapterView<*>?) = Unit
        }
    }

    private fun persistProfileState() {
        getSharedPreferences(profilePrefsName, MODE_PRIVATE)
            .edit()
            .putString(profileListKey, availableProfiles.joinToString(","))
            .putString(profileActiveKey, currentProfile)
            .apply()
    }

    private fun profileScopedRulesPref(profile: String = currentProfile): String {
        val key = profile.lowercase(Locale.ROOT)
            .replace(Regex("[^a-z0-9._-]"), "_")
            .ifBlank { "default" }
        return "fw_app_rules_$key"
    }

    private fun profileScopedShadowPref(profile: String = currentProfile): String {
        val key = profile.lowercase(Locale.ROOT)
            .replace(Regex("[^a-z0-9._-]"), "_")
            .ifBlank { "default" }
        return "${shadowPrefsName}_$key"
    }

    private fun switchProfile(target: String) {
        // Simpan draft profile saat ini dulu agar perubahan checkbox langsung persist per-profile,
        // meski user belum Apply (Apply hanya untuk rewrite iptables).
        saveAllCurrentPermsToProfile(currentProfile)
        currentProfile = target
        persistProfileState()
        reloadPermsForCurrentProfile()
        val count = countProfileRuleEntries(currentProfile)
        Toast.makeText(this, "Profile aktif: $currentProfile (rules: $count)", Toast.LENGTH_SHORT).show()
    }

    private fun ensureProfileExists(target: String) {
        if (target !in availableProfiles) {
            availableProfiles += target
            (binding.profileSpinner.adapter as? ArrayAdapter<*>)?.notifyDataSetChanged()
        }
        currentProfile = target
        persistProfileState()
        suppressProfileSelection = true
        binding.profileSpinner.setSelection(availableProfiles.indexOf(target).coerceAtLeast(0))
        suppressProfileSelection = false
    }

    private fun reloadPermsForCurrentProfile() {
        // Rebuild list object supaya RecyclerView pasti rebind checkbox dari profile target.
        allApps = allApps.map { item ->
            item.copy(perms = loadPerms(item.packageName))
        }
        refreshList()
        adapter.notifyDataSetChanged()
    }

    private fun countProfileRuleEntries(profile: String): Int {
        return getSharedPreferences(profileScopedRulesPref(profile), MODE_PRIVATE).all.size
    }

    private fun requestNotifIfNeeded() {
        if (Build.VERSION.SDK_INT < 33) return
        val granted = ContextCompat.checkSelfPermission(
            this,
            Manifest.permission.POST_NOTIFICATIONS,
        ) == PackageManager.PERMISSION_GRANTED
        if (!granted) notifPermLauncher.launch(Manifest.permission.POST_NOTIFICATIONS)
    }

    private fun ensureKeepAliveService() {
        val intent = Intent(this, FirewallKeepAliveService::class.java)
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
            startForegroundService(intent)
        } else {
            startService(intent)
        }
    }

    private fun setBusy(busy: Boolean) {
        if (Looper.myLooper() != Looper.getMainLooper()) {
            runOnUiThread { setBusy(busy) }
            return
        }
        if (busy) {
            backendBusyDepth += 1
            binding.progress.visibility = View.VISIBLE
            if (!applyInProgress && appInForeground) {
                showBackendBusyDialog()
            }
            return
        }
        backendBusyDepth = (backendBusyDepth - 1).coerceAtLeast(0)
        if (backendBusyDepth == 0) {
            binding.progress.visibility = View.GONE
            dismissBackendBusyDialog()
        }
    }

    private fun showBackendBusyDialog() {
        if (backendBusyDialog != null) return
        val pad = (24 * resources.displayMetrics.density).toInt()
        val gap = (14 * resources.displayMetrics.density).toInt()
        val box = LinearLayout(this).apply {
            orientation = LinearLayout.VERTICAL
            setPadding(pad, pad, pad, pad)
            gravity = android.view.Gravity.CENTER
        }
        val spinner = ProgressBar(this).apply {
            isIndeterminate = true
        }
        val text = TextView(this).apply {
            text = "Backend sedang memproses...\nTunggu sampai selesai."
            setTextColor(0xFFFFFFFF.toInt())
            textSize = 16f
            gravity = android.view.Gravity.CENTER
            setPadding(0, gap, 0, 0)
        }
        box.addView(spinner)
        box.addView(text)
        val dlg = AlertDialog.Builder(this)
            .setView(box)
            .setCancelable(false)
            .create()
        dlg.setCanceledOnTouchOutside(false)
        dlg.show()
        backendBusyDialog = dlg
    }

    private fun dismissBackendBusyDialog() {
        backendBusyDialog?.dismiss()
        backendBusyDialog = null
    }

    private fun setSearchMode(enabled: Boolean) {
        binding.searchBackBtn.visibility = if (enabled) View.VISIBLE else View.GONE
        binding.searchTopInput.visibility = if (enabled) View.VISIBLE else View.GONE
        binding.titleText.visibility = if (enabled) View.GONE else View.VISIBLE
        binding.toolSearchBtn.visibility = if (enabled) View.GONE else View.VISIBLE
    }

    private fun checkRootAndLoad() {
        lifecycleScope.launch {
            setBusy(true)
            val rooted = withContext(Dispatchers.IO) { RootFirewallController.checkRoot() }
            rootAvailable = rooted

            val status = withContext(Dispatchers.IO) { RootFirewallController.status() }
            cacheServiceState(status)
            if (rooted && !currentFirewallEnabled) {
                withContext(Dispatchers.IO) { RootFirewallController.clearAppChains() }
            }
            updateStatusFab(rooted, status.ok)
            syncPersistentNotification()
            updateCellularRuleIcon()

            loadInstalledApps()
            cleanupOrphanManagedUids()
            setBusy(false)
        }
    }

    private suspend fun cleanupOrphanManagedUids() {
        val installed = allApps.map { it.uid }.filter { it > 0 }.toSet()
        val managed = withContext(Dispatchers.IO) { RootFirewallController.listManagedUids() }
        val protected = managed.filter { RootFirewallController.isProtectedSystemUid(it) }.toSet()
        val orphans = (managed - installed) + protected
        if (orphans.isEmpty()) return
        withContext(Dispatchers.IO) { RootFirewallController.removeUidRules(orphans) }
        cleanupShadowStateForRemovedUids(orphans)
    }

    private fun cleanupShadowStateForRemovedUids(removedUids: Set<Int>) {
        if (removedUids.isEmpty()) return
        val currentState = loadRuleStateMap().toMutableMap()
        removedUids.forEach { currentState.remove(it) }
        saveRuleStateMap(currentState)
        val blocked = loadShadowBlockedUids().filterNot { it in removedUids }
        saveShadowBlockedUids(blocked)
    }

    private fun forceCleanupOrphansOnOpen() {
        lifecycleScope.launch {
            val removed = withContext(Dispatchers.IO) {
                val managed = RootFirewallController.listManagedUids()
                if (managed.isEmpty()) return@withContext emptySet<Int>()
                val installed = packageManager.getInstalledApplications(0)
                    .asSequence()
                    .map { it.uid }
                    .filter { it > 0 }
                    .toSet()
                val protected = managed.filter { RootFirewallController.isProtectedSystemUid(it) }.toSet()
                val orphans = (managed - installed) + protected
                if (orphans.isNotEmpty()) {
                    RootFirewallController.removeUidRules(orphans)
                }
                orphans
            }
            if (removed.isNotEmpty()) {
                cleanupShadowStateForRemovedUids(removed)
                showOutput("Orphan UID dibersihkan: ${removed.size}")
            }
        }
    }

    private suspend fun loadInstalledApps() {
        if (appsLoadInProgress) {
            pendingAppsReload = true
            return
        }
        setBusy(true)
        appsLoadInProgress = true
        val pm = packageManager
        try {
            // Fast-first render: load from backend cache so UI does not wait full enrich/icon phase.
            val cached = withContext(Dispatchers.IO) { AppMetaCacheStore.read(applicationContext) }
            if (cached.isNotEmpty()) {
                allApps = cached.map { row ->
                    AppRuleEntry(
                        packageName = row.packageName,
                        appName = row.appName,
                        uid = row.uid,
                        type = row.type,
                        installTime = row.installTime,
                        icon = null,
                        perms = loadPerms(row.packageName),
                    )
                }
                refreshList()
                showOutput("Apps cache loaded: ${allApps.size}")
            }

            val (launcherMeta, packageInfos) = withContext(Dispatchers.IO) {
                val launcher = loadLauncherMeta(pm)
                val infos = if (Build.VERSION.SDK_INT >= 33) {
                    pm.getInstalledPackages(PackageManager.PackageInfoFlags.of(0))
                } else {
                    @Suppress("DEPRECATION")
                    pm.getInstalledPackages(0)
                }
                launcher to infos
            }

            val fromPm = packageInfos.associateBy { it.packageName }
            // Fast path: rely on PackageManager snapshot to avoid slow root shell enumeration.
            val mergedPkgs = fromPm.keys.toSortedSet(String.CASE_INSENSITIVE_ORDER)
            val uidMap = buildMap<String, Int> {
                mergedPkgs.forEach { pkg ->
                    val uid = fromPm[pkg]?.applicationInfo?.uid ?: -1
                    if (uid > 0) put(pkg, uid)
                }
            }
            enforceDefaultDenyForNewPackages(mergedPkgs, uidMap)

            val loaded = withContext(Dispatchers.Default) {
                mergedPkgs.mapNotNull { pkg ->
                    val p = fromPm[pkg]
                    val ai = p?.applicationInfo ?: tryLoadAppInfo(pm, pkg)
                    val uid = ai?.uid ?: return@mapNotNull null
                    val type = ai?.let { classifyType(it, uid) } ?: if (uid < 10000) "core" else "user"
                    val appMeta = resolveAppMeta(pm, pkg, ai, launcherMeta[pkg])
                    val appName = appMeta.first
                    val icon = appMeta.second
                    val installTime = p?.firstInstallTime ?: 0L
                    AppRuleEntry(
                        packageName = pkg,
                        appName = appName,
                        uid = uid,
                        type = type,
                        installTime = installTime,
                        icon = icon,
                        perms = loadPerms(pkg),
                    )
                }
            }
            allApps = loaded
            withContext(Dispatchers.IO) {
                runCatching { AppMetaCacheStore.refreshSnapshot(applicationContext) }
            }
            showOutput("Apps loaded: ${allApps.size}")
            refreshList()
        } finally {
            appsLoadInProgress = false
            setBusy(false)
            if (pendingAppsReload) {
                pendingAppsReload = false
                requestAppsReload("pending_reload", immediate = true)
            }
        }
    }

    private fun tryLoadAppInfo(pm: PackageManager, pkg: String): ApplicationInfo? {
        return try {
            if (Build.VERSION.SDK_INT >= 33) {
                pm.getApplicationInfo(
                    pkg,
                    PackageManager.ApplicationInfoFlags.of(
                        PackageManager.MATCH_UNINSTALLED_PACKAGES.toLong() or
                            PackageManager.MATCH_DISABLED_COMPONENTS.toLong(),
                    ),
                )
            } else {
                @Suppress("DEPRECATION")
                pm.getApplicationInfo(
                    pkg,
                    PackageManager.MATCH_UNINSTALLED_PACKAGES or PackageManager.MATCH_DISABLED_COMPONENTS,
                )
            }
        } catch (_: Exception) {
            null
        }
    }

    private fun resolveAppMeta(
        pm: PackageManager,
        pkg: String,
        ai: ApplicationInfo?,
        launcherMeta: Pair<String, Drawable?>?,
    ): Pair<String, Drawable?> {
        if (launcherMeta != null && launcherMeta.first.isNotBlank()) {
            return launcherMeta
        }
        if (ai != null) {
            val label = ai.loadLabel(pm)?.toString()?.takeIf { it.isNotBlank() } ?: pkg
            return label to ai.loadIcon(pm)
        }
        val launch = pm.getLaunchIntentForPackage(pkg)
        if (launch != null) {
            val ri = pm.resolveActivity(launch, 0)
            if (ri != null) {
                val label = ri.loadLabel(pm)?.toString()?.takeIf { it.isNotBlank() } ?: pkg
                return label to ri.loadIcon(pm)
            }
        }
        return pkg to null
    }

    private fun loadLauncherMeta(pm: PackageManager): Map<String, Pair<String, Drawable?>> {
        val launcherIntent = Intent(Intent.ACTION_MAIN).addCategory(Intent.CATEGORY_LAUNCHER)
        val flags = if (Build.VERSION.SDK_INT >= 33) {
            PackageManager.ResolveInfoFlags.of(0L)
        } else {
            null
        }
        val activities = if (Build.VERSION.SDK_INT >= 33) {
            pm.queryIntentActivities(launcherIntent, flags!!)
        } else {
            @Suppress("DEPRECATION")
            pm.queryIntentActivities(launcherIntent, 0)
        }

        val map = LinkedHashMap<String, Pair<String, Drawable?>>()
        activities.forEach { ri ->
            val pkg = ri.activityInfo?.packageName ?: return@forEach
            if (map.containsKey(pkg)) return@forEach
            val label = ri.loadLabel(pm)?.toString()?.takeIf { it.isNotBlank() } ?: pkg
            map[pkg] = label to ri.loadIcon(pm)
        }
        return map
    }

    private fun listPackagesFromRoot(): Map<String, Int> {
        val result = RootFirewallController.runRaw("pm list packages -U; echo '---'; cmd package list packages -U")
        val text = buildString {
            append(result.stdout)
            if (result.stderr.isNotBlank()) append('\n').append(result.stderr)
        }
        val map = linkedMapOf<String, Int>()
        text.lineSequence().forEach { raw ->
            val line = raw.trim()
            if (!line.startsWith("package:")) return@forEach
            val pkg = line.substringAfter("package:").substringBefore(" ").trim()
            if (pkg.isBlank()) return@forEach
            val uid = Regex("uid:(\\d+)").find(line)?.groupValues?.getOrNull(1)?.toIntOrNull() ?: -1
            map[pkg] = uid
        }
        return map
    }

    private fun classifyType(ai: ApplicationInfo, uid: Int): String {
        if (isProtectedPackage(ai.packageName, uid)) return "protected"
        if (uid < 10_000 || ai.packageName == "android") return "core"
        val systemFlag = (ai.flags and ApplicationInfo.FLAG_SYSTEM) != 0
        val updatedSystemFlag = (ai.flags and ApplicationInfo.FLAG_UPDATED_SYSTEM_APP) != 0
        return if (systemFlag || updatedSystemFlag) "system" else "user"
    }

    private fun isProtectedPackage(pkg: String, uid: Int): Boolean {
        if (uid in 1000..1999) return true
        val exact = setOf(
            "android",
            "com.android.phone",
            "com.android.server.telecom",
            "com.android.networkstack",
            "com.google.android.networkstack",
            "com.google.android.networkstack.tethering",
            "com.android.networkstack.tethering.overlay",
            "com.android.providers.telephony",
            "com.mediatek.telephony",
            "com.mediatek.ims",
            "com.google.android.cellbroadcastservice",
            "com.android.cellbroadcastservice",
        )
        if (pkg in exact) return true
        val prefixes = listOf(
            "com.android.networkstack",
            "com.google.android.networkstack",
            "com.android.telephony",
            "com.mediatek.ims",
            "com.mediatek.telephony",
        )
        return prefixes.any { pkg.startsWith(it) }
    }

    private fun refreshList() {
        var rows = allApps
        if (currentFilter != "all") rows = rows.filter { it.type == currentFilter }
        if (searchQuery.isNotBlank()) {
            rows = rows.filter {
                it.appName.contains(searchQuery, true) || it.packageName.contains(searchQuery, true)
            }
        }
        rows = when (sortBy) {
            "uid" -> rows.sortedBy { it.uid }
            "install" -> rows.sortedByDescending { it.installTime }
            else -> rows.sortedBy { it.appName.lowercase() }
        }
        if (sessionNewPackages.isNotEmpty()) {
            val rank = sessionNewPackages.withIndex().associate { it.value to it.index }
            rows = rows.sortedWith(
                compareBy<AppRuleEntry> { rank[it.packageName] ?: Int.MAX_VALUE }
                    .thenBy { it.appName.lowercase() },
            )
        }
        visibleRows = rows
        adapter.submit(rows)
        binding.appsScroll.post { binding.appsScroll.scrollTo(0, 0) }
    }

    private fun registerPackageEvents() {
        if (packageEventsRegistered) return
        val filter = IntentFilter().apply {
            addAction(Intent.ACTION_PACKAGE_ADDED)
            addAction(Intent.ACTION_PACKAGE_FULLY_REMOVED)
            addAction(FirewallKeepAliveService.ACTION_INTERNAL_PACKAGE_ADDED)
            addDataScheme("package")
        }
        if (Build.VERSION.SDK_INT >= 33) {
            registerReceiver(packageChangedReceiver, filter, Context.RECEIVER_EXPORTED)
        } else {
            @Suppress("DEPRECATION")
            registerReceiver(packageChangedReceiver, filter)
        }
        packageEventsRegistered = true
    }

    private fun unregisterPackageEvents() {
        if (!packageEventsRegistered) return
        runCatching { unregisterReceiver(packageChangedReceiver) }
        packageEventsRegistered = false
    }

    private fun startPackageAutoRefresh() {
        // Broadcast package events adalah jalur utama.
        // Polling diperlambat sebagai fallback supaya tidak membebani UI.
        if (packageRefreshJob != null) return
        packageRefreshJob = lifecycleScope.launch(Dispatchers.IO) {
            lastPackageSnapshot = currentPackageSnapshot()
            while (isActive && appInForeground) {
                runCatching {
                    val now = currentPackageSnapshot()
                    if (now != lastPackageSnapshot) {
                        lastPackageSnapshot = now
                        Log.i(tag, "auto_refresh package delta detected size=${now.size}")
                        withContext(Dispatchers.Main) {
                            requestInventorySync("auto_refresh_delta")
                            requestAppsReload("auto_refresh_delta", immediate = false)
                        }
                    }
                }
                kotlinx.coroutines.delay(60000)
            }
        }
    }

    private fun stopPackageAutoRefresh() {
        packageRefreshJob?.cancel()
        packageRefreshJob = null
    }

    private fun startInventoryObserver() {
        if (inventoryObserveJob != null) return
        inventoryObserveJob = lifecycleScope.launch(Dispatchers.IO) {
            lastInventoryVersion = AppInventoryStore.version(applicationContext)
            while (isActive && appInForeground) {
                runCatching {
                    val current = AppInventoryStore.version(applicationContext)
                    if (current != lastInventoryVersion) {
                        lastInventoryVersion = current
                        withContext(Dispatchers.Main) {
                            requestInventorySync("inventory_version_changed")
                        }
                    }
                }
                kotlinx.coroutines.delay(1000)
            }
        }
    }

    private fun stopInventoryObserver() {
        inventoryObserveJob?.cancel()
        inventoryObserveJob = null
    }

    private fun requestInventorySync(reason: String) {
        lifecycleScope.launch {
            syncFromInventory(reason)
        }
    }

    private suspend fun syncFromInventory(reason: String) {
        val inventory = withContext(Dispatchers.IO) { AppInventoryStore.read(applicationContext) }
        if (inventory.isEmpty()) return
        val existing = allApps.asSequence().map { it.packageName }.toHashSet()
        val missing = inventory
            .asSequence()
            .filter { (pkg, uid) -> pkg.isNotBlank() && uid > 0 && pkg !in existing }
            .toList()
        if (missing.isEmpty()) return
        val additions = withContext(Dispatchers.IO) {
            missing.mapNotNull { (pkg, uid) -> buildEntryForPackage(pkg, uid) }
        }
        if (additions.isEmpty()) return
        allApps = (allApps + additions).distinctBy { it.packageName }
        Log.i(tag, "inventory sync reason=$reason added=${additions.size}")
        refreshList()
    }

    private fun currentPackageSnapshot(): Set<String> {
        return try {
            if (Build.VERSION.SDK_INT >= 33) {
                packageManager.getInstalledPackages(PackageManager.PackageInfoFlags.of(0))
                    .map { it.packageName }
                    .toSet()
            } else {
                @Suppress("DEPRECATION")
                packageManager.getInstalledPackages(0)
                    .map { it.packageName }
                    .toSet()
            }
        } catch (_: Throwable) {
            emptySet()
        }
    }

    private suspend fun enforceDefaultDenyForNewPackages(
        installedPackages: Set<String>,
        uidMap: Map<String, Int>,
    ) {
        withContext(Dispatchers.IO) {
            val known = loadKnownPackages().toMutableSet()
            if (known.isEmpty()) {
                // First run: do not mass-deny existing apps.
                saveKnownPackages(installedPackages)
                return@withContext
            }
            val newPkgs = installedPackages.filter { it !in known }
            if (newPkgs.isEmpty()) {
                saveKnownPackages(installedPackages)
                return@withContext
            }

            val denyRules = mutableListOf<AppNetRule>()
            newPkgs.forEach { pkg ->
                val shouldInitDefaultDeny = !hasAnySavedRuleForPackage(pkg)
                if (shouldInitDefaultDeny) {
                    writeDefaultDenyForPackageAllProfiles(pkg)
                }
                val uid = uidMap[pkg] ?: -1
                if (shouldInitDefaultDeny && rootAvailable && currentFirewallEnabled && RootFirewallController.isManagedAppUid(uid)) {
                    denyRules += AppNetRule(
                        uid = uid,
                        local = false,
                        wifi = false,
                        cellular = false,
                        roaming = false,
                        vpn = false,
                        bluetooth = false,
                        tor = false,
                        download = false,
                        upload = false,
                    )
                }
            }
            if (denyRules.isNotEmpty()) {
                RootFirewallController.applyAppRulesIncremental(
                    upsertRules = denyRules,
                    removeUids = emptySet(),
                ) { _, _ -> }
            }

            saveKnownPackages(installedPackages)
            withContext(Dispatchers.Main) {
                newPkgs.forEach { markPackageAsSessionNew(it) }
            }
        }
    }

    private fun hasAnySavedRuleForPackage(pkg: String): Boolean {
        val targets = availableProfiles.ifEmpty { listOf("anlap") }.distinct()
        return targets.any { profile ->
            getSharedPreferences(profileScopedRulesPref(profile), MODE_PRIVATE).contains(pkg)
        }
    }

    private fun markPackageAsSessionNew(pkg: String) {
        sessionNewPackages.remove(pkg)
        sessionNewPackages.add(0, pkg)
    }

    private fun writeDefaultDenyForPackageAllProfiles(pkg: String) {
        val deny = JSONObject()
            .put("local", false)
            .put("wifi", false)
            .put("cellular", false)
            .put("roaming", false)
            .put("vpn", false)
            .put("bluetooth_tethering", false)
            .put("tor", false)
            .put("download", false)
            .put("upload", false)
            .toString()

        val targets = availableProfiles.ifEmpty { listOf("anlap") }
        targets.forEach { profile ->
            getSharedPreferences(profileScopedRulesPref(profile), MODE_PRIVATE)
                .edit()
                .putString(pkg, deny)
                .apply()
        }
    }

    private fun loadKnownPackages(): Set<String> {
        val raw = getSharedPreferences(knownPackagesPrefName, MODE_PRIVATE)
            .getString(knownPackagesKey, "")
            .orEmpty()
        if (raw.isBlank()) return emptySet()
        return raw.split(',')
            .map { it.trim() }
            .filter { it.isNotBlank() }
            .toSet()
    }

    private fun saveKnownPackages(packages: Set<String>) {
        val csv = packages
            .asSequence()
            .filter { it.isNotBlank() }
            .distinct()
            .sorted()
            .joinToString(",")
        getSharedPreferences(knownPackagesPrefName, MODE_PRIVATE)
            .edit()
            .putString(knownPackagesKey, csv)
            .apply()
    }

    private fun markKnownPackagesAdded(added: Set<String>) {
        if (added.isEmpty()) return
        val merged = loadKnownPackages().toMutableSet()
        merged.addAll(added)
        saveKnownPackages(merged)
    }

    private fun removeKnownPackage(pkg: String) {
        val updated = loadKnownPackages().toMutableSet()
        updated.remove(pkg)
        saveKnownPackages(updated)
    }

    private fun defaultPerms(): MutableMap<String, Boolean> = mutableMapOf(
        "local" to true,
        "wifi" to true,
        "cellular" to true,
        "roaming" to false,
        "vpn" to true,
        "bluetooth_tethering" to false,
        "tor" to false,
        "download" to true,
        "upload" to true,
    )

    private fun loadPerms(pkg: String): MutableMap<String, Boolean> {
        val pref = getSharedPreferences(profileScopedRulesPref(), MODE_PRIVATE)
        val raw = pref.getString(pkg, null) ?: return defaultPerms()
        return try {
            val j = JSONObject(raw)
            mutableMapOf(
                "local" to j.optBoolean("local", true),
                "wifi" to j.optBoolean("wifi", true),
                "cellular" to j.optBoolean("cellular", true),
                "roaming" to j.optBoolean("roaming", false),
                "vpn" to j.optBoolean("vpn", true),
                "bluetooth_tethering" to j.optBoolean("bluetooth_tethering", false),
                "tor" to j.optBoolean("tor", false),
                "download" to j.optBoolean("download", true),
                "upload" to j.optBoolean("upload", true),
            )
        } catch (_: Exception) {
            defaultPerms()
        }
    }

    private fun saveAppPerm(item: AppRuleEntry) {
        val pref = getSharedPreferences(profileScopedRulesPref(), MODE_PRIVATE)
        val j = JSONObject()
            .put("local", item.perms["local"] == true)
            .put("wifi", item.perms["wifi"] == true)
            .put("cellular", item.perms["cellular"] == true)
            .put("roaming", item.perms["roaming"] == true)
            .put("vpn", item.perms["vpn"] == true)
            .put("bluetooth_tethering", item.perms["bluetooth_tethering"] == true)
            .put("tor", item.perms["tor"] == true)
            .put("download", item.perms["download"] == true)
            .put("upload", item.perms["upload"] == true)
        pref.edit().putString(item.packageName, j.toString()).apply()
    }

    private fun saveAllCurrentPermsToProfile(targetProfile: String) {
        val pref = getSharedPreferences(profileScopedRulesPref(targetProfile), MODE_PRIVATE)
        val editor = pref.edit()
        allApps.forEach { item ->
            val j = JSONObject()
                .put("local", item.perms["local"] == true)
                .put("wifi", item.perms["wifi"] == true)
                .put("cellular", item.perms["cellular"] == true)
                .put("roaming", item.perms["roaming"] == true)
                .put("vpn", item.perms["vpn"] == true)
                .put("bluetooth_tethering", item.perms["bluetooth_tethering"] == true)
                .put("tor", item.perms["tor"] == true)
                .put("download", item.perms["download"] == true)
                .put("upload", item.perms["upload"] == true)
            editor.putString(item.packageName, j.toString())
        }
        editor.apply()
    }

    private fun openSortMenu() {
        val menu = PopupMenu(this, binding.toolSortBtn)
        menu.menu.add(Menu.NONE, 1, 1, "By name (default)")
        menu.menu.add(Menu.NONE, 2, 2, "By install/update")
        menu.menu.add(Menu.NONE, 3, 3, "By UID")
        menu.menu.setGroupCheckable(Menu.NONE, true, true)
        when (sortBy) {
            "name" -> menu.menu.findItem(1).isChecked = true
            "install" -> menu.menu.findItem(2).isChecked = true
            "uid" -> menu.menu.findItem(3).isChecked = true
        }
        menu.setOnMenuItemClickListener {
            sortBy = when (it.itemId) {
                2 -> "install"
                3 -> "uid"
                else -> "name"
            }
            refreshList()
            true
        }
        menu.show()
    }

    private fun openModeMenu() {
        val menu = PopupMenu(this, binding.toolModeBtn)
        menu.menu.add(Menu.NONE, 1, 1, "Allow selected")
        menu.menu.add(Menu.NONE, 2, 2, "Block selected")
        menu.menu.setGroupCheckable(Menu.NONE, true, true)
        if (checkboxMode == "allow") menu.menu.findItem(1).isChecked = true else menu.menu.findItem(2).isChecked = true
        menu.setOnMenuItemClickListener {
            checkboxMode = if (it.itemId == 1) "allow" else "blocked"
            Toast.makeText(this, "Mode: $checkboxMode", Toast.LENGTH_SHORT).show()
            true
        }
        menu.show()
    }

    private fun openMainMenu() {
        val menu = PopupMenu(this, binding.toolMenuBtn)
        val toggleLabel = if (currentFirewallEnabled) "Disable Firewall Agent" else "Enable Firewall Agent"
        menu.menu.add(Menu.NONE, 1, 1, toggleLabel)
        menu.menu.add(Menu.NONE, 3, 3, "Apply")
        menu.menu.add(Menu.NONE, 14, 14, "Check all (visible)")
        menu.menu.add(Menu.NONE, 15, 15, "Uncheck all (visible)")
        menu.menu.add(Menu.NONE, 16, 16, "Restore check")
        menu.menu.add(Menu.NONE, 4, 4, "View Log")
        menu.menu.add(Menu.NONE, 5, 5, "ML Alerts")
        menu.menu.add(Menu.NONE, 6, 6, "Rules")
        menu.menu.add(Menu.NONE, 7, 7, "Preferences")
        menu.menu.add(Menu.NONE, 8, 8, "Model Update URL")
        menu.menu.add(Menu.NONE, 10, 10, "Traffic Monitor")
        menu.menu.add(Menu.NONE, 11, 11, "Call Guard")
        menu.menu.add(Menu.NONE, 12, 12, "AdGuard DNS")
        menu.menu.add(Menu.NONE, 13, 13, "Tor Connection")
        menu.menu.add(Menu.NONE, 17, 17, "Security Stats")
        menu.setOnMenuItemClickListener { onMenuClicked(it) }
        menu.show()
    }

    private fun onMenuClicked(item: MenuItem): Boolean {
        return when (item.itemId) {
            1 -> {
                if (currentFirewallEnabled) {
                    runAction("Disable Firewall", 104) { RootFirewallController.disable() }
                } else {
                    runAction("Enable Firewall", 103) {
                        val enableResult = RootFirewallController.enable()
                        if (!enableResult.ok) return@runAction enableResult
                        val applyResult = RootFirewallController.applyAppRules(buildManagedRules())
                        mergeExecResults(enableResult, applyResult)
                    }
                }
                true
            }
            3 -> { promptProfileForApply(); true }
            14 -> { bulkSetChecks(true); true }
            15 -> { bulkSetChecks(false); true }
            16 -> { restoreBulkChecks(); true }
            4 -> { startActivity(Intent(this, LogActivity::class.java)); true }
            5 -> { startActivity(Intent(this, AlertsActivity::class.java)); true }
            6 -> { startActivity(Intent(this, RulesActivity::class.java)); true }
            7 -> { startActivity(Intent(this, PreferencesActivity::class.java)); true }
            8 -> { startActivity(Intent(this, ModelUpdateActivity::class.java)); true }
            10 -> { startActivity(Intent(this, TrafficMonitorActivity::class.java)); true }
            11 -> { startActivity(Intent(this, CallGuardDialerActivity::class.java)); true }
            12 -> { startActivity(Intent(this, AdGuardActivity::class.java)); true }
            13 -> { openTorEntry(); true }
            17 -> { startActivity(Intent(this, SecurityStatsActivity::class.java)); true }
            else -> false
        }
    }

    private fun bulkSetChecks(checked: Boolean) {
        val targets = visibleRows
        if (targets.isEmpty()) {
            Toast.makeText(this, "Tidak ada aplikasi pada list saat ini.", Toast.LENGTH_SHORT).show()
            return
        }
        saveBulkSnapshot(targets)
        val keys = listOf(
            "local",
            "wifi",
            "cellular",
            "roaming",
            "vpn",
            "bluetooth_tethering",
            "tor",
            "download",
            "upload",
        )
        targets.forEach { item ->
            keys.forEach { key -> item.perms[key] = checked }
            saveAppPerm(item)
        }
        adapter.notifyDataSetChanged()
        val mode = if (checked) "Check all" else "Uncheck all"
        Toast.makeText(this, "$mode diterapkan ke ${targets.size} aplikasi.", Toast.LENGTH_SHORT).show()
        showOutput("$mode (visible) selesai: ${targets.size} aplikasi.")
    }

    private fun saveBulkSnapshot(targets: List<AppRuleEntry>) {
        val root = JSONObject()
        targets.forEach { item ->
            val p = JSONObject()
                .put("local", item.perms["local"] == true)
                .put("wifi", item.perms["wifi"] == true)
                .put("cellular", item.perms["cellular"] == true)
                .put("roaming", item.perms["roaming"] == true)
                .put("vpn", item.perms["vpn"] == true)
                .put("bluetooth_tethering", item.perms["bluetooth_tethering"] == true)
                .put("tor", item.perms["tor"] == true)
                .put("download", item.perms["download"] == true)
                .put("upload", item.perms["upload"] == true)
            root.put(item.packageName, p)
        }
        getSharedPreferences(bulkPrefsName, MODE_PRIVATE)
            .edit()
            .putString(bulkSnapshotKey, root.toString())
            .apply()
    }

    private fun restoreBulkChecks() {
        val raw = getSharedPreferences(bulkPrefsName, MODE_PRIVATE)
            .getString(bulkSnapshotKey, null)
        if (raw.isNullOrBlank()) {
            Toast.makeText(this, "Snapshot restore tidak ditemukan.", Toast.LENGTH_SHORT).show()
            return
        }
        val obj = runCatching { JSONObject(raw) }.getOrNull()
        if (obj == null) {
            Toast.makeText(this, "Snapshot restore rusak.", Toast.LENGTH_SHORT).show()
            return
        }
        var restored = 0
        allApps.forEach { item ->
            val p = obj.optJSONObject(item.packageName) ?: return@forEach
            item.perms["local"] = p.optBoolean("local", item.perms["local"] == true)
            item.perms["wifi"] = p.optBoolean("wifi", item.perms["wifi"] == true)
            item.perms["cellular"] = p.optBoolean("cellular", item.perms["cellular"] == true)
            item.perms["roaming"] = p.optBoolean("roaming", item.perms["roaming"] == true)
            item.perms["vpn"] = p.optBoolean("vpn", item.perms["vpn"] == true)
            item.perms["bluetooth_tethering"] = p.optBoolean("bluetooth_tethering", item.perms["bluetooth_tethering"] == true)
            item.perms["tor"] = p.optBoolean("tor", item.perms["tor"] == true)
            item.perms["download"] = p.optBoolean("download", item.perms["download"] == true)
            item.perms["upload"] = p.optBoolean("upload", item.perms["upload"] == true)
            saveAppPerm(item)
            restored++
        }
        adapter.notifyDataSetChanged()
        Toast.makeText(this, "Restore check berhasil: $restored aplikasi.", Toast.LENGTH_SHORT).show()
        showOutput("Restore check selesai: $restored aplikasi.")
    }

    private fun promptProfileForApply() {
        val options = arrayOf(
            "Simpan ke profile saat ini ($currentProfile)",
            "Pilih profile lain",
            "Buat profile baru",
        )
        AlertDialog.Builder(this)
            .setTitle("Simpan rules ke profile")
            .setItems(options) { _, which ->
                when (which) {
                    0 -> applySelectedRules()
                    1 -> showPickExistingProfileDialog()
                    2 -> showCreateProfileDialog()
                }
            }
            .setNegativeButton("Batal", null)
            .show()
    }

    private fun showPickExistingProfileDialog() {
        if (availableProfiles.isEmpty()) {
            showCreateProfileDialog()
            return
        }
        val items = availableProfiles.toTypedArray()
        AlertDialog.Builder(this)
            .setTitle("Pilih profile target")
            .setItems(items) { _, index ->
                val target = items.getOrNull(index) ?: return@setItems
                saveAllCurrentPermsToProfile(target)
                ensureProfileExists(target)
                reloadPermsForCurrentProfile()
                applySelectedRules()
            }
            .setNegativeButton("Batal", null)
            .show()
    }

    private fun showCreateProfileDialog() {
        val input = EditText(this).apply {
            hint = "nama profile"
            setText("profile_${System.currentTimeMillis() % 1000}")
        }
        AlertDialog.Builder(this)
            .setTitle("Buat profile baru")
            .setView(input)
            .setPositiveButton("Simpan") { _, _ ->
                val name = input.text.toString().trim()
                if (name.isBlank()) {
                    Toast.makeText(this, "Nama profile tidak boleh kosong.", Toast.LENGTH_SHORT).show()
                    return@setPositiveButton
                }
                saveAllCurrentPermsToProfile(name)
                ensureProfileExists(name)
                reloadPermsForCurrentProfile()
                applySelectedRules()
            }
            .setNegativeButton("Batal", null)
            .show()
    }

    private fun openTorEntry() {
        val orbotPkg = "org.torproject.android"
        val launch = packageManager.getLaunchIntentForPackage(orbotPkg)
        if (launch != null) {
            startActivity(launch)
            return
        }

        AlertDialog.Builder(this)
            .setTitle("Orbot diperlukan")
            .setMessage(
                "Fitur Tor membutuhkan aplikasi Orbot.\n" +
                    "Install Orbot sekarang dari halaman rilis resmi?",
            )
            .setPositiveButton("Ya") { _, _ ->
                runCatching {
                    startActivity(
                        Intent(
                            Intent.ACTION_VIEW,
                            Uri.parse("https://github.com/guardianproject/orbot-android/releases"),
                        ),
                    )
                }
            }
            .setNegativeButton("Tidak", null)
            .show()
    }

    private fun applySelectedRules() {
        lifecycleScope.launch {
            // Refresh installed package snapshot first to avoid stale uninstall entries.
            loadInstalledApps()
            cleanupOrphanManagedUids()

            // Apply must evaluate all known app rules, not only filtered/visible rows.
            val allRules = buildManagedRules()
            val blocked = allRules
                .filter { RootFirewallController.isManagedAppUid(it.uid) }
                .filter { shouldBlock(it) }
                .map { it.uid }
                .distinct()
            saveShadowBlockedUids(blocked)

            val rootedNow = withContext(Dispatchers.IO) { RootFirewallController.checkRoot() }
            rootAvailable = rootedNow
            if (!rootedNow) {
                updateStatusFab(false, false)
                showOutput("Root belum aktif. Grant akses root di Magisk/KSU.")
                return@launch
            }

            val totalApps = allApps.size
            val desiredRestrictedByUid = allRules
                .filter { !isAllAllowedRule(it) }
                .associateBy { it.uid }
            val desiredSignatures = desiredRestrictedByUid.mapValues { (_, r) -> ruleSignature(r) }
            val savedSignatures = loadRuleStateMap()
            val currentManagedUids = withContext(Dispatchers.IO) { RootFirewallController.listManagedUids() }
            val protectedManaged = currentManagedUids.filter { RootFirewallController.isProtectedSystemUid(it) }.toSet()
            val inspectUids = desiredRestrictedByUid.keys.intersect(currentManagedUids)
            val currentChainSpecs = withContext(Dispatchers.IO) { RootFirewallController.readUidChainSpecs(inspectUids) }
            val removeUids = (currentManagedUids - desiredRestrictedByUid.keys) + protectedManaged
            val upsertRules = desiredRestrictedByUid.values.filter { r ->
                val sig = desiredSignatures[r.uid]
                val savedSig = savedSignatures[r.uid]
                val expectedSpec = RootFirewallController.expectedUidChainSpec(r)
                val currentSpec = currentChainSpecs[r.uid].orEmpty()
                savedSig != sig || !currentManagedUids.contains(r.uid) || expectedSpec != currentSpec
            }
            val totalChanges = upsertRules.size + removeUids.size

            if (totalChanges == 0) {
                setBusy(false)
                showApplyResultDialog(
                    "Tidak ada perubahan",
                    "Semua rules sudah sinkron. Tidak ada update iptables yang perlu diterapkan.",
                )
                return@launch
            }

            lastProgressNotifProcessed = -1
            lastProgressNotifAtMs = 0L
            lastProgressUiProcessed = -1
            lastProgressUiAtMs = 0L
            applyInProgress = true
            latestApplyProgress = ApplyProgressModel(0, totalChanges, totalApps)
            if (appInForeground) {
                showApplyProgressDialog(0, totalChanges, totalApps)
            } else {
                NotifyHelper.postApplyProgress(this@MainActivity, 0, totalChanges, totalApps)
            }
            setBusy(true)

            val resultPack = withContext(Dispatchers.IO) {
                val (applyResult, summary) = RootFirewallController.applyAppRulesIncremental(upsertRules, removeUids) { processed, total ->
                    runOnUiThread {
                        latestApplyProgress = ApplyProgressModel(processed, total, totalApps)
                        if (appInForeground) {
                            if (applyProgressDialog == null) {
                                showApplyProgressDialog(processed, total, totalApps)
                            }
                            val now = System.currentTimeMillis()
                            val shouldUiUpdate = processed == total ||
                                processed <= 1 ||
                                processed - lastProgressUiProcessed >= 2 ||
                                now - lastProgressUiAtMs >= 90
                            if (shouldUiUpdate) {
                                updateApplyProgressDialog(processed, total, totalApps)
                                lastProgressUiProcessed = processed
                                lastProgressUiAtMs = now
                            }
                        } else {
                            val now = System.currentTimeMillis()
                            val shouldNotify = processed == total ||
                                processed <= 1 ||
                                processed - lastProgressNotifProcessed >= 4 ||
                                now - lastProgressNotifAtMs >= 700
                            if (shouldNotify) {
                                NotifyHelper.postApplyProgress(this@MainActivity, processed, total, totalApps)
                                lastProgressNotifProcessed = processed
                                lastProgressNotifAtMs = now
                            }
                        }
                    }
                }
                val phase = if (applyResult.ok && summary.failedUids == 0) {
                    "Apply selesai"
                } else if (summary.failedUids > 0) {
                    "Apply selesai dengan peringatan"
                } else {
                    "Apply gagal"
                }
                Triple(applyResult, summary, phase)
            }

            val (result, summary, phase) = resultPack
            applyInProgress = false
            NotifyHelper.clearApplyProgress(this@MainActivity)

            if (result.ok && summary.failedUids == 0) {
                saveRuleStateMap(desiredSignatures)
            }

            val serviceStatus = withContext(Dispatchers.IO) { RootFirewallController.status() }
            cacheServiceState(serviceStatus)
            updateStatusFab(true, result.ok)
            syncPersistentNotification()
            setBusy(false)

            val detail = buildString {
                appendLine("$phase")
                appendLine("exit=${result.code}")
                appendLine("Aplikasi terdeteksi: $totalApps")
                appendLine("Perubahan terdeteksi: ${summary.totalUids}")
                appendLine("Perubahan diproses: ${summary.processedUids}")
                appendLine("UID upsert: ${summary.restrictedUids}")
                appendLine("Perubahan berhasil: ${summary.appliedUids}")
                appendLine("Perubahan gagal: ${summary.failedUids}")
                if (result.stdout.isNotBlank()) appendLine(result.stdout)
                if (result.stderr.isNotBlank()) appendLine(result.stderr)
            }
            showOutput(detail)

            val successNoError = result.ok && summary.failedUids == 0
            val title = when {
                successNoError -> "Rules diterapkan"
                summary.failedUids > 0 -> "Rules diterapkan (peringatan)"
                else -> "Apply gagal"
            }
            val message =
                "Sinkronisasi perubahan ${summary.processedUids}/${summary.totalUids}.\n" +
                    "Perubahan diterapkan: ${summary.appliedUids}.\n" +
                    "Perubahan gagal: ${summary.failedUids}."
            if (appInForeground) {
                dismissApplyProgressDialog()
                showApplyResultDialog(title, message)
            } else {
                pendingApplySummary = PendingApplySummary(title, message)
                dismissApplyProgressDialog()
            }

            val applyResultMessage = when {
                successNoError -> "Apply rules berhasil (${summary.appliedUids} perubahan)"
                summary.failedUids > 0 -> "Apply rules selesai dg peringatan (${summary.failedUids} perubahan gagal)"
                else -> "Apply rules gagal (code=${result.code})"
            }
            NotifyHelper.postApplyResult(
                this@MainActivity,
                success = successNoError,
                content = applyResultMessage,
                id = 105,
            )
        }
    }

    private fun showApplyProgressDialog(processed: Int, totalUid: Int, totalApps: Int) {
        dismissApplyProgressDialog()
        val state = mutableStateOf(ApplyProgressModel(processed, totalUid, totalApps))
        applyProgressState = state
        val content = ComposeView(this).apply {
            setContent {
                MaterialTheme {
                    ApplyProgressContent(state.value)
                }
            }
        }
        val dlg = AlertDialog.Builder(this)
            .setView(content)
            .setCancelable(false)
            .create()
        dlg.show()
        dlg.window?.setFlags(
            android.view.WindowManager.LayoutParams.FLAG_NOT_TOUCH_MODAL,
            android.view.WindowManager.LayoutParams.FLAG_NOT_TOUCH_MODAL,
        )
        dlg.window?.setFlags(
            android.view.WindowManager.LayoutParams.FLAG_WATCH_OUTSIDE_TOUCH,
            android.view.WindowManager.LayoutParams.FLAG_WATCH_OUTSIDE_TOUCH,
        )
        applyProgressDialog = dlg
    }

    private fun updateApplyProgressDialog(processed: Int, totalUid: Int, totalApps: Int) {
        applyProgressState?.value = ApplyProgressModel(processed, totalUid, totalApps)
    }

    private fun dismissApplyProgressDialog() {
        applyProgressDialog?.dismiss()
        applyProgressDialog = null
        applyProgressState = null
    }

    private fun showApplyResultDialog(title: String, message: String) {
        AlertDialog.Builder(this@MainActivity)
            .setTitle(title)
            .setMessage(message)
            .setCancelable(false)
            .setPositiveButton("OK") { _, _ ->
                dismissApplyProgressDialog()
            }
            .show()
    }

    private fun buildAllRules(): List<AppNetRule> {
        return allApps
            .map {
                AppNetRule(
                    uid = it.uid,
                    local = it.perms["local"] == true,
                    wifi = it.perms["wifi"] == true,
                    cellular = it.perms["cellular"] == true,
                    roaming = it.perms["roaming"] == true,
                    vpn = it.perms["vpn"] == true,
                    bluetooth = it.perms["bluetooth_tethering"] == true,
                    tor = it.perms["tor"] == true,
                    download = it.perms["download"] == true,
                    upload = it.perms["upload"] == true,
                )
            }
            .distinctBy { it.uid }
    }

    private fun buildManagedRules(): List<AppNetRule> {
        // Manage all app-space UIDs (>=10000): user/system/core-app.
        // Low system UIDs (<10000) remain protected in RootFirewallController.
        return allApps
            .asSequence()
            .filter { RootFirewallController.isManagedAppUid(it.uid) }
            .map {
                AppNetRule(
                    uid = it.uid,
                    local = it.perms["local"] == true,
                    wifi = it.perms["wifi"] == true,
                    cellular = it.perms["cellular"] == true,
                    roaming = it.perms["roaming"] == true,
                    vpn = it.perms["vpn"] == true,
                    bluetooth = it.perms["bluetooth_tethering"] == true,
                    tor = it.perms["tor"] == true,
                    download = it.perms["download"] == true,
                    upload = it.perms["upload"] == true,
                )
            }
            .distinctBy { it.uid }
            .toList()
    }

    private fun saveShadowBlockedUids(uids: List<Int>) {
        val csv = uids.distinct().filter { it > 0 }.joinToString(",")
        getSharedPreferences(profileScopedShadowPref(), MODE_PRIVATE)
            .edit()
            .putString(shadowKeyBlockedUids, csv)
            .apply()
    }

    private fun loadShadowBlockedUids(): List<Int> {
        val csv = getSharedPreferences(profileScopedShadowPref(), MODE_PRIVATE)
            .getString(shadowKeyBlockedUids, "")
            .orEmpty()
        if (csv.isBlank()) return emptyList()
        return csv.split(',')
            .mapNotNull { it.trim().toIntOrNull() }
            .filter { it > 0 }
            .distinct()
    }

    private fun mergeExecResults(first: ExecResult, second: ExecResult): ExecResult {
        val out = buildString {
            if (first.stdout.isNotBlank()) appendLine(first.stdout)
            if (second.stdout.isNotBlank()) appendLine(second.stdout)
        }.trim()
        val err = buildString {
            if (first.stderr.isNotBlank()) appendLine(first.stderr)
            if (second.stderr.isNotBlank()) appendLine(second.stderr)
        }.trim()
        val code = if (second.code != 0) second.code else first.code
        return ExecResult(code = code, stdout = out, stderr = err)
    }

    private fun shouldBlock(rule: AppNetRule): Boolean {
        // "LAN" here means localhost/local-only, not internet path.
        // Internet paths are wifi/cellular/roaming/vpn/bluetooth_tethering/tor.
        val allowWifi = rule.wifi
        val allowCell = rule.cellular
        val allowRoam = rule.roaming
        val allowVpn = rule.vpn
        val allowBt = rule.bluetooth
        val allowTor = rule.tor
        val allowDownload = rule.download
        val allowUpload = rule.upload
        val anyNetworkPathAllowed = allowWifi || allowCell || allowRoam || allowVpn || allowBt || allowTor
        val anyDirectionAllowed = allowDownload || allowUpload

        return if (checkboxMode == "allow") {
            // In allow mode, app is blocked if no internet path or direction is allowed.
            !anyNetworkPathAllowed || !anyDirectionAllowed
        } else {
            // In blocked mode, any blocked internet path implies block (global per-UID backend).
            anyNetworkPathAllowed || anyDirectionAllowed
        }
    }

    private fun isAllAllowedRule(rule: AppNetRule): Boolean {
        return rule.local &&
            rule.wifi &&
            rule.cellular &&
            (rule.roaming || rule.cellular) &&
            rule.vpn &&
            rule.bluetooth &&
            rule.tor &&
            rule.download &&
            rule.upload
    }

    private fun ruleSignature(rule: AppNetRule): String {
        return listOf(
            rule.uid,
            if (rule.local) 1 else 0,
            if (rule.wifi) 1 else 0,
            if (rule.cellular) 1 else 0,
            if (rule.roaming) 1 else 0,
            if (rule.vpn) 1 else 0,
            if (rule.bluetooth) 1 else 0,
            if (rule.tor) 1 else 0,
            if (rule.download) 1 else 0,
            if (rule.upload) 1 else 0,
        ).joinToString(":")
    }

    private fun loadRuleStateMap(): Map<Int, String> {
        val raw = getSharedPreferences(profileScopedShadowPref(), MODE_PRIVATE)
            .getString(shadowKeyRuleState, "{}")
            .orEmpty()
        return runCatching {
            val obj = JSONObject(raw)
            buildMap {
                obj.keys().forEach { k ->
                    val uid = k.toIntOrNull() ?: return@forEach
                    put(uid, obj.optString(k, ""))
                }
            }
        }.getOrDefault(emptyMap())
    }

    private fun saveRuleStateMap(map: Map<Int, String>) {
        val obj = JSONObject()
        map.forEach { (uid, sig) -> obj.put(uid.toString(), sig) }
        getSharedPreferences(profileScopedShadowPref(), MODE_PRIVATE)
            .edit()
            .putString(shadowKeyRuleState, obj.toString())
            .apply()
    }

    private fun runAction(title: String, notifId: Int, block: () -> ExecResult) {
        lifecycleScope.launch {
            val rootedNow = withContext(Dispatchers.IO) { RootFirewallController.checkRoot() }
            rootAvailable = rootedNow
            if (!rootedNow) {
                updateStatusFab(false, false)
                NotifyHelper.syncPersistentStatus(
                    this@MainActivity,
                    enabled = false,
                    mode = currentMode,
                    service = currentServiceState,
                    ml = currentMlState,
                )
                showOutput("Root belum aktif. Grant akses root di Magisk/KSU.")
                return@launch
            }
            setBusy(true)
            val result = withContext(Dispatchers.IO) { block() }
            val serviceStatus = withContext(Dispatchers.IO) { RootFirewallController.status() }
            cacheServiceState(serviceStatus)
            updateStatusFab(true, result.ok)
            syncPersistentNotification()
            showOutput(buildString {
                appendLine(title)
                appendLine("exit=${result.code}")
                if (result.stdout.isNotBlank()) appendLine(result.stdout)
                if (result.stderr.isNotBlank()) appendLine(result.stderr)
            })
            NotifyHelper.post(
                this@MainActivity,
                "Firewall Agent",
                if (result.ok) "$title berhasil" else "$title gagal (code=${result.code})",
                notifId,
            )
            setBusy(false)
        }
    }

    private fun updateStatusFab(rooted: Boolean, statusOk: Boolean?) {
        val iconRes = when {
            !rooted -> R.drawable.ic_status_error
            statusOk == true -> R.drawable.ic_status_ok
            statusOk == false -> R.drawable.ic_status_error
            else -> R.drawable.ic_status_unknown
        }
        val bgColor = when {
            !rooted -> 0xFF9E2A2B.toInt()
            statusOk == true -> 0xFF1FA122.toInt()
            statusOk == false -> 0xFF9E2A2B.toInt()
            else -> 0xFF6B7280.toInt()
        }
        binding.statusFab.setImageResource(iconRes)
        binding.statusFab.backgroundTintList = android.content.res.ColorStateList.valueOf(bgColor)
    }

    private fun cacheServiceState(status: ExecResult) {
        if (!status.ok || status.stdout.isBlank()) {
            currentServiceState = "unknown"
            currentMlState = "unknown"
            return
        }
        runCatching {
            val j = JSONObject(status.stdout.trim())
            currentServiceState = j.optString("service", "unknown")
            currentMlState = if (currentServiceState == "running") "running" else "stopped"
            currentFirewallEnabled = j.optBoolean("firewall_enabled", false)
            currentMode = j.optString("mode", "audit")
        }.onFailure {
            currentServiceState = "unknown"
            currentMlState = "unknown"
        }
    }

    private fun showStatusDialog() {
        val rootState = if (rootAvailable) "available" else "not available"
        val firewallState = if (currentFirewallEnabled) "enabled" else "disabled"
        val message = buildString {
            appendLine("Root: $rootState")
            appendLine("Service: $currentServiceState")
            appendLine("ML Engine: $currentMlState")
            appendLine("Firewall: $firewallState")
            append("Mode: $currentMode")
        }
        AlertDialog.Builder(this)
            .setTitle("Firewall Status")
            .setMessage(message)
            .setPositiveButton("OK", null)
            .show()
    }

    private fun onStatusFabClicked() {
        if (rootAvailable) {
            showStatusDialog()
            return
        }
        lifecycleScope.launch {
            setBusy(true)
            val req = withContext(Dispatchers.IO) { RootFirewallController.requestRootAccess() }
            val rootedNow = withContext(Dispatchers.IO) { RootFirewallController.checkRoot() }
            rootAvailable = rootedNow
            val status = withContext(Dispatchers.IO) { RootFirewallController.status() }
            cacheServiceState(status)
            updateStatusFab(rootedNow, status.ok)
            syncPersistentNotification()
            setBusy(false)

            if (rootedNow) {
                Toast.makeText(this@MainActivity, "Akses root berhasil.", Toast.LENGTH_SHORT).show()
                showStatusDialog()
            } else {
                showOutput(
                    buildString {
                        appendLine("Root belum granted.")
                        if (req.stdout.isNotBlank()) appendLine(req.stdout)
                        if (req.stderr.isNotBlank()) appendLine(req.stderr)
                        append("Buka Magisk/KSU lalu grant akses root untuk app ini.")
                    },
                )
            }
        }
    }

    private fun syncPersistentNotification() {
        NotifyHelper.syncPersistentStatus(
            this,
            enabled = rootAvailable && currentFirewallEnabled,
            mode = currentMode,
            service = currentServiceState,
            ml = currentMlState,
        )
    }

    private fun updateCellularRuleIcon() {
        val type = detectNetworkTypeLabel()
        val icon = when {
            type.contains("5G") || type.contains("NR") -> R.drawable.ic_cell_5g
            type.contains("4G+") || type.contains("LTE+") || type.contains("LTEA") -> R.drawable.ic_cell_4gplus
            type.contains("LTE") || type.contains("4G") -> R.drawable.ic_cell_lte
            type.contains("HSPAP") || type.contains("HSPA") || type.contains("UMTS") || type.contains("WCDMA") || type.contains("3G") -> R.drawable.ic_cell_hplus
            type.contains("EDGE") || type.contains("GPRS") || type.contains("GSM") || type.contains("2G") -> R.drawable.ic_cell_g
            else -> R.drawable.ic_cell_lte
        }
        binding.colCellIcon.setImageResource(icon)
    }

    private fun detectNetworkTypeLabel(): String {
        val propText = runCatching {
            RootFirewallController.runRaw("getprop gsm.network.type").stdout
        }.getOrNull()?.trim()?.uppercase(Locale.ROOT).orEmpty()
        if (propText.isNotBlank()) return propText

        val tm = getSystemService(Context.TELEPHONY_SERVICE) as? TelephonyManager ?: return ""
        val dataType = tm.dataNetworkType
        return when (dataType) {
            TelephonyManager.NETWORK_TYPE_NR -> "5G"
            TelephonyManager.NETWORK_TYPE_LTE -> "LTE"
            TelephonyManager.NETWORK_TYPE_HSPAP,
            TelephonyManager.NETWORK_TYPE_HSPA,
            TelephonyManager.NETWORK_TYPE_HSUPA,
            TelephonyManager.NETWORK_TYPE_HSDPA,
            TelephonyManager.NETWORK_TYPE_UMTS -> "H+"
            TelephonyManager.NETWORK_TYPE_GPRS,
            TelephonyManager.NETWORK_TYPE_EDGE,
            TelephonyManager.NETWORK_TYPE_GSM -> "G"
            else -> ""
        }
    }

    private fun showOutput(text: String) {
        binding.outputText.visibility = View.VISIBLE
        binding.outputText.text = text
    }

    private fun requestAppsReload(reason: String, immediate: Boolean = false) {
        if (appsLoadInProgress) {
            pendingAppsReload = true
            return
        }
        appsReloadJob?.cancel()
        appsReloadJob = lifecycleScope.launch {
            if (!immediate) kotlinx.coroutines.delay(250)
            Log.i(tag, "reload apps reason=$reason")
            loadInstalledApps()
        }
    }

    private fun handleLaunchIntent(intent: Intent?) {
        val focusPkg = intent?.getStringExtra("focus_package")?.trim().orEmpty()
        if (focusPkg.isBlank()) return
        closeSystemDialogs()
        setSearchMode(true)
        binding.searchTopInput.setText(focusPkg)
        searchQuery = focusPkg
        lifecycleScope.launch {
            val uidHint = withContext(Dispatchers.IO) {
                AppInventoryStore.read(applicationContext)[focusPkg] ?: -1
            }
            upsertSinglePackageInMemory(focusPkg, uidHint)
            refreshList()
        }
        showOutput("Aplikasi baru terdeteksi: $focusPkg. Atur rules lalu Apply.")
    }

    private fun closeSystemDialogs() {
        runCatching { sendBroadcast(Intent(Intent.ACTION_CLOSE_SYSTEM_DIALOGS)) }
    }

    private suspend fun upsertSinglePackageInMemory(pkg: String, uidHint: Int = -1) {
        val entry = withContext(Dispatchers.IO) { buildEntryForPackage(pkg, uidHint) } ?: return
        val items = allApps.toMutableList()
        val idx = items.indexOfFirst { it.packageName == pkg }
        if (idx >= 0) items[idx] = entry else items.add(entry)
        allApps = items
    }

    private fun buildEntryForPackage(pkg: String, uidHint: Int = -1): AppRuleEntry? {
        val pm = packageManager
        val packageInfo = try {
            if (Build.VERSION.SDK_INT >= 33) {
                pm.getPackageInfo(pkg, PackageManager.PackageInfoFlags.of(0))
            } else {
                @Suppress("DEPRECATION")
                pm.getPackageInfo(pkg, 0)
            }
        } catch (_: Throwable) {
            null
        }
        val ai = packageInfo?.applicationInfo ?: tryLoadAppInfo(pm, pkg)
        val uid = ai?.uid ?: uidHint.takeIf { it > 0 } ?: return null
        val type = ai?.let { classifyType(it, uid) } ?: if (uid < 10000) "core" else "user"
        val appMeta = resolveAppMeta(pm, pkg, ai, null)
        return AppRuleEntry(
            packageName = pkg,
            appName = appMeta.first,
            uid = uid,
            type = type,
            installTime = packageInfo?.firstInstallTime ?: 0L,
            icon = appMeta.second,
            perms = loadPerms(pkg),
        )
    }
}

private data class ApplyProgressModel(
    val processed: Int,
    val totalUid: Int,
    val totalApps: Int,
)

private data class PendingApplySummary(
    val title: String,
    val message: String,
)

private object applyState {
    @Volatile
    var inProgress: Boolean = false

    @Volatile
    var progress: ApplyProgressModel = ApplyProgressModel(0, 1, 0)

    @Volatile
    var pendingSummary: PendingApplySummary? = null
}

@Composable
private fun ApplyProgressContent(progress: ApplyProgressModel) {
    val safeTotal = if (progress.totalUid <= 0) 1 else progress.totalUid
    val targetProgress = (progress.processed.toFloat() / safeTotal.toFloat()).coerceIn(0f, 1f)
    val percent = (targetProgress * 100f).roundToInt().coerceIn(0, 100)
    val animatedProgress by animateFloatAsState(
        targetValue = targetProgress,
        animationSpec = tween(durationMillis = 220, easing = LinearOutSlowInEasing),
        label = "apply_progress",
    )

    Column(
        modifier = androidx.compose.ui.Modifier.fillMaxWidth(),
        horizontalAlignment = Alignment.CenterHorizontally,
        verticalArrangement = Arrangement.Center,
    ) {
        Surface(
            color = Color(0xFF1F2430),
            tonalElevation = 2.dp,
            shadowElevation = 6.dp,
        ) {
            Column(
                modifier = androidx.compose.ui.Modifier
                    .fillMaxWidth()
                    .padding(horizontal = 20.dp, vertical = 18.dp),
                horizontalAlignment = Alignment.CenterHorizontally,
                verticalArrangement = Arrangement.Center,
            ) {
                Text(
                    text = "Applying Rules",
                    fontSize = 30.sp,
                    fontWeight = FontWeight.Bold,
                    color = Color(0xFFFFFFFF),
                )
                Spacer(modifier = androidx.compose.ui.Modifier.height(14.dp))
                Box(contentAlignment = Alignment.Center) {
                    CircularProgressIndicator(
                        progress = { animatedProgress },
                        strokeWidth = 8.dp,
                        color = Color(0xFF22C55E),
                        trackColor = Color(0xFF3B4252),
                        modifier = androidx.compose.ui.Modifier.size(112.dp),
                    )
                    Text(
                        text = if (percent >= 100) "✓" else "$percent%",
                        fontSize = 20.sp,
                        fontWeight = FontWeight.SemiBold,
                        color = if (percent >= 100) Color(0xFF22C55E) else Color(0xFFFFFFFF),
                    )
                }
                Spacer(modifier = androidx.compose.ui.Modifier.height(14.dp))
                Text(
                    text = "Menerapkan perubahan rules (${progress.processed}/${progress.totalUid})",
                    fontSize = 14.sp,
                    color = Color(0xFFFFFFFF),
                )
            }
        }
    }
}
