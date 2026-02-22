package com.mrksvt.firewallagent

import android.app.AlarmManager
import android.app.PendingIntent
import android.app.Service
import android.content.BroadcastReceiver
import android.content.Context
import android.content.Intent
import android.content.IntentFilter
import android.net.ConnectivityManager
import android.net.Network
import android.net.NetworkCapabilities
import android.net.Uri
import android.os.IBinder
import android.util.Log
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.cancel
import kotlinx.coroutines.delay
import kotlinx.coroutines.launch
import org.json.JSONObject
import org.json.JSONException
import java.net.InetSocketAddress
import java.net.Socket
import kotlin.system.measureNanoTime

class FirewallKeepAliveService : Service() {
    companion object {
        const val ACTION_INTERNAL_PACKAGE_ADDED = "com.mrksvt.firewallagent.PACKAGE_ADDED_INTERNAL"
        const val ACTION_RESTART_SELF = "com.mrksvt.firewallagent.ACTION_RESTART_SELF"
        const val ACTION_STOP_SELF = "com.mrksvt.firewallagent.ACTION_STOP_SELF"
    }
    private val tag = "FA.Handover"
    private val scope = CoroutineScope(SupervisorJob() + Dispatchers.IO)
    private var cm: ConnectivityManager? = null
    private var networkCallback: ConnectivityManager.NetworkCallback? = null
    @Volatile private var lastHandoverFixAt = 0L
    @Volatile private var lastNetworkSignature = ""
    private var packageAddedReceiver: BroadcastReceiver? = null
    private var shutdownReceiver: BroadcastReceiver? = null
    @Volatile private var shuttingDown: Boolean = false
    @Volatile private var stopRequested: Boolean = false
    private val autoDnsHosts = listOf(
        "base.dns.mullvad.net",
        "family.dns.mullvad.net",
        "dns.quad9.net",
        "dns11.quad9.net",
        "dns.dnsguard.pub",
        "dns.adguard-dns.com",
        "family.adguard-dns.com",
        "doh.cleanbrowsing.org",
        "security.cloudflare-dns.com",
    )
    private val adHostPatterns = listOf(
        "doubleclick.net",
        "googleads.g.doubleclick.net",
        "adservice.google.com",
        "adservice.google.",
        "googlesyndication.com",
        "admob.com",
        "app-measurement.com",
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

    override fun onCreate() {
        super.onCreate()
        stopRequested = false
        shuttingDown = false
        Log.i(tag, "engine=v2.1 start")
        NotifyHelper.ensureChannel(this)
        RootFirewallController.init(applicationContext)
        startForeground(
            9001,
            NotifyHelper.buildPersistentStatusNotification(
                context = this,
                enabled = false,
                mode = "audit",
                service = "starting",
                ml = "unknown",
            ),
        )
        lastNetworkSignature = currentNetworkSignature()
        registerNetworkCallback()
        registerPackageAddedReceiver()
        registerShutdownReceiver()
        scope.launch {
            runCatching { cleanupOrphanManagedUids() }
            runCatching { AppInventoryStore.refreshSnapshot(applicationContext) }
            runCatching { AppMetaCacheStore.refreshSnapshot(applicationContext) }
            while (true) {
                runCatching { syncStatusNotification() }
                runCatching { AppInventoryStore.refreshSnapshot(applicationContext) }
                runCatching { AppMetaCacheStore.refreshSnapshot(applicationContext) }
                delay(60_000)
            }
        }
    }

    override fun onStartCommand(intent: Intent?, flags: Int, startId: Int): Int {
        val action = intent?.action.orEmpty()
        if (action == ACTION_STOP_SELF) {
            stopRequested = true
            stopSelf()
            return START_NOT_STICKY
        }
        scope.launch {
            runCatching { cleanupOrphanManagedUids() }
            runCatching { syncStatusNotification() }
            runCatching { handleNetworkTransition("service_start") }
        }
        return START_STICKY
    }

    override fun onTaskRemoved(rootIntent: Intent?) {
        super.onTaskRemoved(rootIntent)
        if (stopRequested || shuttingDown) return
        scheduleSelfRestart(2_500L)
        Log.w(tag, "task_removed: restart scheduled")
    }

    private fun registerNetworkCallback() {
        val mgr = getSystemService(Context.CONNECTIVITY_SERVICE) as? ConnectivityManager ?: return
        cm = mgr
        val cb = object : ConnectivityManager.NetworkCallback() {
            override fun onAvailable(network: Network) {
                scope.launch { handleNetworkTransition("onAvailable") }
            }

            override fun onCapabilitiesChanged(network: Network, networkCapabilities: NetworkCapabilities) {
                scope.launch { handleNetworkTransition("onCapabilitiesChanged") }
            }

            override fun onLost(network: Network) {
                scope.launch { handleNetworkTransition("onLost") }
            }
        }
        networkCallback = cb
        runCatching { mgr.registerDefaultNetworkCallback(cb) }
    }

    private fun registerPackageAddedReceiver() {
        if (packageAddedReceiver != null) return
        val receiver = object : BroadcastReceiver() {
            override fun onReceive(context: Context, intent: Intent?) {
                val action = intent?.action ?: return
                val pkg = intent.data?.schemeSpecificPart?.trim().orEmpty()
                if (pkg.isBlank()) return
                if (pkg == packageName) return

                if (action == Intent.ACTION_PACKAGE_FULLY_REMOVED) {
                    scope.launch {
                        runCatching { AppInventoryStore.remove(applicationContext, pkg) }
                        runCatching { AppMetaCacheStore.remove(applicationContext, pkg) }
                    }
                    return
                }

                if (action != Intent.ACTION_PACKAGE_ADDED) return
                if (intent.getBooleanExtra(Intent.EXTRA_REPLACING, false)) return
                val uid = intent.getIntExtra(Intent.EXTRA_UID, -1)
                if (uid <= 0) return
                if (!RootFirewallController.isManagedAppUid(uid)) return

                scope.launch {
                    runCatching { applyDefaultDenyForAllProfiles(pkg) }
                    runCatching { enforceUidDenyIfFirewallEnabled(uid) }
                    runCatching { AppInventoryStore.upsert(applicationContext, pkg, uid) }
                    runCatching { AppMetaCacheStore.upsert(applicationContext, pkg, uid) }
                    runCatching { NotifyHelper.postNewAppNeedsRules(applicationContext, pkg) }
                    runCatching {
                        sendBroadcast(
                            Intent(ACTION_INTERNAL_PACKAGE_ADDED).apply {
                                `package` = packageName
                                data = Uri.parse("package:$pkg")
                                putExtra("pkg", pkg)
                                putExtra("uid", uid)
                            },
                        )
                    }
                    Log.i(tag, "pkg_added_fallback handled pkg=$pkg uid=$uid")
                }
            }
        }
        val filter = IntentFilter().apply {
            addAction(Intent.ACTION_PACKAGE_ADDED)
            addAction(Intent.ACTION_PACKAGE_FULLY_REMOVED)
            addDataScheme("package")
        }
        registerReceiver(receiver, filter)
        packageAddedReceiver = receiver
    }

    private fun registerShutdownReceiver() {
        if (shutdownReceiver != null) return
        val receiver = object : BroadcastReceiver() {
            override fun onReceive(context: Context?, intent: Intent?) {
                val action = intent?.action.orEmpty()
                if (action == Intent.ACTION_SHUTDOWN || action == Intent.ACTION_REBOOT) {
                    shuttingDown = true
                }
            }
        }
        val filter = IntentFilter().apply {
            addAction(Intent.ACTION_SHUTDOWN)
            addAction(Intent.ACTION_REBOOT)
        }
        registerReceiver(receiver, filter)
        shutdownReceiver = receiver
    }

    private fun applyDefaultDenyForAllProfiles(pkg: String) {
        val profilePref = getSharedPreferences("fw_profiles", MODE_PRIVATE)
        val raw = profilePref.getString("profiles_csv", "anlap").orEmpty()
        val profiles = raw.split(',')
            .map { it.trim() }
            .filter { it.isNotBlank() }
            .ifEmpty { listOf("anlap") }
            .distinct()

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

        profiles.forEach { p ->
            val key = p.lowercase()
                .replace(Regex("[^a-z0-9._-]"), "_")
                .ifBlank { "default" }
            getSharedPreferences("fw_app_rules_$key", MODE_PRIVATE)
                .edit()
                .putString(pkg, deny)
                .apply()
        }
    }

    private fun enforceUidDenyIfFirewallEnabled(uid: Int) {
        if (!RootFirewallController.checkRoot()) return
        val status = RootFirewallController.status().stdout
        val enabled = runCatching { JSONObject(status).optBoolean("firewall_enabled", false) }.getOrDefault(false)
        if (!enabled) return
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

    private fun handleNetworkTransition(reason: String) {
        if (!RootFirewallController.checkRoot()) return
        val now = System.currentTimeMillis()
        if (now - lastHandoverFixAt < 8_000L) return
        val before = lastNetworkSignature
        val after = currentNetworkSignature()
        if (after == before) return
        lastHandoverFixAt = now
        lastNetworkSignature = after

        // 1) detect network now + change + new network
        Log.i(tag, "step1 current_network=$before")
        Log.i(tag, "step2 network_changed reason=$reason")
        Log.i(tag, "step3 new_network=$after")

        // Tunggu sebentar sampai route/resolver baru settle
        Thread.sleep(1200)

        val lockDesired = isDnsLockDesired()

        // 2) cleanup DNS rules
        val clean = clearDnsRules()
        Log.i(tag, "step4 clear_dns_rules exit=${clean.code}")

        // 3) ping saved dns
        val savedHost = resolveSavedDnsHost()
        Log.i(tag, "step5 saved_dns=$savedHost lock_desired=$lockDesired")
        if (savedHost.isNotBlank() && probeDnsHostWithRetry(savedHost)) {
            // 4) rewrite rules when ping success
            val applyCode = if (lockDesired) applyDnsLockRulesForCurrentNetwork().code else 0
            RootFirewallController.runRaw("settings put global private_dns_mode hostname; settings put global private_dns_specifier $savedHost")
            Log.i(tag, "step6 rewrite_rules_for_saved_dns exit=$applyCode lock=${if (lockDesired) "on" else "off"}")
            NotifyHelper.post(this, "Firewall Agent", "Handover OK: DNS $savedHost aktif.", 1204)
            return
        }

        if (lockDesired) {
            val apply = applyDnsLockRulesForCurrentNetwork()
            Log.w(tag, "step7 keep_user_dns_and_reapply_lock exit=${apply.code}")
            NotifyHelper.post(this, "Firewall Agent", "Handover: DNS/Lock user dipertahankan.", 1205)
        } else {
            Log.w(tag, "step7 lock_not_desired keep_current_dns")
            NotifyHelper.post(this, "Firewall Agent", "Handover: DNS user dipertahankan.", 1205)
        }
    }

    private fun currentNetworkSignature(): String {
        val mgr = cm ?: return "none"
        val net = mgr.activeNetwork ?: return "none"
        val cap = mgr.getNetworkCapabilities(net) ?: return "none"
        val transport = when {
            cap.hasTransport(NetworkCapabilities.TRANSPORT_WIFI) -> "wifi"
            cap.hasTransport(NetworkCapabilities.TRANSPORT_CELLULAR) -> "cell"
            cap.hasTransport(NetworkCapabilities.TRANSPORT_ETHERNET) -> "eth"
            cap.hasTransport(NetworkCapabilities.TRANSPORT_VPN) -> "vpn"
            else -> "other"
        }
        val validated = cap.hasCapability(NetworkCapabilities.NET_CAPABILITY_VALIDATED)
        return "$transport|validated=$validated|net=${net.hashCode()}"
    }

    private fun resolveSavedDnsHost(): String {
        val state = RootFirewallController.runRaw(
            "settings get global private_dns_mode; settings get global private_dns_specifier",
        ).stdout.lines().map { it.trim() }.filter { it.isNotEmpty() }
        val mode = state.getOrNull(0).orEmpty()
        val host = state.getOrNull(1).orEmpty()
        if (mode == "hostname" && host.isNotBlank() && host != "null") return host
        val pref = getSharedPreferences("adguard_dns", MODE_PRIVATE)
        return pref.getString("saved_dns_host", "").orEmpty()
    }

    private fun isDnsLockDesired(): Boolean {
        val pref = getSharedPreferences("adguard_dns", MODE_PRIVATE)
        if (pref.getBoolean("dns_lock_enabled", false)) return true
        val lockState = RootFirewallController.runRaw(
            "if iptables -S OUTPUT 2>/dev/null | grep -q ' -j FA_DNS'; then echo on; else echo off; fi",
        ).stdout.trim()
        return lockState == "on"
    }

    private fun probeDnsHost(host: String): Boolean {
        val dot = tcpConnectLatency(host, 853, 1700)
        val https = tcpConnectLatency(host, 443, 1700)
        Log.i(tag, "step5 ping_saved_dns host=$host dot=${dot}ms https=${https}ms")
        return dot >= 0 || https >= 0
    }

    private fun probeDnsHostWithRetry(host: String): Boolean {
        repeat(3) { i ->
            if (probeDnsHost(host)) return true
            Log.w(tag, "step5 retry_saved_dns attempt=${i + 1} host=$host")
            Thread.sleep(1200)
        }
        return false
    }

    private fun chooseBestDnsHost(): String? {
        val scored = autoDnsHosts.mapNotNull { h ->
            val ms = tcpConnectLatency(h, 853, 1700)
            if (ms >= 0) h to ms else null
        }
        return scored.minByOrNull { it.second }?.first
    }

    private fun chooseBestDnsHostWithRetry(): String? {
        repeat(2) { i ->
            val best = chooseBestDnsHost()
            if (best != null) return best
            Log.w(tag, "step7 retry_fallback_dns pass=${i + 1}")
            Thread.sleep(1200)
        }
        return null
    }

    private fun tcpConnectLatency(host: String, port: Int, timeoutMs: Int): Int {
        return try {
            var elapsedMs = -1
            val duration = measureNanoTime {
                Socket().use { s ->
                    s.connect(InetSocketAddress(host, port), timeoutMs)
                }
            }
            elapsedMs = (duration / 1_000_000.0).toInt()
            elapsedMs
        } catch (_: Exception) {
            -1
        }
    }

    private fun refreshDnsLockAllowlistIfEnabled() {
        val lockState = RootFirewallController.runRaw(
            "if iptables -S OUTPUT 2>/dev/null | grep -q ' -j FA_DNS'; then echo on; else echo off; fi",
        ).stdout.trim()
        if (lockState != "on") return
        val cmd = buildString {
            append("iptables -N FA_DNS >/dev/null 2>&1 || true;")
            append("iptables -F FA_DNS >/dev/null 2>&1 || true;")
            // Bypass UID sistem agar resolver internal Android tetap stabil saat network handover.
            append("iptables -A FA_DNS -m owner --uid-owner 0-9999 -j RETURN;")
            append("iptables -A FA_DNS -o lo -j RETURN;")
            append("iptables -A FA_DNS -d 127.0.0.0/8 -j RETURN;")
            append("for ip in 94.140.14.14 94.140.15.15; do ")
            append("iptables -A FA_DNS -p udp --dport 53 -d \"${'$'}ip\" -j RETURN;")
            append("iptables -A FA_DNS -p tcp --dport 53 -d \"${'$'}ip\" -j RETURN;")
            append("iptables -A FA_DNS -p tcp --dport 853 -d \"${'$'}ip\" -j RETURN;")
            append("done;")
            append(
                "for p in net.dns1 net.dns2 net.dns3 net.dns4; do " +
                    "d=$(getprop ${'$'}p); " +
                    "case \"${'$'}d\" in ''|'0.0.0.0'|'::') continue;; esac; " +
                    "echo \"${'$'}d\" | grep -q ':' && continue; " +
                    "iptables -A FA_DNS -p udp --dport 53 -d \"${'$'}d\" -j RETURN; " +
                    "iptables -A FA_DNS -p tcp --dport 53 -d \"${'$'}d\" -j RETURN; " +
                    "iptables -A FA_DNS -p tcp --dport 853 -d \"${'$'}d\" -j RETURN; " +
                    "done;",
            )
            append("iptables -A FA_DNS -p udp --dport 53 -j REJECT;")
            append("iptables -A FA_DNS -p tcp --dport 53 -j REJECT;")
            append("while iptables -C OUTPUT -j FA_DNS >/dev/null 2>&1; do iptables -D OUTPUT -j FA_DNS >/dev/null 2>&1 || break; done;")
            append("iptables -I OUTPUT 1 -j FA_DNS;")
            append(buildAdsFirewallEnableScript(resolveAdPatterns()))
        }
        val r = RootFirewallController.runRaw(cmd)
        Log.i(tag, "refresh FA_DNS lock result=${r.code}")
    }

    private fun clearDnsRules(): ExecResult {
        return RootFirewallController.runRaw(
            "while iptables -C OUTPUT -j FA_DNS >/dev/null 2>&1; do iptables -D OUTPUT -j FA_DNS >/dev/null 2>&1 || break; done;" +
                "iptables -F FA_DNS >/dev/null 2>&1 || true;" +
                "iptables -X FA_DNS >/dev/null 2>&1 || true",
        )
    }

    private fun applyDnsLockRulesForCurrentNetwork(): ExecResult {
        val patterns = resolveAdPatterns()
        val cmd = buildString {
            append("iptables -N FA_DNS >/dev/null 2>&1 || true;")
            append("iptables -F FA_DNS >/dev/null 2>&1 || true;")
            // Bypass UID sistem supaya resolver internal tetap stabil.
            append("iptables -A FA_DNS -m owner --uid-owner 0-9999 -j RETURN;")
            append("iptables -A FA_DNS -o lo -j RETURN;")
            append("iptables -A FA_DNS -d 127.0.0.0/8 -j RETURN;")
            append("for ip in 94.140.14.14 94.140.15.15; do ")
            append("iptables -A FA_DNS -p udp --dport 53 -d \"${'$'}ip\" -j RETURN;")
            append("iptables -A FA_DNS -p tcp --dport 53 -d \"${'$'}ip\" -j RETURN;")
            append("iptables -A FA_DNS -p tcp --dport 853 -d \"${'$'}ip\" -j RETURN;")
            append("done;")
            append(
                "for p in net.dns1 net.dns2 net.dns3 net.dns4; do " +
                    "d=$(getprop ${'$'}p); " +
                    "case \"${'$'}d\" in ''|'0.0.0.0'|'::') continue;; esac; " +
                    "echo \"${'$'}d\" | grep -q ':' && continue; " +
                    "iptables -A FA_DNS -p udp --dport 53 -d \"${'$'}d\" -j RETURN; " +
                    "iptables -A FA_DNS -p tcp --dport 53 -d \"${'$'}d\" -j RETURN; " +
                    "iptables -A FA_DNS -p tcp --dport 853 -d \"${'$'}d\" -j RETURN; " +
                    "done;",
            )
            append("iptables -A FA_DNS -p udp --dport 53 -j REJECT;")
            append("iptables -A FA_DNS -p tcp --dport 53 -j REJECT;")
            append("iptables -I OUTPUT 1 -j FA_DNS;")
            append(buildAdsFirewallEnableScript(patterns))
        }
        return RootFirewallController.runRaw(cmd)
    }

    private fun resolveAdPatterns(): List<String> {
        val persisted = AdMlScorer.loadDynamicPatterns(this)
        return AdMlScorer.mergePatterns(adHostPatterns, persisted)
    }

    private fun buildAdsFirewallEnableScript(patterns: List<String>): String = buildString {
        append("iptables -N FA_ADS >/dev/null 2>&1 || true;")
        append("iptables -F FA_ADS >/dev/null 2>&1 || true;")
        append("iptables -A FA_ADS -m owner --uid-owner 0-9999 -j RETURN;")
        append("iptables -A FA_ADS -o lo -j RETURN;")
        append("if iptables -m string -h >/dev/null 2>&1; then ")
        patterns.forEach { pattern ->
            append("iptables -A FA_ADS -p tcp --dport 80 -m string --algo bm --icase --string \"$pattern\" -m statistic --mode random --probability 0.35 -j RETURN >/dev/null 2>&1 || true;")
            append("iptables -A FA_ADS -p tcp --dport 80 -m string --algo bm --icase --string \"$pattern\" -j DROP >/dev/null 2>&1 || true;")
            append("iptables -A FA_ADS -p tcp --dport 443 -m string --algo bm --icase --string \"$pattern\" -m statistic --mode random --probability 0.35 -j RETURN >/dev/null 2>&1 || true;")
            append("iptables -A FA_ADS -p tcp --dport 443 -m string --algo bm --icase --string \"$pattern\" -j DROP >/dev/null 2>&1 || true;")
        }
        append("fi;")
        append("while iptables -C OUTPUT -j FA_ADS >/dev/null 2>&1; do iptables -D OUTPUT -j FA_ADS >/dev/null 2>&1 || break; done;")
        append("iptables -I OUTPUT 1 -j FA_ADS;")
    }

    private fun cleanupOrphanManagedUids() {
        val installed = packageManager.getInstalledApplications(0)
            .asSequence()
            .map { it.uid }
            .filter { it > 0 }
            .toSet()
        val managed = RootFirewallController.listManagedUids()
        val orphans = managed - installed
        if (orphans.isEmpty()) return
        RootFirewallController.removeUidRules(orphans)

        val pref = getSharedPreferences("fw_shadow_rules", MODE_PRIVATE)
        val stateObj = try {
            JSONObject(pref.getString("rule_state_json", "{}").orEmpty())
        } catch (_: JSONException) {
            JSONObject()
        }
        orphans.forEach { stateObj.remove(it.toString()) }

        val blocked = pref.getString("blocked_uids_csv", "").orEmpty()
            .split(',')
            .mapNotNull { it.trim().toIntOrNull() }
            .filter { it > 0 && it !in orphans }
            .distinct()
            .joinToString(",")

        pref.edit()
            .putString("rule_state_json", stateObj.toString())
            .putString("blocked_uids_csv", blocked)
            .apply()
    }

    private fun syncStatusNotification() {
        val status = RootFirewallController.status()
        var service = "unknown"
        var mode = "audit"
        var enabled = false
        var ml = "unknown"

        if (status.ok && status.stdout.isNotBlank()) {
            runCatching {
                val j = JSONObject(status.stdout.trim())
                service = j.optString("service", "unknown")
                mode = j.optString("mode", "audit")
                enabled = j.optBoolean("firewall_enabled", false)
                ml = if (service == "running") "running" else "stopped"
            }
        }

        val notif = NotifyHelper.buildPersistentStatusNotification(
            context = this,
            enabled = enabled,
            mode = mode,
            service = service,
            ml = ml,
        )
        startForeground(9001, notif)
    }

    override fun onDestroy() {
        runCatching {
            packageAddedReceiver?.let { unregisterReceiver(it) }
        }
        runCatching {
            shutdownReceiver?.let { unregisterReceiver(it) }
        }
        packageAddedReceiver = null
        shutdownReceiver = null
        runCatching {
            val mgr = cm
            val cb = networkCallback
            if (mgr != null && cb != null) mgr.unregisterNetworkCallback(cb)
        }
        networkCallback = null
        scope.cancel()
        if (!stopRequested && !shuttingDown) {
            scheduleSelfRestart(2_000L)
            Log.w(tag, "service_destroyed_unexpected: restart scheduled")
        }
        super.onDestroy()
    }

    override fun onBind(intent: Intent?): IBinder? = null

    private fun scheduleSelfRestart(delayMs: Long) {
        val am = getSystemService(Context.ALARM_SERVICE) as? AlarmManager ?: return
        val restartIntent = Intent(this, RestartServiceReceiver::class.java).apply {
            action = ACTION_RESTART_SELF
            `package` = packageName
        }
        val pi = PendingIntent.getBroadcast(
            this,
            9071,
            restartIntent,
            PendingIntent.FLAG_UPDATE_CURRENT or PendingIntent.FLAG_IMMUTABLE,
        )
        val triggerAt = System.currentTimeMillis() + delayMs
        runCatching {
            am.setExactAndAllowWhileIdle(AlarmManager.RTC_WAKEUP, triggerAt, pi)
        }
    }
}
