package com.mrksvt.firewallagent

import android.app.Service
import android.content.Context
import android.content.Intent
import android.os.Build
import android.os.IBinder
import android.provider.Settings
import android.util.Log
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.Job
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.cancel
import kotlinx.coroutines.delay
import kotlinx.coroutines.isActive
import kotlinx.coroutines.launch
import java.net.Inet4Address
import java.net.Inet6Address
import java.net.InetAddress
import java.util.Locale

class GlobalRuleSyncService : Service() {
    companion object {
        const val ACTION_START_GLOBAL_STRICT = "com.mrksvt.firewallagent.action.START_GLOBAL_STRICT"
        const val ACTION_STOP_GLOBAL_STRICT = "com.mrksvt.firewallagent.action.STOP_GLOBAL_STRICT"
        const val ACTION_PANIC_DISABLE = "com.mrksvt.firewallagent.action.PANIC_DISABLE"

        private const val PREF_FILE = "global_strict_state"
        private const val KEY_ENABLED = "enabled"
        private const val KEY_FAIL_COUNT = "fail_count"
        private const val KEY_BOOT_SAFE_UNTIL = "boot_safe_until_ms"
        private const val BOOT_SAFE_WINDOW_MS = 10 * 60 * 1000L
    }

    private val scope = CoroutineScope(SupervisorJob() + Dispatchers.IO)
    private var syncJob: Job? = null

    private val defaultAllowDomains = linkedSetOf(
        "google.com",
        "gstatic.com",
        "googleapis.com",
        "android.com",
        "connectivitycheck.gstatic.com",
        "clients3.google.com",
        "telegram.org",
        "t.me",
        "facebook.com",
        "fb.com",
        "fbcdn.net",
        "instagram.com",
        "cdninstagram.com",
        "whatsapp.com",
    )

    private val defaultBlockDomains = linkedSetOf(
        "ppv99b.xyz",
        "rejekibetasia02.com",
        "bw88cdn.com",
        "bw88cdn.net",
        "55rp.plx193.com",
        "liftoff.io",
        "liftoff-creatives.io",
        "mintegral.com",
    )

    override fun onCreate() {
        super.onCreate()
        NotifyHelper.ensureChannel(this)
        startForeground(
            9011,
            NotifyHelper.buildPersistentStatusNotification(
                context = this,
                enabled = true,
                mode = "global_strict",
                service = "rule-sync",
                ml = "strict",
            ),
        )
    }

    override fun onStartCommand(intent: Intent?, flags: Int, startId: Int): Int {
        val action = intent?.action.orEmpty()
        when (action) {
            ACTION_STOP_GLOBAL_STRICT, ACTION_PANIC_DISABLE -> {
                disableStrict(reason = if (action == ACTION_PANIC_DISABLE) "panic" else "manual-stop")
                stopSelf()
                return START_NOT_STICKY
            }
            ACTION_START_GLOBAL_STRICT, "" -> {
                if (isBootSafeBlocked()) {
                    Log.w("FA.GlobalStrict", "boot-safe active, skip strict start")
                    NotifyHelper.post(this, "Firewall Agent", "Global strict ditunda (boot-safe).", 1301)
                    stopSelf()
                    return START_NOT_STICKY
                }
                getSharedPreferences(PREF_FILE, MODE_PRIVATE).edit().putBoolean(KEY_ENABLED, true).apply()
                ensureSyncLoop()
            }
        }
        return START_STICKY
    }

    override fun onDestroy() {
        syncJob?.cancel()
        scope.cancel()
        super.onDestroy()
    }

    override fun onBind(intent: Intent?): IBinder? = null

    private fun ensureSyncLoop() {
        if (syncJob?.isActive == true) return
        syncJob = scope.launch {
            val appUid = applicationInfo.uid
            val applyRes = RootFirewallController.applyGlobalStrict(appUid)
            if (!applyRes.ok) {
                onSyncFailure("apply-global-failed: ${applyRes.stderr.ifBlank { applyRes.stdout }}")
                return@launch
            }
            Log.i("FA.GlobalStrict", "global strict enabled for uid=$appUid")

            while (isActive) {
                val ok = runCatching { syncOnce() }.getOrElse {
                    onSyncFailure("sync-exception: ${it.message}")
                    false
                }
                if (!ok) {
                    delay(5_000)
                    continue
                }
                resetFailCount()
                delay(45_000)
            }
        }
    }

    private fun syncOnce(): Boolean {
        val adguardPref = getSharedPreferences("adguard_dns", MODE_PRIVATE)
        val statePref = getSharedPreferences(PREF_FILE, MODE_PRIVATE)
        val externalFeedHosts = BlacklistFeedSync.syncIfDue(applicationContext)

        val savedDnsHost = adguardPref.getString("saved_dns_host", "").orEmpty().trim().lowercase(Locale.US)
        val userAllow = parseCsv(adguardPref.getString("global_allow_domains_csv", ""))
        val userBlock = parseCsv(adguardPref.getString("global_block_domains_csv", ""))
        val externalCached = parseCsv(adguardPref.getString("external_block_domains_csv", ""))

        val allowDomains = linkedSetOf<String>().apply {
            addAll(defaultAllowDomains)
            addAll(userAllow)
            if (savedDnsHost.isNotBlank()) add(savedDnsHost)
        }
        val blockDomains = linkedSetOf<String>().apply {
            addAll(defaultBlockDomains)
            addAll(userBlock)
            addAll(externalCached)
            addAll(externalFeedHosts)
        }

        val allowV4 = linkedSetOf<String>()
        val allowV6 = linkedSetOf<String>()
        val blockV4 = linkedSetOf<String>()
        val blockV6 = linkedSetOf<String>()

        resolveDomains(allowDomains, allowV4, allowV6)
        resolveDomains(blockDomains, blockV4, blockV6)

        val localAllowV4 = linkedSetOf("127.0.0.1")
        val localAllowV6 = linkedSetOf("::1")
        localAllowV4.addAll(allowV4)
        localAllowV6.addAll(allowV6)

        val syncRes = RootFirewallController.syncIpSets(
            allowV4 = localAllowV4,
            allowV6 = localAllowV6,
            blockV4 = blockV4,
            blockV6 = blockV6,
        )
        if (!syncRes.ok) {
            onSyncFailure("ipset-sync-failed: ${syncRes.stderr.ifBlank { syncRes.stdout }}")
            return false
        }

        val dnsLockEnabled = adguardPref.getBoolean("dns_lock_enabled", false)
        val dnsMode = readSystemSetting("private_dns_mode")
        if (!dnsLockEnabled || dnsMode != "hostname") {
            onSyncFailure("dns-lock-or-private-dns-not-ready")
            return false
        }

        val hbRes = RootFirewallController.runRaw("iptables -S FA_GLOBAL_OUT 2>/dev/null | head -n 1")
        if (!hbRes.ok || hbRes.stdout.isBlank()) {
            onSyncFailure("global-chain-missing")
            return false
        }

        statePref.edit().putBoolean(KEY_ENABLED, true).apply()
        Log.i(
            "FA.GlobalStrict",
            "sync ok allowV4=${localAllowV4.size} allowV6=${localAllowV6.size} blockV4=${blockV4.size} blockV6=${blockV6.size} feed=${externalFeedHosts.size}",
        )
        return true
    }

    private fun onSyncFailure(reason: String) {
        val pref = getSharedPreferences(PREF_FILE, MODE_PRIVATE)
        val failCount = pref.getInt(KEY_FAIL_COUNT, 0) + 1
        pref.edit().putInt(KEY_FAIL_COUNT, failCount).apply()
        Log.w("FA.GlobalStrict", "sync failure #$failCount reason=$reason")
        if (failCount >= 3) {
            pref.edit().putLong(KEY_BOOT_SAFE_UNTIL, System.currentTimeMillis() + BOOT_SAFE_WINDOW_MS).apply()
            disableStrict("auto-rollback:$reason")
            stopSelf()
        }
    }

    private fun resetFailCount() {
        getSharedPreferences(PREF_FILE, MODE_PRIVATE).edit().putInt(KEY_FAIL_COUNT, 0).apply()
    }

    private fun isBootSafeBlocked(): Boolean {
        val until = getSharedPreferences(PREF_FILE, MODE_PRIVATE).getLong(KEY_BOOT_SAFE_UNTIL, 0L)
        return until > System.currentTimeMillis()
    }

    private fun disableStrict(reason: String) {
        val pref = getSharedPreferences(PREF_FILE, MODE_PRIVATE)
        val disableRes = RootFirewallController.disableGlobalStrict()
        pref.edit()
            .putBoolean(KEY_ENABLED, false)
            .putInt(KEY_FAIL_COUNT, 0)
            .apply()
        Log.w("FA.GlobalStrict", "global strict disabled reason=$reason ok=${disableRes.ok}")
        NotifyHelper.post(this, "Firewall Agent", "Global strict dimatikan ($reason)", 1302)
    }

    private fun resolveDomains(domains: Set<String>, outV4: MutableSet<String>, outV6: MutableSet<String>) {
        domains.forEach { host ->
            val normalized = host.trim().lowercase(Locale.US)
            if (normalized.isBlank()) return@forEach
            runCatching { InetAddress.getAllByName(normalized) }
                .getOrDefault(emptyArray())
                .forEach { addr ->
                    when (addr) {
                        is Inet4Address -> outV4 += addr.hostAddress.orEmpty()
                        is Inet6Address -> outV6 += addr.hostAddress.orEmpty()
                    }
                }
        }
    }

    private fun parseCsv(raw: String?): Set<String> {
        if (raw.isNullOrBlank()) return emptySet()
        return raw.split(',')
            .map { it.trim().lowercase(Locale.US) }
            .filter { it.isNotBlank() }
            .toSet()
    }

    private fun readSystemSetting(key: String): String {
        return runCatching {
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.JELLY_BEAN_MR1) {
                Settings.Global.getString(contentResolver, key).orEmpty()
            } else {
                ""
            }
        }.getOrDefault("")
    }

    fun isEnabled(context: Context): Boolean {
        return context.getSharedPreferences(PREF_FILE, MODE_PRIVATE).getBoolean(KEY_ENABLED, false)
    }
}
