package com.mrksvt.firewallagent

import android.content.Context

object LogSnapshotCache {
    private const val PREF = "fa_log_snapshot_cache"
    private const val KEY_NET_RAW = "net_raw_v1"
    private const val KEY_NET_TS = "net_ts_v1"
    private const val KEY_AD_RAW = "ad_raw_v1"
    private const val KEY_AD_TS = "ad_ts_v1"
    private const val KEY_CTL_TAIL = "ctl_tail_raw_v1"
    private const val KEY_CTL_TS = "ctl_tail_ts_v1"
    private const val TTL_MS = 45_000L

    fun prewarm(context: Context) {
        runCatching { getHybridNetEvents(context, maxLines = 40000) }
        runCatching { getHybridAdEvents(context, maxLines = 40000) }
        runCatching { getControllerRunnerTail(context, maxLines = 1600) }
    }

    fun prewarmLite(context: Context) {
        runCatching { getControllerRunnerTail(context, maxLines = 600) }
        runCatching { getHybridAdEvents(context, maxLines = 12000) }
    }

    fun getHybridNetEvents(context: Context, maxLines: Int = 60000): String {
        return getOrRefresh(
            context = context,
            rawKey = KEY_NET_RAW,
            tsKey = KEY_NET_TS,
            command = "grep -h 'FA.HybridAdHook net event ' /data/adb/lspd/log/modules_*.log 2>/dev/null | tail -n $maxLines",
        )
    }

    fun getHybridAdEvents(context: Context, maxLines: Int = 40000): String {
        return getOrRefresh(
            context = context,
            rawKey = KEY_AD_RAW,
            tsKey = KEY_AD_TS,
            command = "grep -h -E 'FA.HybridAdHook|FA.DnsHideHook' /data/adb/lspd/log/modules_*.log 2>/dev/null | tail -n $maxLines",
        )
    }

    fun getControllerRunnerTail(context: Context, maxLines: Int = 1600): String {
        return getOrRefresh(
            context = context,
            rawKey = KEY_CTL_TAIL,
            tsKey = KEY_CTL_TS,
            command = "tail -n $maxLines /data/local/tmp/firewall_agent/logs/controller.log 2>/dev/null",
        )
    }

    private fun getOrRefresh(
        context: Context,
        rawKey: String,
        tsKey: String,
        command: String,
    ): String {
        val pref = context.getSharedPreferences(PREF, Context.MODE_PRIVATE)
        val now = System.currentTimeMillis()
        val lastTs = pref.getLong(tsKey, 0L)
        val cached = pref.getString(rawKey, "").orEmpty()
        if (cached.isNotBlank() && (now - lastTs) <= TTL_MS) return cached

        val fresh = RootFirewallController.runRaw(command).stdout
        if (fresh.isNotBlank()) {
            pref.edit()
                .putString(rawKey, fresh)
                .putLong(tsKey, now)
                .apply()
            return fresh
        }
        return cached
    }
}
