package com.mrksvt.firewallagent

import android.net.wifi.WifiConfiguration
import android.net.wifi.WifiInfo
import android.net.wifi.WifiManager

/**
 * Engine koneksi WiFi untuk flow pentest.
 *
 * Jalur utama: `cmd wifi` via root (KSUNext) — framework command, tidak terpengaruh
 * SELinux/SELinux socket block, bekerja di Android 11+.
 * Jalur fallback: Java API legacy (addNetwork/enableNetwork) untuk device tanpa root.
 */
object WifiConnectEngine {

    private const val CONNECT_TIMEOUT_MS = 20_000L
    private const val DHCP_SETTLE_MS = 3_000L
    private const val CMD = "cmd wifi"

    fun securityTypeForCmd(level: NetworkSecurityClassifier.SecurityLevel): String = when (level) {
        NetworkSecurityClassifier.SecurityLevel.OPEN, NetworkSecurityClassifier.SecurityLevel.OWE -> "open"
        NetworkSecurityClassifier.SecurityLevel.WEP -> "wep"
        NetworkSecurityClassifier.SecurityLevel.WPA_TKIP, NetworkSecurityClassifier.SecurityLevel.WPA2 -> "wpa2"
        NetworkSecurityClassifier.SecurityLevel.WPA3 -> "wpa3"
    }

    // ---------- saved network ----------

    /** Cari saved network via `cmd wifi list-networks` (root). Return network id atau null. */
    fun findSavedNetworkIdCmdWifi(ssid: String): Int? {
        val res = RootFirewallController.execRoot("$CMD list-networks 2>/dev/null")
        if (res.code != 0) return null
        val target = ssid.trim('"')
        for (line in res.stdout.lines()) {
            // Format: "Network Id\tSSID\tSecurity type"
            val parts = line.split("\t", limit = 3)
            if (parts.size < 2) continue
            val id = parts[0].toIntOrNull() ?: continue
            val networkSsid = parts[1].trim('"')
            if (networkSsid == target) return id
        }
        return null
    }

    /** Connect ke saved network via `cmd wifi connect-network` (root). */
    fun connectSavedNetworkCmdWifi(ssid: String, securityType: String): Boolean {
        val res = RootFirewallController.execRoot("$CMD connect-network '$ssid' $securityType 2>/dev/null")
        return res.code == 0
    }

    // ---------- connect ----------

    /** Connect dengan password via `cmd wifi` (root). */
    fun tryConnectWithPasswordCmdWifi(
        ssid: String,
        password: String,
        securityType: String = "wpa2",
    ): Boolean {
        val res = RootFirewallController.execRoot(
            "$CMD connect-network '$ssid' $securityType '$password' 2>/dev/null"
        )
        return res.code == 0
    }

    /** Connect open network via `cmd wifi` (root). */
    fun tryConnectOpenCmdWifi(ssid: String): Boolean {
        return tryConnectWithPasswordCmdWifi(ssid, "", "open")
    }

    /** Coba connect dengan satu password (Java API fallback). */
    @Suppress("DEPRECATION")
    fun tryConnectWithPassword(
        wifiManager: WifiManager,
        ssid: String,
        password: String,
        isOpen: Boolean = false,
    ): Boolean {
        val cfg = WifiConfiguration().apply {
            SSID = "\"$ssid\""
            status = WifiConfiguration.Status.ENABLED
            if (isOpen) {
                allowedKeyManagement.set(WifiConfiguration.KeyMgmt.NONE)
            } else {
                preSharedKey = "\"$password\""
                allowedKeyManagement.set(WifiConfiguration.KeyMgmt.WPA_PSK)
            }
        }
        val netId = wifiManager.addNetwork(cfg)
        if (netId == -1) return false
        val enabled = try {
            wifiManager.enableNetwork(netId, true)
        } catch (e: Exception) {
            false
        }
        if (!enabled) {
            cleanupNetwork(wifiManager, netId)
            return false
        }
        val connected = waitForConnection(wifiManager, ssid)
        if (!connected) {
            cleanupNetwork(wifiManager, netId)
        }
        return connected
    }

    /** Brute force PSK — `cmd wifi` via root dulu, Java API fallback. */
    fun bruteConnect(
        wifiManager: WifiManager,
        ssid: String,
        passwords: List<String>,
        securityType: String = "wpa2",
        useRoot: Boolean = true,
        onAttempt: (index: Int, total: Int, password: String, connected: Boolean) -> Unit,
        shouldStop: () -> Boolean = { false },
    ): String? {
        val distinct = passwords.distinct().filter { it.isNotBlank() }
        for ((idx, pass) in distinct.withIndex()) {
            if (shouldStop()) break
            val connected = if (useRoot) {
                tryConnectWithPasswordCmdWifi(ssid, pass, securityType) &&
                    waitForConnectionCmdWifi(ssid)
            } else {
                tryConnectWithPassword(wifiManager, ssid, pass)
            }
            onAttempt(idx + 1, distinct.size, pass, connected)
            if (connected) return pass
        }
        return null
    }

    /** Cek apakah HP sedang terhubung ke SSID ini (via `cmd wifi status`). */
    fun isCurrentlyConnectedCmdWifi(ssid: String): Boolean {
        val res = RootFirewallController.execRoot("$CMD status 2>/dev/null")
        if (res.code != 0) return false
        val out = res.stdout
        val ssidMatch = Regex("SSID: \"([^\"]+)\"").find(out)
        val currentSsid = ssidMatch?.groupValues?.getOrNull(1)?.trim('"') ?: ""
        return currentSsid == ssid.trim('"') && out.contains("Supplicant state: COMPLETED")
    }

    /** Cek via Java API (fallback non-root). */
    @Suppress("DEPRECATION")
    fun isCurrentlyConnected(wifiManager: WifiManager, ssid: String): Boolean {
        val info = try { wifiManager.connectionInfo } catch (e: Exception) { null }
        return isConnectedTo(info, ssid)
    }

    /** Resolve gateway via root (ip route). Primary. */
    fun resolveGatewayRoot(wifiManager: WifiManager): String? {
        val res = RootFirewallController.execRoot(
            "ip route 2>/dev/null | awk '/default/ {print \\$3; exit}'"
        )
        if (res.code == 0) {
            val gw = res.stdout.trim()
            if (gw.isNotEmpty() && gw.contains(".")) return gw
        }
        return resolveGateway(wifiManager)
    }

    /** Tunggu sampai terhubung ke SSID (via `cmd wifi status`). */
    fun waitForConnectionCmdWifi(ssid: String): Boolean {
        val deadline = System.currentTimeMillis() + CONNECT_TIMEOUT_MS
        val target = ssid.trim('"')
        while (System.currentTimeMillis() < deadline) {
            val res = RootFirewallController.execRoot("$CMD status 2>/dev/null")
            val out = res.stdout
            // Parse SSID dari output
            val ssidMatch = Regex("SSID: \"([^\"]+)\"").find(out)
            val stateMatch = Regex("state: ([A-Z_]+)").find(out)
            val currentSsid = ssidMatch?.groupValues?.getOrNull(1)?.trim('"') ?: ""
            val state = stateMatch?.groupValues?.getOrNull(1) ?: ""
            if (currentSsid == target && (state.contains("COMPLETED") || out.contains("Supplicant state: COMPLETED"))) {
                Thread.sleep(DHCP_SETTLE_MS)
                return true
            }
            try { Thread.sleep(500) } catch (_: InterruptedException) { return false }
        }
        return false
    }

    @Suppress("DEPRECATION")
    private fun waitForConnection(wifiManager: WifiManager, ssid: String): Boolean {
        val deadline = System.currentTimeMillis() + CONNECT_TIMEOUT_MS
        while (System.currentTimeMillis() < deadline) {
            val info = try { wifiManager.connectionInfo } catch (e: Exception) { null }
            if (isConnectedTo(info, ssid)) {
                try { Thread.sleep(DHCP_SETTLE_MS) } catch (_: InterruptedException) {}
                return true
            }
            try { Thread.sleep(500) } catch (_: InterruptedException) { return false }
        }
        return false
    }

    @Suppress("DEPRECATION")
    fun isConnectedTo(info: WifiInfo?, ssid: String): Boolean {
        if (info == null || info.networkId == -1) return false
        val cur = info.ssid?.trim('"') ?: return false
        return cur == ssid && info.supplicantState == android.net.wifi.SupplicantState.COMPLETED
    }

    @Suppress("DEPRECATION")
    private fun cleanupNetwork(wifiManager: WifiManager, netId: Int) {
        try {
            wifiManager.removeNetwork(netId)
            wifiManager.saveConfiguration()
        } catch (_: Exception) {}
    }

    @Suppress("DEPRECATION")
    fun disconnectAll(wifiManager: WifiManager) {
        try { wifiManager.disconnect() } catch (_: Exception) {}
    }

    /** Resolve gateway dari DHCP info (Java API fallback). */
    fun resolveGateway(wifiManager: WifiManager): String? {
        return try {
            val dhcp = wifiManager.dhcpInfo ?: return null
            if (dhcp.gateway == 0) return null
            intToIp(dhcp.gateway)
        } catch (e: Exception) {
            null
        }
    }

    fun intToIp(value: Int): String {
        return (value and 0xFF).toString() + "." +
            ((value shr 8) and 0xFF) + "." +
            ((value shr 16) and 0xFF) + "." +
            ((value shr 24) and 0xFF)
    }
}
