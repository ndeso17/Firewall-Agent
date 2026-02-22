package com.mrksvt.firewallagent

import android.content.BroadcastReceiver
import android.content.Context
import android.content.Intent
import android.net.wifi.ScanResult
import android.net.wifi.WifiManager
import android.os.Build
import android.util.Log
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.launch
import java.util.concurrent.ConcurrentHashMap

class EvilTwinReceiver : BroadcastReceiver() {
    
    private val tag = "EvilTwinReceiver"
    private val receiverScope = CoroutineScope(SupervisorJob() + Dispatchers.IO)
    
    // Cache untuk tracking perubahan jaringan
    private val networkCache = ConcurrentHashMap<String, NetworkInfo>()
    private val threatPatterns = ConcurrentHashMap<String, ThreatPattern>()
    
    data class NetworkInfo(
        val ssid: String,
        val bssid: String,
        val level: Int,
        val frequency: Int,
        val capabilities: String,
        val timestamp: Long = System.currentTimeMillis()
    )
    
    data class ThreatPattern(
        var detectionCount: Int = 0,
        var lastSeen: Long = System.currentTimeMillis(),
        var reasons: MutableList<String> = mutableListOf()
    )
    
    override fun onReceive(context: Context, intent: Intent) {
        when (intent.action) {
            WifiManager.SCAN_RESULTS_AVAILABLE_ACTION -> {
                handleScanResults(context)
            }
            WifiManager.NETWORK_STATE_CHANGED_ACTION -> {
                handleNetworkStateChanged(context, intent)
            }
            WifiManager.WIFI_STATE_CHANGED_ACTION -> {
                handleWifiStateChanged(context, intent)
            }
        }
    }
    
    private fun handleScanResults(context: Context) {
        receiverScope.launch {
            try {
                val wifiManager = context.applicationContext.getSystemService(Context.WIFI_SERVICE) as WifiManager
                val scanResults = wifiManager.scanResults
                
                Log.d(tag, "Processing ${scanResults.size} scan results for Evil Twin detection")
                
                val threats = mutableListOf<EvilTwinNetwork>()
                val currentNetworks = mutableMapOf<String, NetworkInfo>()
                
                // Process each network
                for (result in scanResults) {
                    val networkInfo = NetworkInfo(
                        ssid = result.SSID ?: "Hidden Network",
                        bssid = result.BSSID,
                        level = result.level,
                        frequency = result.frequency,
                        capabilities = result.capabilities
                    )
                    
                    currentNetworks[result.BSSID] = networkInfo
                    
                    // Check for Evil Twin indicators
                    val evilTwinNetwork = analyzeForEvilTwin(networkInfo)
                    if (evilTwinNetwork.isSuspicious) {
                        threats.add(evilTwinNetwork)
                    }
                }
                
                // Update cache
                updateNetworkCache(currentNetworks)
                
                // Handle threats
                if (threats.isNotEmpty()) {
                    handleThreats(context, threats)
                }
                
                // Cleanup old entries
                cleanupOldEntries()
                
            } catch (e: SecurityException) {
                Log.e(tag, "Security exception accessing WiFi scan results", e)
            } catch (e: Exception) {
                Log.e(tag, "Error processing scan results", e)
            }
        }
    }
    
    private fun analyzeForEvilTwin(networkInfo: NetworkInfo): EvilTwinNetwork {
        val suspicions = mutableListOf<String>()
        var threatLevel = ThreatLevel.LOW
        
        // Check 1: Sudden appearance of duplicate SSIDs
        val cachedNetwork = networkCache[networkInfo.bssid]
        if (cachedNetwork != null) {
            // Check for sudden signal strength changes
            val levelDiff = kotlin.math.abs(networkInfo.level - cachedNetwork.level)
            if (levelDiff > 25) {
                suspicions.add("Signal strength changed dramatically by ${levelDiff}dBm")
                threatLevel = ThreatLevel.MEDIUM
            }
            
            // Check for SSID changes on same BSSID
            if (networkInfo.ssid != cachedNetwork.ssid) {
                suspicions.add("SSID changed from '${cachedNetwork.ssid}' to '${networkInfo.ssid}'")
                threatLevel = ThreatLevel.HIGH
            }
        }
        
        // Check 2: Multiple networks with same SSID but different BSSIDs
        val sameSsidNetworks = networkCache.values.filter { it.ssid == networkInfo.ssid && it.bssid != networkInfo.bssid }
        if (sameSsidNetworks.isNotEmpty()) {
            val recentSameSsid = sameSsidNetworks.filter { 
                System.currentTimeMillis() - it.timestamp < 300000 // Within 5 minutes
            }
            
            if (recentSameSsid.isNotEmpty()) {
                suspicions.add("Multiple APs with same SSID detected: ${recentSameSsid.size} networks")
                threatLevel = ThreatLevel.HIGH
            }
        }
        
        // Check 3: Suspicious timing patterns
        val patternKey = "${networkInfo.ssid}_${networkInfo.bssid}"
        val existingPattern = threatPatterns[patternKey]
        
        if (existingPattern != null) {
            val timeSinceLastSeen = System.currentTimeMillis() - existingPattern.lastSeen
            
            // Rapid reappearance could indicate spoofing
            if (timeSinceLastSeen < 60000) { // Less than 1 minute
                existingPattern.detectionCount++
                suspicions.add("Rapid reappearance (${timeSinceLastSeen/1000}s)")
                threatLevel = ThreatLevel.HIGH
            }
            
            existingPattern.lastSeen = System.currentTimeMillis()
        } else {
            threatPatterns[patternKey] = ThreatPattern(
                detectionCount = 1,
                lastSeen = System.currentTimeMillis(),
                reasons = suspicions
            )
        }
        
        // Check 4: Unusual signal strength for frequency band
        if (networkInfo.frequency > 5000 && networkInfo.level > -30) {
            suspicions.add("Unusually strong 5GHz signal")
            threatLevel = ThreatLevel.MEDIUM
        }
        
        // Check 5: Open network that should be secured
        if (networkInfo.capabilities.contains("[OPEN]") && networkInfo.ssid.isNotEmpty()) {
            val secureKeywords = listOf("corp", "office", "secure", "company", "business", "enterprise")
            val shouldBeSecure = secureKeywords.any { keyword ->
                networkInfo.ssid.contains(keyword, ignoreCase = true)
            }
            
            if (shouldBeSecure) {
                suspicions.add("Corporate network is open (no encryption)")
                threatLevel = ThreatLevel.HIGH
            }
        }
        
        // Upgrade threat level based on pattern history
        if (existingPattern != null && existingPattern.detectionCount >= 3) {
            threatLevel = ThreatLevel.CRITICAL
            suspicions.add("Persistent threat pattern detected")
        }
        
        return EvilTwinNetwork(
            ssid = networkInfo.ssid,
            bssid = networkInfo.bssid,
            capabilities = networkInfo.capabilities,
            level = networkInfo.level,
            frequency = networkInfo.frequency,
            timestamp = networkInfo.timestamp,
            isSuspicious = suspicions.isNotEmpty(),
            threatLevel = threatLevel,
            reason = suspicions.joinToString("; ")
        )
    }
    
    private fun updateNetworkCache(currentNetworks: Map<String, NetworkInfo>) {
        // Update cache with current networks
        networkCache.putAll(currentNetworks)
        
        // Remove networks that are no longer visible
        val currentBssids = currentNetworks.keys
        val toRemove = networkCache.keys.filter { it !in currentBssids }
        toRemove.forEach { networkCache.remove(it) }
    }
    
    private fun handleThreats(context: Context, threats: List<EvilTwinNetwork>) {
        val criticalThreats = threats.filter { it.threatLevel == ThreatLevel.CRITICAL }
        val highThreats = threats.filter { it.threatLevel == ThreatLevel.HIGH }
        
        Log.w(tag, "Detected ${threats.size} Evil Twin threats (${criticalThreats.size} critical, ${highThreats.size} high)")
        
        // Handle critical threats immediately
        if (criticalThreats.isNotEmpty()) {
            handleCriticalThreats(context, criticalThreats)
        }
        
        // Handle high priority threats
        if (highThreats.isNotEmpty()) {
            handleHighThreats(context, highThreats)
        }
        
        // Update threat history
        threats.forEach { threat ->
            val serviceIntent = Intent(context, EvilTwinDetectionService::class.java)
            serviceIntent.action = "RECORD_THREAT"
            serviceIntent.putExtra("BSSID", threat.bssid)
            
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
                context.startForegroundService(serviceIntent)
            } else {
                context.startService(serviceIntent)
            }
        }
    }
    
    private fun handleCriticalThreats(context: Context, threats: List<EvilTwinNetwork>) {
        val threatDetails = buildString {
            appendLine("🚨 CRITICAL EVIL TWIN ATTACK DETECTED!")
            appendLine()
            threats.forEach { threat ->
                appendLine("Network: ${threat.ssid}")
                appendLine("BSSID: ${threat.bssid}")
                appendLine("Reason: ${threat.reason}")
                appendLine()
            }
            appendLine("RECOMMENDATION: Disconnect from WiFi immediately")
        }
        
        Log.e(tag, "CRITICAL THREAT: $threatDetails")
        
        // Send notification via service
        val serviceIntent = Intent(context, EvilTwinDetectionService::class.java)
        serviceIntent.action = "SEND_THREAT_NOTIFICATION"
        serviceIntent.putExtra("THREAT_DETAILS", threatDetails)
        
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
            context.startForegroundService(serviceIntent)
        } else {
            context.startService(serviceIntent)
        }
    }
    
    private fun handleHighThreats(context: Context, threats: List<EvilTwinNetwork>) {
        val threatSummary = buildString {
            appendLine("⚠️ High Priority Evil Twin Threats Detected:")
            threats.forEach { threat ->
                appendLine("• ${threat.ssid}: ${threat.reason}")
            }
        }
        
        Log.w(tag, "HIGH THREAT: $threatSummary")
        
        // Update service notification
        val serviceIntent = Intent(context, EvilTwinDetectionService::class.java)
        serviceIntent.action = "UPDATE_NOTIFICATION"
        serviceIntent.putExtra("NOTIFICATION_CONTENT", "High priority threats detected: ${threats.size} networks")
        
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
            context.startForegroundService(serviceIntent)
        } else {
            context.startService(serviceIntent)
        }
    }
    
    private fun handleNetworkStateChanged(context: Context, intent: Intent) {
        Log.d(tag, "Network state changed")
        // Additional network state monitoring can be implemented here
    }
    
    private fun handleWifiStateChanged(context: Context, intent: Intent) {
        val wifiState = intent.getIntExtra(WifiManager.EXTRA_WIFI_STATE, WifiManager.WIFI_STATE_UNKNOWN)
        Log.d(tag, "WiFi state changed to: $wifiState")
        
        when (wifiState) {
            WifiManager.WIFI_STATE_ENABLED -> {
                Log.d(tag, "WiFi enabled, starting monitoring")
                // WiFi just turned on, give it time to stabilize
                android.os.Handler(android.os.Looper.getMainLooper()).postDelayed({
                    performImmediateScan(context)
                }, 5000) // Wait 5 seconds
            }
            WifiManager.WIFI_STATE_DISABLED -> {
                Log.d(tag, "WiFi disabled, clearing cache")
                networkCache.clear()
                threatPatterns.clear()
            }
        }
    }
    
    private fun performImmediateScan(context: Context) {
        receiverScope.launch {
            try {
                val wifiManager = context.applicationContext.getSystemService(Context.WIFI_SERVICE) as WifiManager
                wifiManager.startScan()
            } catch (e: Exception) {
                Log.e(tag, "Error performing immediate scan", e)
            }
        }
    }
    
    private fun cleanupOldEntries() {
        val currentTime = System.currentTimeMillis()
        val fiveMinutesAgo = currentTime - 300000
        
        // Remove old network cache entries
        val oldNetworkEntries = networkCache.filter { it.value.timestamp < fiveMinutesAgo }
        oldNetworkEntries.forEach { (bssid, _) ->
            networkCache.remove(bssid)
        }
        
        // Remove old threat patterns
        val oldThreatPatterns = threatPatterns.filter { it.value.lastSeen < fiveMinutesAgo }
        oldThreatPatterns.forEach { (key, _) ->
            threatPatterns.remove(key)
        }
        
        if (oldNetworkEntries.isNotEmpty() || oldThreatPatterns.isNotEmpty()) {
            Log.d(tag, "Cleaned up ${oldNetworkEntries.size} old networks and ${oldThreatPatterns.size} old threat patterns")
        }
    }
}
