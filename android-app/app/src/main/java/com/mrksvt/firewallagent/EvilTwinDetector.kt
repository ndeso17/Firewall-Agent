package com.mrksvt.firewallagent

import android.net.wifi.ScanResult
import android.util.Log
import kotlin.math.abs
import kotlin.math.sqrt

/**
 * Advanced Evil Twin Detection Algorithm
 * 
 * This class implements multiple detection techniques:
 * 1. Signal strength analysis
 * 2. BSSID/SSID correlation analysis  
 * 3. Timing pattern analysis
 * 4. Channel/frequency analysis
 * 5. Cryptographic capability analysis
 * 6. Historical pattern matching
 */
class EvilTwinDetector {
    
    private val tag = "EvilTwinDetector"
    
    // Detection thresholds
    private companion object {
        const val SIGNAL_STABILITY_THRESHOLD = 15 // dBm
        const val RAPID_CHANGE_THRESHOLD = 25 // dBm
        const val SUSPICIOUS_TIMING_THRESHOLD = 30000 // 30 seconds
        const val MAX_SSID_CHANGES = 2
        const val MIN_CONFIDENCE_SCORE = 0.7
        const val PERSISTENCE_THRESHOLD = 3

        fun frequencyToChannel(frequency: Int): Int {
            return when (frequency) {
                in 2412..2484 -> (frequency - 2412) / 5 + 1
                in 5170..5825 -> (frequency - 5170) / 5 + 34
                else -> 0
            }
        }
    }
    
    data class DetectionResult(
        val isEvilTwin: Boolean,
        val confidenceScore: Double,
        val threatLevel: ThreatLevel,
        val reasons: List<String>,
        val recommendations: List<String>
    )
    
    data class NetworkProfile(
        val ssid: String,
        val bssid: String,
        val frequency: Int,
        val capabilities: String,
        val signalStrength: Int,
        val timestamp: Long = System.currentTimeMillis(),
        val channel: Int = frequencyToChannel(frequency)
    )
    
    data class HistoricalData(
        val profiles: MutableList<NetworkProfile> = mutableListOf(),
        var evilTwinCount: Int = 0,
        var lastSeen: Long = System.currentTimeMillis()
    )
    
    // Data storage for historical analysis
    private val networkHistory = mutableMapOf<String, HistoricalData>() // BSSID -> HistoricalData
    private val ssidHistory = mutableMapOf<String, MutableList<NetworkProfile>>() // SSID -> List of profiles
    
    /**
     * Main detection function that analyzes a network for Evil Twin characteristics
     */
    fun detectEvilTwin(scanResult: ScanResult, currentTime: Long = System.currentTimeMillis()): DetectionResult {
        Log.d(tag, "Analyzing network: ${scanResult.SSID} (${scanResult.BSSID})")
        
        val currentProfile = NetworkProfile(
            ssid = scanResult.SSID ?: "Hidden Network",
            bssid = scanResult.BSSID,
            frequency = scanResult.frequency,
            capabilities = scanResult.capabilities,
            signalStrength = scanResult.level,
            timestamp = currentTime
        )
        
        // Update historical data
        updateHistoricalData(currentProfile)
        
        // Perform various detection algorithms
        val signalAnalysis = analyzeSignalPatterns(currentProfile)
        val correlationAnalysis = analyzeCorrelations(currentProfile)
        val timingAnalysis = analyzeTimingPatterns(currentProfile)
        val channelAnalysis = analyzeChannelPatterns(currentProfile)
        val cryptoAnalysis = analyzeCryptographicAnomalies(currentProfile)
        val historicalAnalysis = analyzeHistoricalPatterns(currentProfile)
        
        // Combine all analyses
        val combinedResult = combineAnalyses(
            signalAnalysis,
            correlationAnalysis,
            timingAnalysis,
            channelAnalysis,
            cryptoAnalysis,
            historicalAnalysis
        )
        
        Log.d(tag, "Detection result for ${currentProfile.ssid}: " +
                "isEvilTwin=${combinedResult.isEvilTwin}, " +
                "confidence=${combinedResult.confidenceScore}, " +
                "threatLevel=${combinedResult.threatLevel}")
        
        return combinedResult
    }
    
    /**
     * Analyze signal strength patterns for suspicious changes
     */
    private fun analyzeSignalPatterns(profile: NetworkProfile): DetectionResult {
        val reasons = mutableListOf<String>()
        val recommendations = mutableListOf<String>()
        var confidenceScore = 0.0
        
        val historicalData = networkHistory[profile.bssid] ?: return DetectionResult(
            isEvilTwin = false,
            confidenceScore = 0.0,
            threatLevel = ThreatLevel.LOW,
            reasons = emptyList(),
            recommendations = emptyList()
        )
        
        if (historicalData.profiles.size < 2) {
            return DetectionResult(false, 0.0, ThreatLevel.LOW, emptyList(), emptyList())
        }
        
        val recentProfiles = historicalData.profiles.takeLast(5) // Last 5 measurements
        val avgSignal = recentProfiles.map { it.signalStrength }.average()
        val signalVariance = calculateVariance(recentProfiles.map { it.signalStrength })
        
        // Check for sudden signal changes
        val lastProfile = recentProfiles.last()
        val signalChange = abs(profile.signalStrength - lastProfile.signalStrength)
        
        if (signalChange > RAPID_CHANGE_THRESHOLD) {
            reasons.add("Signal strength changed dramatically by ${signalChange}dBm")
            confidenceScore += 0.3
            recommendations.add("Verify physical location of access point")
        }
        
        // Check for unstable signal patterns
        if (signalVariance > SIGNAL_STABILITY_THRESHOLD) {
            reasons.add("Unstable signal pattern detected (variance: ${signalVariance.toInt()})")
            confidenceScore += 0.2
            recommendations.add("Monitor signal stability over time")
        }
        
        // Check for signal strength inconsistent with distance
        if (profile.signalStrength > -30 && !is5GHzBand(profile.frequency)) {
            reasons.add("Unusually strong signal for 2.4GHz band")
            confidenceScore += 0.15
            recommendations.add("Check if access point is unusually close")
        }
        
        val threatLevel = when {
            confidenceScore > 0.5 -> ThreatLevel.HIGH
            confidenceScore > 0.3 -> ThreatLevel.MEDIUM
            else -> ThreatLevel.LOW
        }
        
        return DetectionResult(
            isEvilTwin = confidenceScore > 0.4,
            confidenceScore = confidenceScore.coerceAtMost(1.0),
            threatLevel = threatLevel,
            reasons = reasons,
            recommendations = recommendations
        )
    }
    
    /**
     * Analyze correlations between SSIDs and BSSIDs
     */
    private fun analyzeCorrelations(profile: NetworkProfile): DetectionResult {
        val reasons = mutableListOf<String>()
        val recommendations = mutableListOf<String>()
        var confidenceScore = 0.0
        
        val sameSsidNetworks = ssidHistory[profile.ssid] ?: return DetectionResult(
            isEvilTwin = false,
            confidenceScore = 0.0,
            threatLevel = ThreatLevel.LOW,
            reasons = emptyList(),
            recommendations = emptyList()
        )
        
        // Check for multiple BSSIDs with same SSID
        val uniqueBssids = sameSsidNetworks.map { it.bssid }.distinct()
        if (uniqueBssids.size > 1) {
            reasons.add("Multiple BSSIDs detected for same SSID: ${uniqueBssids.size} networks")
            confidenceScore += 0.4
            recommendations.add("Verify all access points for this SSID")
            
            // Check if the BSSIDs are very similar (possible spoofing)
            if (areBssidsSimilar(uniqueBssids)) {
                reasons.add("BSSIDs are suspiciously similar (possible spoofing)")
                confidenceScore += 0.3
                recommendations.add("Check MAC address patterns for spoofing")
            }
        }
        
        // Check for sudden appearance of new BSSID
        val existingBssids = sameSsidNetworks.filter { it.bssid != profile.bssid }
        if (existingBssids.isNotEmpty() && !networkHistory.containsKey(profile.bssid)) {
            val newestExisting = existingBssids.maxByOrNull { it.timestamp }
            if (newestExisting != null && (profile.timestamp - newestExisting.timestamp) < SUSPICIOUS_TIMING_THRESHOLD) {
                reasons.add("New BSSID appeared suspiciously quickly")
                confidenceScore += 0.25
                recommendations.add("Investigate timing of new access point appearance")
            }
        }
        
        val threatLevel = when {
            confidenceScore > 0.6 -> ThreatLevel.HIGH
            confidenceScore > 0.3 -> ThreatLevel.MEDIUM
            else -> ThreatLevel.LOW
        }
        
        return DetectionResult(
            isEvilTwin = confidenceScore > 0.5,
            confidenceScore = confidenceScore.coerceAtMost(1.0),
            threatLevel = threatLevel,
            reasons = reasons,
            recommendations = recommendations
        )
    }
    
    /**
     * Analyze timing patterns for suspicious behavior
     */
    private fun analyzeTimingPatterns(profile: NetworkProfile): DetectionResult {
        val reasons = mutableListOf<String>()
        val recommendations = mutableListOf<String>()
        var confidenceScore = 0.0
        
        val historicalData = networkHistory[profile.bssid]
        if (historicalData == null || historicalData.profiles.size < 2) {
            return DetectionResult(false, 0.0, ThreatLevel.LOW, emptyList(), emptyList())
        }
        
        val recentSightings = historicalData.profiles.filter {
            profile.timestamp - it.timestamp < 300000 // Last 5 minutes
        }
        
        // Check for rapid reappearances
        if (recentSightings.size > 3) {
            val avgInterval = calculateAverageInterval(recentSightings)
            if (avgInterval < 10000) { // Less than 10 seconds
                reasons.add("Network reappearing too frequently (avg ${avgInterval/1000}s interval)")
                confidenceScore += 0.35
                recommendations.add("Check for network instability or spoofing")
            }
        }
        
        // Check for disappearance/reappearance pattern
        val timeGaps = calculateTimeGaps(historicalData.profiles)
        val suspiciousGaps = timeGaps.filter { it > 60000 && it < 300000 } // 1-5 minute gaps
        
        if (suspiciousGaps.size >= 2) {
            reasons.add("Suspicious disappearance/reappearance pattern detected")
            confidenceScore += 0.25
            recommendations.add("Monitor for intermittent spoofing behavior")
        }
        
        val threatLevel = when {
            confidenceScore > 0.4 -> ThreatLevel.MEDIUM
            else -> ThreatLevel.LOW
        }
        
        return DetectionResult(
            isEvilTwin = confidenceScore > 0.3,
            confidenceScore = confidenceScore.coerceAtMost(1.0),
            threatLevel = threatLevel,
            reasons = reasons,
            recommendations = recommendations
        )
    }
    
    /**
     * Analyze channel and frequency patterns
     */
    private fun analyzeChannelPatterns(profile: NetworkProfile): DetectionResult {
        val reasons = mutableListOf<String>()
        val recommendations = mutableListOf<String>()
        var confidenceScore = 0.0
        
        val sameChannelNetworks = networkHistory.values.flatMap { it.profiles }
            .filter { frequencyToChannel(it.frequency) == profile.channel }
        
        // Check for channel overcrowding
        if (sameChannelNetworks.size > 10) {
            reasons.add("Channel ${profile.channel} is overcrowded (${sameChannelNetworks.size} networks)")
            confidenceScore += 0.1
            recommendations.add("Consider using less congested channels")
        }
        
        // Check for unusual frequency combinations
        if (profile.frequency in 5000..5999) { // 5GHz band
            val signalStrength = profile.signalStrength
            
            // 5GHz signals should not be extremely strong unless very close
            if (signalStrength > -40) {
                reasons.add("Unusually strong 5GHz signal (${signalStrength}dBm)")
                confidenceScore += 0.2
                recommendations.add("Verify proximity to 5GHz access point")
            }
            
            // Check for DFS channels (radar interference possible)
            if (profile.channel in 52..144) {
                reasons.add("Network using DFS channel ${profile.channel}")
                confidenceScore += 0.05
                recommendations.add("Monitor for radar interference on DFS channels")
            }
        }
        
        val threatLevel = when {
            confidenceScore > 0.25 -> ThreatLevel.MEDIUM
            else -> ThreatLevel.LOW
        }
        
        return DetectionResult(
            isEvilTwin = confidenceScore > 0.2,
            confidenceScore = confidenceScore.coerceAtMost(1.0),
            threatLevel = threatLevel,
            reasons = reasons,
            recommendations = recommendations
        )
    }
    
    /**
     * Analyze cryptographic capabilities for downgrades
     */
    private fun analyzeCryptographicAnomalies(profile: NetworkProfile): DetectionResult {
        val reasons = mutableListOf<String>()
        val recommendations = mutableListOf<String>()
        var confidenceScore = 0.0
        
        val capabilities = profile.capabilities
        
        // Check for security downgrades
        val historicalData = networkHistory[profile.bssid]
        if (historicalData != null && historicalData.profiles.isNotEmpty()) {
            val previousCapabilities = historicalData.profiles.last().capabilities
            
            if (isSecurityDowngrade(previousCapabilities, capabilities)) {
                reasons.add("Security downgrade detected: $previousCapabilities → $capabilities")
                confidenceScore += 0.5 // High confidence for security downgrades
                recommendations.add("DO NOT CONNECT - Security has been downgraded")
            }
        }
        
        // Check for open networks that should be secured
        if (capabilities.contains("[OPEN]")) {
            val ssid = profile.ssid.lowercase()
            val secureKeywords = listOf("corp", "office", "secure", "company", "business", "enterprise", "vpn")
            
            val shouldBeSecure = secureKeywords.any { keyword ->
                ssid.contains(keyword)
            }
            
            if (shouldBeSecure) {
                reasons.add("Network named '$profile.ssid' should be secured but is open")
                confidenceScore += 0.3
                recommendations.add("Verify legitimacy of open corporate network")
            }
        }
        
        // Check for weak encryption
        if (capabilities.contains("WEP") || capabilities.contains("TKIP")) {
            reasons.add("Weak encryption detected: $capabilities")
            confidenceScore += 0.2
            recommendations.add("Avoid networks with weak encryption")
        }
        
        val threatLevel = when {
            confidenceScore > 0.4 -> ThreatLevel.HIGH
            confidenceScore > 0.2 -> ThreatLevel.MEDIUM
            else -> ThreatLevel.LOW
        }
        
        return DetectionResult(
            isEvilTwin = confidenceScore > 0.3,
            confidenceScore = confidenceScore.coerceAtMost(1.0),
            threatLevel = threatLevel,
            reasons = reasons,
            recommendations = recommendations
        )
    }
    
    /**
     * Analyze historical patterns for this network
     */
    private fun analyzeHistoricalPatterns(profile: NetworkProfile): DetectionResult {
        val reasons = mutableListOf<String>()
        val recommendations = mutableListOf<String>()
        var confidenceScore = 0.0
        
        val historicalData = networkHistory[profile.bssid] ?: return DetectionResult(
            isEvilTwin = false,
            confidenceScore = 0.0,
            threatLevel = ThreatLevel.LOW,
            reasons = emptyList(),
            recommendations = emptyList()
        )
        
        // Check for persistent evil twin detection
        if (historicalData.evilTwinCount >= PERSISTENCE_THRESHOLD) {
            reasons.add("Network has been flagged as Evil Twin ${historicalData.evilTwinCount} times")
            confidenceScore += 0.4
            recommendations.add("Avoid this network - persistent threat")
        }
        
        // Check for SSID changes over time
        val uniqueSsids = historicalData.profiles.map { it.ssid }.distinct()
        if (uniqueSsids.size > MAX_SSID_CHANGES) {
            reasons.add("SSID has changed ${uniqueSsids.size} times: ${uniqueSsids.joinToString(", ")}")
            confidenceScore += 0.3
            recommendations.add("SSID instability indicates possible spoofing")
        }
        
        // Check for abnormal frequency of appearance
        val avgTimeBetweenSightings = calculateAverageTimeBetweenSightings(historicalData.profiles)
        if (avgTimeBetweenSightings < 60000) { // Less than 1 minute average
            reasons.add("Network appears too frequently (avg ${avgTimeBetweenSightings/1000}s)")
            confidenceScore += 0.25
            recommendations.add("Possible automated spoofing attack")
        }
        
        val threatLevel = when {
            confidenceScore > 0.5 -> ThreatLevel.HIGH
            confidenceScore > 0.25 -> ThreatLevel.MEDIUM
            else -> ThreatLevel.LOW
        }
        
        return DetectionResult(
            isEvilTwin = confidenceScore > 0.3,
            confidenceScore = confidenceScore.coerceAtMost(1.0),
            threatLevel = threatLevel,
            reasons = reasons,
            recommendations = recommendations
        )
    }
    
    /**
     * Combine all analysis results into final decision
     */
    private fun combineAnalyses(
        signalAnalysis: DetectionResult,
        correlationAnalysis: DetectionResult,
        timingAnalysis: DetectionResult,
        channelAnalysis: DetectionResult,
        cryptoAnalysis: DetectionResult,
        historicalAnalysis: DetectionResult
    ): DetectionResult {
        
        val allReasons = mutableListOf<String>()
        val allRecommendations = mutableListOf<String>()
        var totalConfidence = 0.0
        var highThreatCount = 0
        var mediumThreatCount = 0
        
        val analyses = listOf(
            signalAnalysis,
            correlationAnalysis,
            timingAnalysis,
            channelAnalysis,
            cryptoAnalysis,
            historicalAnalysis
        )
        
        analyses.forEach { analysis ->
            if (analysis.confidenceScore > 0) {
                allReasons.addAll(analysis.reasons)
                allRecommendations.addAll(analysis.recommendations)
                totalConfidence += analysis.confidenceScore
                
                when (analysis.threatLevel) {
                    ThreatLevel.HIGH, ThreatLevel.CRITICAL -> highThreatCount++
                    ThreatLevel.MEDIUM -> mediumThreatCount++
                    else -> {}
                }
            }
        }
        
        // Weighted confidence calculation
        val weightedConfidence = when {
            cryptoAnalysis.confidenceScore > 0.4 -> totalConfidence * 1.5 // Security downgrades are critical
            highThreatCount >= 2 -> totalConfidence * 1.3 // Multiple high threats increase risk
            else -> totalConfidence
        }
        
        val finalConfidence = (weightedConfidence / analyses.size).coerceAtMost(1.0)
        
        val finalThreatLevel = when {
            finalConfidence > 0.8 || highThreatCount >= 3 -> ThreatLevel.CRITICAL
            finalConfidence > 0.6 || highThreatCount >= 2 -> ThreatLevel.HIGH
            finalConfidence > 0.4 || mediumThreatCount >= 2 -> ThreatLevel.MEDIUM
            else -> ThreatLevel.LOW
        }
        
        val isEvilTwin = finalConfidence > MIN_CONFIDENCE_SCORE
        
        // Add critical warning for security downgrades
        if (cryptoAnalysis.confidenceScore > 0.4) {
            allReasons.add(0, "🚨 SECURITY DOWNGRADE DETECTED - IMMEDIATE THREAT")
            allRecommendations.add(0, "⚠️ DO NOT CONNECT TO THIS NETWORK")
        }
        
        return DetectionResult(
            isEvilTwin = isEvilTwin,
            confidenceScore = finalConfidence,
            threatLevel = finalThreatLevel,
            reasons = allReasons.distinct(),
            recommendations = allRecommendations.distinct()
        )
    }
    
    /**
     * Update historical data with new network profile
     */
    private fun updateHistoricalData(profile: NetworkProfile) {
        // Update BSSID-based history
        val historicalData = networkHistory.getOrPut(profile.bssid) { HistoricalData() }
        historicalData.profiles.add(profile)
        historicalData.lastSeen = profile.timestamp
        
        // Keep only last 100 profiles to prevent memory issues
        if (historicalData.profiles.size > 100) {
            historicalData.profiles.removeAt(0)
        }
        
        // Update SSID-based history
        val ssidProfiles = ssidHistory.getOrPut(profile.ssid) { mutableListOf() }
        ssidProfiles.add(profile)
        
        // Keep only last 50 profiles per SSID
        if (ssidProfiles.size > 50) {
            ssidProfiles.removeAt(0)
        }
    }
    
    // Helper functions
    
    private fun is5GHzBand(frequency: Int): Boolean = frequency in 5000..5999
    
    private fun calculateVariance(values: List<Int>): Double {
        if (values.size < 2) return 0.0
        val mean = values.average()
        return values.map { (it - mean) * (it - mean) }.average()
    }
    
    private fun areBssidsSimilar(bssids: List<String>): Boolean {
        if (bssids.size < 2) return false
        
        // Check if BSSIDs differ by only a few characters
        val reference = bssids.first()
        return bssids.drop(1).all { bssid ->
            var differences = 0
            for (i in reference.indices) {
                if (reference[i] != bssid[i]) differences++
            }
            differences <= 2 // Allow max 2 character differences
        }
    }
    
    private fun calculateAverageInterval(profiles: List<NetworkProfile>): Long {
        if (profiles.size < 2) return 0
        
        val sortedProfiles = profiles.sortedBy { it.timestamp }
        val intervals = mutableListOf<Long>()
        
        for (i in 1 until sortedProfiles.size) {
            intervals.add(sortedProfiles[i].timestamp - sortedProfiles[i-1].timestamp)
        }
        
        return if (intervals.isNotEmpty()) intervals.average().toLong() else 0
    }
    
    private fun calculateTimeGaps(profiles: List<NetworkProfile>): List<Long> {
        if (profiles.size < 2) return emptyList()
        
        val sortedProfiles = profiles.sortedBy { it.timestamp }
        val gaps = mutableListOf<Long>()
        
        for (i in 1 until sortedProfiles.size) {
            gaps.add(sortedProfiles[i].timestamp - sortedProfiles[i-1].timestamp)
        }
        
        return gaps
    }
    
    private fun isSecurityDowngrade(previous: String, current: String): Boolean {
        val securityLevels = mapOf(
            "WPA3" to 4,
            "WPA2" to 3,
            "WPA" to 2,
            "WEP" to 1,
            "OPEN" to 0
        )
        
        val prevLevel = securityLevels.entries.find { previous.contains(it.key) }?.value ?: 0
        val currLevel = securityLevels.entries.find { current.contains(it.key) }?.value ?: 0
        
        return currLevel < prevLevel
    }
    
    private fun calculateAverageTimeBetweenSightings(profiles: List<NetworkProfile>): Long {
        if (profiles.size < 2) return Long.MAX_VALUE
        
        val sortedTimestamps = profiles.map { it.timestamp }.sorted()
        val intervals = mutableListOf<Long>()
        
        for (i in 1 until sortedTimestamps.size) {
            intervals.add(sortedTimestamps[i] - sortedTimestamps[i-1])
        }
        
        return if (intervals.isNotEmpty()) intervals.average().toLong() else Long.MAX_VALUE
    }
}
