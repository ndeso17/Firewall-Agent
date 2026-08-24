package com.mrksvt.firewallagent

import android.net.wifi.ScanResult

/**
 * Klasifikasi keamanan jaringan Wi-Fi dari beacon (ScanResult.capabilities).
 * Mirip penanda "Keamanan lemah/kuat" di Android, plus cek PMF (802.11w).
 *
 * Data murni dari apa yang AP iklankan di beacon — AP bisa bohong (relevan ke Evil Twin).
 */
object NetworkSecurityClassifier {

    enum class SecurityLevel(val label: String, val score: Int) {
        OPEN("Open", 0),
        WEP("WEP", 1),
        WPA_TKIP("WPA/WPA2-TKIP", 2),
        WPA2("WPA2-CCMP", 3),
        WPA3("WPA3-SAE", 4),
        OWE("OWE", 4),
    }

    data class Classification(
        val level: SecurityLevel,
        val isWeak: Boolean,
        val hasPmf: Boolean,
        val rawCapabilities: String,
    )

    private val PMF_RE = Regex("""\[MFP\|CCMP\]|\[MFP\|SAE\]|\[WPA2-PMF\]|\[WPA3-PMF\]|MFP|PMF|802.11w""", RegexOption.IGNORE_CASE)

    /** Klasifikasi satu ScanResult. */
    fun classify(result: ScanResult): Classification {
        val caps = result.capabilities ?: ""
        return classifyCapabilities(caps)
    }

    fun classifyCapabilities(caps: String): Classification {
        val level = when {
            caps.contains("[OPEN]") -> SecurityLevel.OPEN
            caps.contains("WEP") -> SecurityLevel.WEP
            caps.contains("WPA3") || caps.contains("SAE") -> SecurityLevel.WPA3
            caps.contains("OWE") -> SecurityLevel.OWE
            caps.contains("WPA2") && caps.contains("TKIP") && !caps.contains("CCMP") -> SecurityLevel.WPA_TKIP
            caps.contains("WPA2") || caps.contains("WPA") -> SecurityLevel.WPA2
            else -> SecurityLevel.OPEN
        }
        val hasPmf = PMF_RE.containsMatchIn(caps)
        // Tanpa PMF (802.11w) = rentan deauth/Evil Twin → masuk kategori lemah
        val isWeak = level in listOf(SecurityLevel.OPEN, SecurityLevel.WEP, SecurityLevel.WPA_TKIP) || !hasPmf
        return Classification(level, isWeak, hasPmf, caps)
    }
}
