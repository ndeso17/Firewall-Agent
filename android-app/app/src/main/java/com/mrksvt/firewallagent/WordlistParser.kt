package com.mrksvt.firewallagent

import android.content.Context
import java.io.BufferedReader
import java.io.InputStreamReader

/**
 * Parser wordlist kredensial router.
 * Mendukung:
 *  - .txt  : satu `user:pass` per baris, komentar `#` di-skip
 *  - .md   : extract dari code block ``` ... ``` atau bullet list
 *  - format line: `user:pass`, `user=pass`, `user / pass`, `user pass`
 */
object WordlistParser {

    data class Credential(val username: String, val password: String)

    /** Load bundled wordlist dari assets. */
    fun loadBundled(context: Context): List<Credential> {
        return try {
            val stream = context.assets.open("wordlist/router_creds.txt")
            val reader = BufferedReader(InputStreamReader(stream))
            parseText(reader.readText())
        } catch (e: Exception) {
            emptyList()
        }
    }

    /** Load bundled password WiFi (satu password per baris, tanpa username). */
    fun loadBundledWifiPasswords(context: Context): List<String> {
        return try {
            val stream = context.assets.open("wordlist/wifi_passwords.txt")
            val reader = BufferedReader(InputStreamReader(stream))
            parsePlainPasswords(reader.readText())
        } catch (e: Exception) {
            emptyList()
        }
    }

    /** Load custom wordlist dari file (txt atau md). */
    fun loadFromFile(context: Context, uri: android.net.Uri): List<Credential> {
        return try {
            val stream = context.contentResolver.openInputStream(uri)
                ?: return emptyList()
            val reader = BufferedReader(InputStreamReader(stream))
            parseText(reader.readText())
        } catch (e: Exception) {
            emptyList()
        }
    }

    /** Load custom password WiFi polos dari file (txt/md). */
    fun loadWifiPasswordsFromFile(context: Context, uri: android.net.Uri): List<String> {
        return try {
            val stream = context.contentResolver.openInputStream(uri)
                ?: return emptyList()
            val reader = BufferedReader(InputStreamReader(stream))
            parsePlainPasswords(reader.readText())
        } catch (e: Exception) {
            emptyList()
        }
    }

    /** Parse daftar password polos: satu per baris, komentar di-skip, extract dari code block md. */
    fun parsePlainPasswords(text: String): List<String> {
        val lines = text.lines()
        val isMarkdown = text.contains("```") || lines.any { it.trimStart().startsWith("- ") }
        val extracted = if (isMarkdown) extractFromMarkdown(lines) else lines
        return extracted
            .mapNotNull { raw ->
                val line = raw.trim()
                when {
                    line.isEmpty() -> null
                    line.startsWith("#") || line.startsWith("//") -> null
                    // Format "user:pass" di file password → ambil bagian password
                    line.contains(":") -> {
                        val idx = line.indexOf(':')
                        line.substring(idx + 1).trim().ifBlank { null }
                    }
                    else -> line.trim('"', '\'')
                }
            }
            .filter { it.isNotBlank() }
            .distinct()
    }

    /** Parse text mentah; auto-detect txt/md (markdown punya code block / bullet). */
    fun parseText(text: String): List<Credential> {
        val lines = text.lines()
        val isMarkdown = text.contains("```") || lines.any { it.trimStart().startsWith("- ") }

        val extracted = if (isMarkdown) {
            extractFromMarkdown(lines)
        } else {
            lines
        }

        return extracted
            .mapNotNull { parseLine(it) }
            .distinctBy { "${it.username.lowercase()}:${it.password}" }
    }

    private fun extractFromMarkdown(lines: List<String>): List<String> {
        val result = mutableListOf<String>()
        var inCodeBlock = false
        for (line in lines) {
            val trimmed = line.trim()
            when {
                trimmed.startsWith("```") -> { inCodeBlock = !inCodeBlock }
                inCodeBlock && trimmed.isNotBlank() && !trimmed.startsWith("#") -> result.add(trimmed)
                !inCodeBlock && trimmed.startsWith("- ") -> result.add(trimmed.removePrefix("- ").trim())
                !inCodeBlock && trimmed.startsWith("* ") -> result.add(trimmed.removePrefix("* ").trim())
            }
        }
        return result
    }

    private fun parseLine(raw: String): Credential? {
        val line = raw.trim()
        if (line.isEmpty()) return null
        if (line.startsWith("#") || line.startsWith("//")) return null

        // Format: user:pass | user=pass | user / pass | user pass (whitespace)
        val parts = when {
            line.contains(":") -> line.split(":", limit = 2)
            line.contains("=") -> line.split("=", limit = 2)
            line.contains("/") -> line.split("/", limit = 2)
            line.contains(Regex("\\s{2,}")) -> line.split(Regex("\\s{2,}"), limit = 2)
            line.contains(Regex("\\s+")) -> line.split(Regex("\\s+"), limit = 2)
            else -> listOf(line)
        }
        if (parts.size < 2) return null

        val user = parts[0].trim()
        val pass = parts[1].trim().trim('"', '\'')
        if (user.isEmpty() || pass.isEmpty()) return null

        return Credential(user, pass)
    }
}
