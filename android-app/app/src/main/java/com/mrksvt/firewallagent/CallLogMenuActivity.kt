package com.mrksvt.firewallagent

import android.Manifest
import android.os.Bundle
import android.provider.CallLog
import androidx.activity.result.contract.ActivityResultContracts
import androidx.appcompat.app.AppCompatActivity
import androidx.core.content.ContextCompat
import com.mrksvt.firewallagent.databinding.ActivityCallLogMenuBinding
import java.io.File
import java.text.SimpleDateFormat
import java.util.Date
import java.util.Locale

class CallLogMenuActivity : AppCompatActivity() {
    private lateinit var binding: ActivityCallLogMenuBinding

    private val callLogPermLauncher = registerForActivityResult(
        ActivityResultContracts.RequestPermission(),
    ) { granted ->
        if (granted) {
            loadSystemCallLog()
        } else {
            binding.outputText.text = "Izin READ_CALL_LOG ditolak."
        }
    }

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        binding = ActivityCallLogMenuBinding.inflate(layoutInflater)
        setContentView(binding.root)

        binding.loadSystemCallLogBtn.setOnClickListener { ensureCallLogPermissionAndLoad() }
        binding.loadBlockedCallLogBtn.setOnClickListener { loadBlockedCallLog() }
        binding.clearBlockedCallLogBtn.setOnClickListener { clearBlockedCallLog() }

        binding.outputText.text = "Pilih jenis log yang ingin dilihat."
    }

    private fun ensureCallLogPermissionAndLoad() {
        val granted = ContextCompat.checkSelfPermission(this, Manifest.permission.READ_CALL_LOG) ==
            android.content.pm.PackageManager.PERMISSION_GRANTED
        if (granted) {
            loadSystemCallLog()
        } else {
            callLogPermLauncher.launch(Manifest.permission.READ_CALL_LOG)
        }
    }

    private fun loadSystemCallLog() {
        val cursor = contentResolver.query(
            CallLog.Calls.CONTENT_URI,
            arrayOf(
                CallLog.Calls.NUMBER,
                CallLog.Calls.TYPE,
                CallLog.Calls.DATE,
                CallLog.Calls.DURATION,
            ),
            null,
            null,
            "${CallLog.Calls.DATE} DESC",
        )

        val fmt = SimpleDateFormat("yyyy-MM-dd HH:mm:ss", Locale.getDefault())
        val lines = mutableListOf<String>()
        cursor?.use { c ->
            val nIdx = c.getColumnIndex(CallLog.Calls.NUMBER)
            val tIdx = c.getColumnIndex(CallLog.Calls.TYPE)
            val dIdx = c.getColumnIndex(CallLog.Calls.DATE)
            val duIdx = c.getColumnIndex(CallLog.Calls.DURATION)
            var i = 1
            while (c.moveToNext() && i <= 300) {
                val number = if (nIdx >= 0) c.getString(nIdx).orEmpty() else "-"
                val type = if (tIdx >= 0) c.getInt(tIdx) else -1
                val dateMs = if (dIdx >= 0) c.getLong(dIdx) else 0L
                val duration = if (duIdx >= 0) c.getLong(duIdx) else 0L
                lines += "${i}. ${fmt.format(Date(dateMs))} | ${typeLabel(type)} | $number | ${duration}s"
                i++
            }
        }

        binding.outputText.text = if (lines.isEmpty()) {
            "Log telepon sistem kosong/tidak tersedia."
        } else {
            buildString {
                appendLine("Log Telepon Sistem (last ${lines.size})")
                appendLine()
                lines.forEach { appendLine(it) }
            }
        }
    }

    private fun loadBlockedCallLog() {
        val file = File(filesDir, "call_guard_blocked.log")
        if (!file.exists()) {
            binding.outputText.text = "Belum ada log panggilan diblokir."
            return
        }
        val lines = file.readLines().takeLast(500)
        binding.outputText.text = buildString {
            appendLine("Log Panggilan Diblokir (last ${lines.size})")
            appendLine("File: ${file.absolutePath}")
            appendLine()
            lines.forEachIndexed { idx, line -> appendLine("${idx + 1}. $line") }
        }
    }

    private fun clearBlockedCallLog() {
        val file = File(filesDir, "call_guard_blocked.log")
        if (file.exists()) {
            file.writeText("")
        }
        binding.outputText.text = "Log panggilan diblokir dibersihkan."
    }

    private fun typeLabel(type: Int): String {
        return when (type) {
            CallLog.Calls.INCOMING_TYPE -> "IN"
            CallLog.Calls.OUTGOING_TYPE -> "OUT"
            CallLog.Calls.MISSED_TYPE -> "MISSED"
            CallLog.Calls.REJECTED_TYPE -> "REJECTED"
            CallLog.Calls.BLOCKED_TYPE -> "BLOCKED"
            else -> "OTHER($type)"
        }
    }
}
