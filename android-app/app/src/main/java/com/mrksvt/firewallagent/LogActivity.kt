package com.mrksvt.firewallagent

import android.os.Bundle
import android.widget.Toast
import androidx.appcompat.app.AppCompatActivity
import androidx.lifecycle.lifecycleScope
import com.mrksvt.firewallagent.databinding.ActivityLogBinding
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext
import java.io.File
import java.time.Instant

class LogActivity : AppCompatActivity() {
    private lateinit var binding: ActivityLogBinding
    private var rawLog: String = ""

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        binding = ActivityLogBinding.inflate(layoutInflater)
        setContentView(binding.root)

        binding.refreshBtn.setOnClickListener { loadLog() }
        binding.searchInput.addTextChangedListener(SimpleTextWatcher { renderLog() })
        binding.exportBtn.setOnClickListener { exportLog() }
        loadLog()
    }

    private fun loadLog() {
        lifecycleScope.launch {
            val result = withContext(Dispatchers.IO) { RootFirewallController.tailServiceLog(400) }
            rawLog = buildString {
                if (result.stdout.isNotBlank()) append(result.stdout)
                if (result.stderr.isNotBlank()) {
                    if (isNotEmpty()) append('\n')
                    append(result.stderr)
                }
            }.ifBlank { "[log] kosong" }
            renderLog()
        }
    }

    private fun renderLog() {
        val query = binding.searchInput.text?.toString()?.trim()?.lowercase().orEmpty()
        val lines = rawLog.split('\n')
        val filtered = if (query.isBlank()) {
            lines
        } else {
            lines.filter { it.lowercase().contains(query) }
        }
        binding.logText.text = filtered.mapIndexed { index, line ->
            "${index + 1}".padStart(4, ' ') + " | " + line
        }.joinToString("\n")
    }

    private fun exportLog() {
        lifecycleScope.launch(Dispatchers.IO) {
            try {
                val dir = getExternalFilesDir(null) ?: filesDir
                val file = File(dir, "firewall-log-${Instant.now().toString().replace(':', '-')}.txt")
                file.writeText(rawLog.ifBlank { "[log] kosong" })
                withContext(Dispatchers.Main) {
                    Toast.makeText(this@LogActivity, "Log exported: ${file.absolutePath}", Toast.LENGTH_LONG).show()
                }
            } catch (e: Exception) {
                withContext(Dispatchers.Main) {
                    Toast.makeText(this@LogActivity, "Export gagal: ${e.message}", Toast.LENGTH_LONG).show()
                }
            }
        }
    }
}
