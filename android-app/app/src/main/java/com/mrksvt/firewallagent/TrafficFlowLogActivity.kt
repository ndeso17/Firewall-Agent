package com.mrksvt.firewallagent

import android.os.Bundle
import androidx.appcompat.app.AppCompatActivity
import androidx.lifecycle.lifecycleScope
import com.mrksvt.firewallagent.databinding.ActivityTrafficFlowLogBinding
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.Job
import kotlinx.coroutines.delay
import kotlinx.coroutines.isActive
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext

class TrafficFlowLogActivity : AppCompatActivity() {
    companion object {
        const val EXTRA_UID = "uid"
        const val EXTRA_APP_NAME = "app_name"
        const val EXTRA_APP_PKG = "app_pkg"
        const val EXTRA_DIRECTION = "direction" // download|upload
    }

    private lateinit var binding: ActivityTrafficFlowLogBinding
    private var refreshJob: Job? = null
    private var uid: Int = -1
    private var appName: String = ""
    private var appPkg: String = ""
    private var direction: String = "download"

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        binding = ActivityTrafficFlowLogBinding.inflate(layoutInflater)
        setContentView(binding.root)

        uid = intent.getIntExtra(EXTRA_UID, -1)
        appName = intent.getStringExtra(EXTRA_APP_NAME).orEmpty()
        appPkg = intent.getStringExtra(EXTRA_APP_PKG).orEmpty()
        direction = intent.getStringExtra(EXTRA_DIRECTION)?.lowercase().orEmpty().ifBlank { "download" }

        binding.titleText.text = if (direction == "upload") "Upload Flow Log" else "Download Flow Log"
        binding.appName.text = appName
        binding.appPkg.text = appPkg
        binding.appIcon.setImageDrawable(
            runCatching {
                packageManager.getApplicationIcon(appPkg)
            }.getOrNull(),
        )
    }

    override fun onStart() {
        super.onStart()
        refreshJob?.cancel()
        refreshJob = lifecycleScope.launch {
            while (isActive) {
                refresh()
                delay(1200)
            }
        }
    }

    override fun onStop() {
        refreshJob?.cancel()
        refreshJob = null
        super.onStop()
    }

    private suspend fun refresh() {
        val rows = withContext(Dispatchers.IO) { TrafficEndpointInspector.readUidEndpointDetails(uid) }
        val sorted = if (direction == "upload") rows.sortedByDescending { it.upload } else rows.sortedByDescending { it.download }
        if (sorted.isEmpty()) {
            binding.logText.text = "Belum ada endpoint aktif untuk UID $uid."
            return
        }
        val sb = StringBuilder()
        sorted.take(80).forEachIndexed { idx, row ->
            sb.append("${idx + 1}. src ${toDomain(row.src)} -> dst ${toDomain(row.dst)}\n")
            if (direction == "upload") {
                sb.append("   packet(upload): ${human(row.upload)}\n")
            } else {
                sb.append("   packet(download): ${human(row.download)}\n")
            }
            sb.append("   total(download/upload): ${human(row.download)} / ${human(row.upload)}\n")
        }
        binding.logText.text = sb.toString()
    }

    private fun toDomain(hostPort: String): String {
        val split = hostPort.lastIndexOf(':')
        if (split <= 0 || split >= hostPort.length - 1) return hostPort
        val host = hostPort.substring(0, split)
        val port = hostPort.substring(split + 1)
        val domain = runCatching {
            java.net.InetAddress.getByName(host).canonicalHostName
        }.getOrNull()
        return if (domain.isNullOrBlank() || domain == host) "$host:$port" else "$domain/$host:$port"
    }

    private fun human(v: Long): String {
        if (v < 1024L) return "${v}B"
        val kb = v / 1024.0
        if (kb < 1024.0) return String.format("%.1fKB", kb)
        val mb = kb / 1024.0
        if (mb < 1024.0) return String.format("%.1fMB", mb)
        return String.format("%.2fGB", mb / 1024.0)
    }
}
