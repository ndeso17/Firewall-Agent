package com.mrksvt.firewallagent

import android.content.Intent
import android.os.Bundle
import android.os.Build
import androidx.appcompat.app.AppCompatActivity
import androidx.lifecycle.lifecycleScope
import com.mrksvt.firewallagent.databinding.ActivityTorBinding
import java.io.File
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext

class TorActivity : AppCompatActivity() {
    private lateinit var binding: ActivityTorBinding

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        binding = ActivityTorBinding.inflate(layoutInflater)
        setContentView(binding.root)

        binding.openOrbotBtn.setOnClickListener { openOrbot() }
        binding.enableBtn.setOnClickListener { setProxy(true) }
        binding.disableBtn.setOnClickListener { setProxy(false) }
        binding.reloadBtn.setOnClickListener { readStatus() }
        binding.hostInput.setText("127.0.0.1")
        binding.portInput.setText("9050")
        readStatus()
    }

    private fun openOrbot() {
        val i = packageManager.getLaunchIntentForPackage("org.torproject.android")
        if (i != null) {
            startActivity(i)
        } else {
            lifecycleScope.launch {
                val embedded = withContext(Dispatchers.IO) { startEmbeddedTor() }
                binding.outputText.text = if (embedded) {
                    "Orbot tidak ada, Embedded Tor berhasil dijalankan."
                } else {
                    "Orbot belum terpasang dan embedded tor binary belum dibundel.\n" +
                        "Taruh binary di assets: bin/tor/<abi>/tor (mis: arm64-v8a)."
                }
            }
        }
    }

    private fun setProxy(enable: Boolean) {
        lifecycleScope.launch {
            val host = binding.hostInput.text?.toString()?.trim().orEmpty().ifBlank { "127.0.0.1" }
            val port = binding.portInput.text?.toString()?.trim().orEmpty().ifBlank { "9050" }
            val cmd = if (enable) {
                "settings put global http_proxy $host:$port"
            } else {
                "settings put global http_proxy :0"
            }
            val result = withContext(Dispatchers.IO) { RootFirewallController.runRaw(cmd) }
            binding.outputText.text = buildString {
                appendLine(if (enable) "Tor proxy enabled: $host:$port" else "Tor proxy disabled")
                appendLine("exit=${result.code}")
                if (result.stdout.isNotBlank()) appendLine(result.stdout)
                if (result.stderr.isNotBlank()) appendLine(result.stderr)
            }
        }
    }

    private fun readStatus() {
        lifecycleScope.launch {
            val result = withContext(Dispatchers.IO) {
                RootFirewallController.runRaw("settings get global http_proxy; pidof tor")
            }
            binding.outputText.text = buildString {
                appendLine("Current Tor/Proxy status:")
                if (result.stdout.isNotBlank()) appendLine(result.stdout) else appendLine("-")
                if (result.stderr.isNotBlank()) appendLine(result.stderr)
            }
        }
    }

    private fun startEmbeddedTor(): Boolean {
        val abi = Build.SUPPORTED_ABIS.firstOrNull().orEmpty()
        val rel = "bin/tor/$abi/tor"
        val torFile = File(filesDir, "bin/tor")
        torFile.parentFile?.mkdirs()
        val copied = runCatching {
            assets.open(rel).use { input ->
                torFile.outputStream().use { output -> input.copyTo(output) }
            }
            true
        }.getOrElse { false }
        if (!copied) return false

        torFile.setExecutable(true, false)
        val cmd = buildString {
            append("mkdir -p ${filesDir.absolutePath}/tor_data;")
            append("${torFile.absolutePath} --RunAsDaemon 1 --DataDirectory ${filesDir.absolutePath}/tor_data >/dev/null 2>&1;")
            append("pidof tor >/dev/null 2>&1 || pidof ${torFile.name} >/dev/null 2>&1")
        }
        val result = RootFirewallController.runRaw(cmd)
        return result.ok
    }
}
