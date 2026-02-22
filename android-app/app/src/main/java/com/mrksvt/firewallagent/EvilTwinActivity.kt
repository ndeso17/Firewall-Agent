package com.mrksvt.firewallagent

import android.Manifest
import android.content.BroadcastReceiver
import android.content.Context
import android.content.Intent
import android.content.IntentFilter
import android.content.pm.PackageManager
import android.net.wifi.ScanResult
import android.net.wifi.WifiManager
import android.os.Build
import android.os.Bundle
import android.view.Menu
import android.view.MenuItem
import android.widget.Toast
import androidx.appcompat.app.AppCompatActivity
import androidx.core.app.ActivityCompat
import androidx.core.content.ContextCompat
import androidx.recyclerview.widget.LinearLayoutManager
import com.mrksvt.firewallagent.databinding.ActivityEvilTwinBinding
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.Job
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.cancel
import kotlinx.coroutines.delay
import kotlinx.coroutines.isActive
import kotlinx.coroutines.launch
import java.text.SimpleDateFormat
import java.util.Date
import java.util.Locale

class EvilTwinActivity : AppCompatActivity() {

    private lateinit var binding: ActivityEvilTwinBinding
    private lateinit var wifiManager: WifiManager
    private lateinit var adapter: EvilTwinAdapter

    private val scannedNetworks = mutableListOf<EvilTwinNetwork>()
    private val scanResults = mutableListOf<ScanResult>()
    private var isScanning = false
    private val evilTwinDetector = EvilTwinDetector()

    private var scanJob: Job? = null
    private val activityScope = CoroutineScope(Dispatchers.Main + SupervisorJob())

    private val wifiScanReceiver = object : BroadcastReceiver() {
        override fun onReceive(context: Context, intent: Intent) {
            if (intent.action == WifiManager.SCAN_RESULTS_AVAILABLE_ACTION) {
                if (ActivityCompat.checkSelfPermission(context, Manifest.permission.ACCESS_FINE_LOCATION) == PackageManager.PERMISSION_GRANTED) {
                    processScanResults(wifiManager.scanResults)
                }
            }
        }
    }

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        binding = ActivityEvilTwinBinding.inflate(layoutInflater)
        setContentView(binding.root)

        setSupportActionBar(binding.toolbar)
        supportActionBar?.setDisplayHomeAsUpEnabled(true)
        supportActionBar?.title = getString(R.string.evil_twin_title)

        wifiManager = applicationContext.getSystemService(Context.WIFI_SERVICE) as WifiManager

        setupRecyclerView()
        setupButtons()
        checkPermissions()
        updateBackgroundMonitorButton(isServiceRunning())
    }

    private fun setupRecyclerView() {
        adapter = EvilTwinAdapter(scannedNetworks) { network ->
            showNetworkDetails(network)
        }

        binding.recyclerView.apply {
            layoutManager = LinearLayoutManager(this@EvilTwinActivity)
            adapter = this@EvilTwinActivity.adapter
        }
    }

    private fun setupButtons() {
        binding.btnStartScan.setOnClickListener {
            toggleScanning()
        }

        binding.btnClearResults.setOnClickListener {
            clearResults()
        }

        binding.btnSaveReport.setOnClickListener {
            saveReport()
        }

        binding.btnBackgroundMonitor.setOnClickListener {
            toggleBackgroundMonitoring()
        }
    }

    private fun toggleBackgroundMonitoring() {
        if (isServiceRunning()) {
            stopBackgroundMonitoring()
        } else {
            startBackgroundMonitoring()
        }
    }

    private fun isServiceRunning(): Boolean {
        val manager = getSystemService(Context.ACTIVITY_SERVICE) as android.app.ActivityManager
        return manager.getRunningServices(Integer.MAX_VALUE).any {
            it.service.className == EvilTwinDetectionService::class.java.name
        }
    }

    private fun startBackgroundMonitoring() {
        try {
            EvilTwinDetectionService.startService(this)
            updateBackgroundMonitorButton(true)
            Toast.makeText(this, "Background monitoring started", Toast.LENGTH_SHORT).show()
        } catch (e: Exception) {
            Toast.makeText(this, "Failed to start monitoring: ${e.message}", Toast.LENGTH_SHORT).show()
        }
    }

    private fun stopBackgroundMonitoring() {
        try {
            EvilTwinDetectionService.stopService(this)
            updateBackgroundMonitorButton(false)
            Toast.makeText(this, "Background monitoring stopped", Toast.LENGTH_SHORT).show()
        } catch (e: Exception) {
            Toast.makeText(this, "Failed to stop monitoring: ${e.message}", Toast.LENGTH_SHORT).show()
        }
    }

    private fun updateBackgroundMonitorButton(isRunning: Boolean) {
        binding.btnBackgroundMonitor.text = if (isRunning) "Stop Monitor" else "Start Monitor"
        binding.btnBackgroundMonitor.setBackgroundColor(
            ContextCompat.getColor(this, if (isRunning) android.R.color.holo_red_dark else android.R.color.holo_green_dark)
        )
    }

    private fun checkPermissions() {
        val permissions = mutableListOf<String>()

        if (ActivityCompat.checkSelfPermission(this, Manifest.permission.ACCESS_FINE_LOCATION) != PackageManager.PERMISSION_GRANTED) {
            permissions.add(Manifest.permission.ACCESS_FINE_LOCATION)
        }

        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU) {
            if (ActivityCompat.checkSelfPermission(this, Manifest.permission.NEARBY_WIFI_DEVICES) != PackageManager.PERMISSION_GRANTED) {
                permissions.add(Manifest.permission.NEARBY_WIFI_DEVICES)
            }
        }

        if (permissions.isNotEmpty()) {
            ActivityCompat.requestPermissions(this, permissions.toTypedArray(), 100)
        }
    }

    override fun onRequestPermissionsResult(requestCode: Int, permissions: Array<out String>, grantResults: IntArray) {
        super.onRequestPermissionsResult(requestCode, permissions, grantResults)
        if (requestCode == 100) {
            val allGranted = grantResults.all { it == PackageManager.PERMISSION_GRANTED }
            if (!allGranted) {
                Toast.makeText(this, getString(R.string.permission_denied), Toast.LENGTH_LONG).show()
            }
        }
    }

    private fun toggleScanning() {
        if (isScanning) {
            stopScanning()
        } else {
            startScanning()
        }
    }

    private fun startScanning() {
        if (ActivityCompat.checkSelfPermission(this, Manifest.permission.ACCESS_FINE_LOCATION) != PackageManager.PERMISSION_GRANTED) {
            Toast.makeText(this, "Location permission required for WiFi scanning", Toast.LENGTH_SHORT).show()
            return
        }

        isScanning = true
        binding.btnStartScan.text = getString(R.string.stop_scan)
        binding.progressBar.visibility = android.view.View.VISIBLE

        val intentFilter = IntentFilter(WifiManager.SCAN_RESULTS_AVAILABLE_ACTION)
        registerReceiver(wifiScanReceiver, intentFilter)

        scanJob = activityScope.launch {
            while (isActive) {
                try {
                    wifiManager.startScan()
                    delay(5000)
                } catch (_: Exception) {
                    delay(5000)
                }
            }
        }

        wifiManager.startScan()
    }

    private fun stopScanning() {
        isScanning = false
        binding.btnStartScan.text = getString(R.string.start_scan)
        binding.progressBar.visibility = android.view.View.GONE

        scanJob?.cancel()

        try {
            unregisterReceiver(wifiScanReceiver)
        } catch (_: IllegalArgumentException) {
            // Receiver not registered
        }
    }

    private fun processScanResults(results: List<ScanResult>) {
        activityScope.launch {
            scanResults.clear()
            scanResults.addAll(results)

            val detectedNetworks = results.map { analyzeNetwork(it) }

            scannedNetworks.clear()
            scannedNetworks.addAll(detectedNetworks.sortedByDescending { it.threatLevel.ordinal })
            adapter.notifyDataSetChanged()

            updateScanResultsSummary()
        }
    }

    private fun analyzeNetwork(result: ScanResult): EvilTwinNetwork {
        val detectionResult = evilTwinDetector.detectEvilTwin(result)

        return EvilTwinNetwork(
            ssid = result.SSID ?: "Hidden Network",
            bssid = result.BSSID,
            capabilities = result.capabilities,
            level = result.level,
            frequency = result.frequency,
            timestamp = result.timestamp,
            isSuspicious = detectionResult.isEvilTwin,
            threatLevel = detectionResult.threatLevel,
            reason = detectionResult.reasons.joinToString("; "),
            confidenceScore = detectionResult.confidenceScore,
            recommendations = detectionResult.recommendations
        )
    }

    private fun updateScanResultsSummary() {
        binding.tvTotalNetworks.text = getString(R.string.total_networks, scanResults.size)
        binding.tvSuspiciousNetworks.text = getString(R.string.suspicious_networks, scannedNetworks.count { it.isSuspicious })
    }

    private fun clearResults() {
        scannedNetworks.clear()
        scanResults.clear()
        adapter.notifyDataSetChanged()
        updateScanResultsSummary()
        Toast.makeText(this, getString(R.string.results_cleared), Toast.LENGTH_SHORT).show()
    }

    private fun saveReport() {
        activityScope.launch(Dispatchers.IO) {
            try {
                val report = buildString {
                    appendLine("=== Evil Twin Detection Report ===")
                    appendLine("Generated: ${SimpleDateFormat("yyyy-MM-dd HH:mm:ss", Locale.getDefault()).format(Date())}")
                    appendLine("Total Networks Scanned: ${scanResults.size}")
                    appendLine("Suspicious Networks: ${scannedNetworks.count { it.isSuspicious }}")
                    appendLine()

                    scannedNetworks.forEachIndexed { index, network ->
                        appendLine("${index + 1}. ${network.ssid}")
                        appendLine("   BSSID: ${network.bssid}")
                        appendLine("   Threat Level: ${network.threatLevel}")
                        appendLine("   Signal: ${network.level}dBm")
                        appendLine("   Frequency: ${network.frequency}MHz")
                        appendLine("   Capabilities: ${network.capabilities}")
                        if (network.reason.isNotBlank()) {
                            appendLine("   Reason: ${network.reason}")
                        }
                        if (network.recommendations.isNotEmpty()) {
                            appendLine("   Recommendations: ${network.recommendations.joinToString(", ")}")
                        }
                        if (network.confidenceScore > 0) {
                            appendLine("   Confidence: ${(network.confidenceScore * 100).toInt()}%")
                        }
                        appendLine()
                    }
                }

                val filename = "evil_twin_report_${System.currentTimeMillis()}.txt"
                openFileOutput(filename, Context.MODE_PRIVATE).use { output ->
                    output.write(report.toByteArray())
                }

                activityScope.launch(Dispatchers.Main) {
                    Toast.makeText(this@EvilTwinActivity, "Report saved: $filename", Toast.LENGTH_LONG).show()
                }
            } catch (e: Exception) {
                activityScope.launch(Dispatchers.Main) {
                    Toast.makeText(this@EvilTwinActivity, "Failed to save report: ${e.message}", Toast.LENGTH_SHORT).show()
                }
            }
        }
    }

    private fun showNetworkDetails(network: EvilTwinNetwork) {
        val dialog = android.app.AlertDialog.Builder(this)
            .setTitle(network.ssid)
            .setMessage(buildString {
                appendLine("BSSID: ${network.bssid}")
                appendLine("Threat Level: ${network.threatLevel}")
                appendLine("Signal: ${network.level}dBm")
                appendLine("Frequency: ${network.frequency}MHz")
                appendLine("Capabilities: ${network.capabilities}")
                if (network.reason.isNotBlank()) {
                    appendLine("Reason: ${network.reason}")
                }
                if (network.recommendations.isNotEmpty()) {
                    appendLine("Recommendations: ${network.recommendations.joinToString(", ")}")
                }
                if (network.confidenceScore > 0) {
                    appendLine("Confidence: ${(network.confidenceScore * 100).toInt()}%")
                }
            })
            .setPositiveButton("OK", null)
            .create()

        dialog.show()
    }

    override fun onCreateOptionsMenu(menu: Menu): Boolean {
        menuInflater.inflate(R.menu.menu_evil_twin, menu)
        return true
    }

    override fun onOptionsItemSelected(item: MenuItem): Boolean {
        return when (item.itemId) {
            android.R.id.home -> {
                finish()
                true
            }
            R.id.action_settings -> {
                Toast.makeText(this, "Settings clicked", Toast.LENGTH_SHORT).show()
                true
            }
            R.id.action_help -> {
                Toast.makeText(this, "Help clicked", Toast.LENGTH_SHORT).show()
                true
            }
            R.id.action_export -> {
                saveReport()
                true
            }
            else -> super.onOptionsItemSelected(item)
        }
    }

    override fun onResume() {
        super.onResume()
        updateBackgroundMonitorButton(isServiceRunning())
    }

    override fun onDestroy() {
        super.onDestroy()
        stopScanning()
        activityScope.cancel()
    }
}

data class EvilTwinNetwork(
    val ssid: String,
    val bssid: String,
    val capabilities: String,
    val level: Int,
    val frequency: Int,
    val timestamp: Long = System.currentTimeMillis(),
    val isSuspicious: Boolean = false,
    val threatLevel: ThreatLevel = ThreatLevel.LOW,
    val reason: String = "",
    val confidenceScore: Double = 0.0,
    val recommendations: List<String> = emptyList()
)

enum class ThreatLevel {
    LOW, MEDIUM, HIGH, CRITICAL
}
