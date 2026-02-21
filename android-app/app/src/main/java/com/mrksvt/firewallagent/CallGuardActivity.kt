package com.mrksvt.firewallagent

import android.Manifest
import android.os.Bundle
import android.app.role.RoleManager
import androidx.appcompat.app.AlertDialog
import android.content.Intent
import android.content.pm.PackageManager
import android.os.Build
import android.provider.Settings
import android.provider.CallLog
import android.telecom.TelecomManager
import android.widget.ArrayAdapter
import androidx.appcompat.app.AppCompatActivity
import androidx.activity.result.contract.ActivityResultContracts
import androidx.core.content.ContextCompat
import androidx.lifecycle.lifecycleScope
import com.mrksvt.firewallagent.databinding.ActivityCallGuardBinding
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext
import java.io.File
import org.json.JSONArray
import org.json.JSONObject

class CallGuardActivity : AppCompatActivity() {
    private lateinit var binding: ActivityCallGuardBinding
    private val recentNumbers = mutableListOf<String>()
    private val roleLauncher = registerForActivityResult(
        ActivityResultContracts.StartActivityForResult(),
    ) {
        maybeRequestContactsPermissionIfDialer()
        loadConfig()
    }
    private val callLogPermLauncher = registerForActivityResult(
        ActivityResultContracts.RequestPermission(),
    ) {
        if (it) {
            loadRecentCalls()
        } else {
            binding.outputText.text = "Izin log telepon ditolak."
        }
    }
    private val contactsPermLauncher = registerForActivityResult(
        ActivityResultContracts.RequestPermission(),
    ) {
        if (it) {
            binding.outputText.text = "Izin kontak diberikan."
            loadConfig()
        } else {
            binding.outputText.text = "Izin kontak ditolak."
        }
    }

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        binding = ActivityCallGuardBinding.inflate(layoutInflater)
        setContentView(binding.root)

        binding.addWhitelistBtn.setOnClickListener { addNumber(true) }
        binding.addBlacklistBtn.setOnClickListener { addNumber(false) }
        binding.removeBtn.setOnClickListener { removeNumber() }
        binding.saveBtn.setOnClickListener { saveConfig() }
        binding.reloadBtn.setOnClickListener { loadConfig() }
        binding.activateDialerBtn.setOnClickListener { requestDialerRole() }
        binding.activateScreeningBtn.setOnClickListener { requestCallScreeningRole() }
        binding.openCallSettingsBtn.setOnClickListener {
            startActivity(Intent(Settings.ACTION_MANAGE_DEFAULT_APPS_SETTINGS))
        }
        binding.forceSetupRootBtn.setOnClickListener { forceSetupViaRoot() }
        binding.requestCallLogBtn.setOnClickListener { requestCallLogPermission() }
        binding.loadRecentBtn.setOnClickListener { loadRecentCalls() }
        binding.addRecentWhitelistBtn.setOnClickListener { addRecentNumbersMulti(true) }
        binding.addRecentBlacklistBtn.setOnClickListener { addRecentNumbersMulti(false) }
        binding.analyzeRiskBtn.setOnClickListener { analyzeRiskNow() }
        binding.openCallLogMenuBtn.setOnClickListener {
            startActivity(Intent(this, CallLogMenuActivity::class.java))
        }
        binding.exportDatasetBtn.setOnClickListener { exportDatasetInfo() }

        loadConfig()
        maybeRequestContactsPermissionIfDialer()
    }

    private fun loadConfig() {
        val pref = getSharedPreferences("call_guard", MODE_PRIVATE)
        val raw = pref.getString("config", null)
        val j = if (raw.isNullOrBlank()) {
            JSONObject()
                .put("block_unknown", false)
                .put("whitelist", JSONArray())
                .put("blacklist", JSONArray())
        } else {
            runCatching { JSONObject(raw) }.getOrElse { JSONObject() }
        }
        binding.blockUnknownSwitch.isChecked = j.optBoolean("block_unknown", false)
        binding.autoRiskSyncSwitch.isChecked = j.optBoolean("auto_risk_autosync", false)
        binding.riskThresholdInput.setText(j.optInt("auto_risk_threshold", 70).toString())
        binding.whitelistText.setText(arrToLines(j.optJSONArray("whitelist")))
        binding.blacklistText.setText(arrToLines(j.optJSONArray("blacklist")))
        val screening = screeningStatus()
        val dialer = dialerStatus()
        binding.outputText.text =
            "Status dialer: $dialer\n" +
                "Status screening: $screening\n" +
                "Mode saat ini memblokir incoming call via CallScreeningService.\n" +
                "Blocked log: ${countBlockedLogLines()} entries\n" +
                "Dataset labels: ${CallDatasetStore.count(this)} entries\n" +
                "Catatan: announcement network asli (nomor tidak aktif/tidak terjangkau) butuh integrasi framework/IMS vendor."
        bindRecentSpinner()
    }

    private fun saveConfig() {
        val whitelistCsv = binding.whitelistText.text?.toString().orEmpty().lineSequence()
            .map { normalize(it) }
            .filter { it.isNotBlank() }
            .toSet()
            .joinToString(",")
        val blacklistCsv = binding.blacklistText.text?.toString().orEmpty().lineSequence()
            .map { normalize(it) }
            .filter { it.isNotBlank() }
            .toSet()
            .joinToString(",")
        val j = JSONObject()
            .put("block_unknown", binding.blockUnknownSwitch.isChecked)
            .put("auto_risk_autosync", binding.autoRiskSyncSwitch.isChecked)
            .put("auto_risk_threshold", parseRiskThreshold())
            .put("whitelist", linesToArr(binding.whitelistText.text?.toString().orEmpty()))
            .put("blacklist", linesToArr(binding.blacklistText.text?.toString().orEmpty()))
            .put("whitelist_csv", whitelistCsv)
            .put("blacklist_csv", blacklistCsv)
        getSharedPreferences("call_guard", MODE_PRIVATE).edit()
            .putString("config", j.toString())
            .apply()
        binding.outputText.text = "Config call guard tersimpan.\nStatus screening: ${screeningStatus()}"
    }

    private fun addNumber(white: Boolean) {
        val num = binding.numberInput.text?.toString()?.trim().orEmpty()
        if (num.isBlank()) return
        val normalized = normalize(num)
        if (normalized.isBlank()) return
        val target = if (white) binding.whitelistText else binding.blacklistText
        val lines = target.text?.toString()?.lineSequence()?.map { it.trim() }?.filter { it.isNotBlank() }?.toMutableSet()
            ?: mutableSetOf()
        lines += normalized
        target.setText(lines.joinToString("\n"))
        CallDatasetStore.recordManualLabel(
            context = this,
            number = normalized,
            isSpam = !white,
            source = if (white) "ui_add_whitelist" else "ui_add_blacklist",
        )
        binding.numberInput.setText("")
    }

    private fun removeNumber() {
        val num = binding.numberInput.text?.toString()?.trim().orEmpty()
        if (num.isBlank()) return
        val normalized = normalize(num)
        if (normalized.isBlank()) return
        val wl = binding.whitelistText.text?.toString().orEmpty().lineSequence().map { it.trim() }.filter { it.isNotBlank() && it != normalized }
        val bl = binding.blacklistText.text?.toString().orEmpty().lineSequence().map { it.trim() }.filter { it.isNotBlank() && it != normalized }
        binding.whitelistText.setText(wl.joinToString("\n"))
        binding.blacklistText.setText(bl.joinToString("\n"))
        binding.numberInput.setText("")
    }

    private fun arrToLines(arr: JSONArray?): String {
        if (arr == null) return ""
        val out = mutableListOf<String>()
        for (i in 0 until arr.length()) out += arr.optString(i)
        return out.filter { it.isNotBlank() }.joinToString("\n")
    }

    private fun linesToArr(lines: String): JSONArray {
        val arr = JSONArray()
        lines.lineSequence().map { it.trim() }.filter { it.isNotBlank() }.forEach { arr.put(it) }
        return arr
    }

    private fun normalize(raw: String): String = raw.filter { it.isDigit() }

    private fun requestDialerRole() {
        val telecom = getSystemService(TelecomManager::class.java)
        if (telecom?.defaultDialerPackage == packageName) {
            binding.outputText.text = "App ini sudah jadi default phone app."
            return
        }

        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.Q) {
            runCatching {
                val rm = getSystemService(RoleManager::class.java)
                if (rm != null && rm.isRoleAvailable(RoleManager.ROLE_DIALER)) {
                    val intent = rm.createRequestRoleIntent(RoleManager.ROLE_DIALER)
                    roleLauncher.launch(intent)
                    return
                }
            }
        }

        // Fallback for OEM ROM where Role service is unavailable.
        runCatching {
            val i = Intent(TelecomManager.ACTION_CHANGE_DEFAULT_DIALER).apply {
                putExtra(TelecomManager.EXTRA_CHANGE_DEFAULT_DIALER_PACKAGE_NAME, packageName)
            }
            roleLauncher.launch(i)
            return
        }

        startActivity(Intent(Settings.ACTION_MANAGE_DEFAULT_APPS_SETTINGS))
    }

    private fun maybeRequestContactsPermissionIfDialer() {
        val telecom = getSystemService(TelecomManager::class.java)
        val isDialer = telecom?.defaultDialerPackage == packageName
        if (!isDialer) return
        val granted = ContextCompat.checkSelfPermission(this, Manifest.permission.READ_CONTACTS) == PackageManager.PERMISSION_GRANTED
        if (!granted) {
            contactsPermLauncher.launch(Manifest.permission.READ_CONTACTS)
        }
    }

    private fun requestCallScreeningRole() {
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.Q) {
            val rm = getSystemService(RoleManager::class.java)
            if (rm != null && rm.isRoleAvailable(RoleManager.ROLE_CALL_SCREENING)) {
                if (rm.isRoleHeld(RoleManager.ROLE_CALL_SCREENING)) {
                    binding.outputText.text = "Call Screening sudah aktif untuk app ini."
                    return
                }
                val intent = rm.createRequestRoleIntent(RoleManager.ROLE_CALL_SCREENING)
                roleLauncher.launch(intent)
                return
            }
        }
        // Fallback older Android/ROM.
        startActivity(Intent(Settings.ACTION_MANAGE_DEFAULT_APPS_SETTINGS))
    }

    private fun requestCallLogPermission() {
        val granted = ContextCompat.checkSelfPermission(this, Manifest.permission.READ_CALL_LOG) == PackageManager.PERMISSION_GRANTED
        if (granted) {
            loadRecentCalls()
        } else {
            callLogPermLauncher.launch(Manifest.permission.READ_CALL_LOG)
        }
    }

    private fun loadRecentCalls() {
        val granted = ContextCompat.checkSelfPermission(this, Manifest.permission.READ_CALL_LOG) == PackageManager.PERMISSION_GRANTED
        if (!granted) {
            binding.outputText.text = "Izin READ_CALL_LOG belum diberikan."
            return
        }
        val list = linkedSetOf<String>()
        val cursor = contentResolver.query(
            CallLog.Calls.CONTENT_URI,
            arrayOf(CallLog.Calls.NUMBER),
            null,
            null,
            "${CallLog.Calls.DATE} DESC",
        )
        cursor?.use { c ->
            val idx = c.getColumnIndex(CallLog.Calls.NUMBER)
            while (c.moveToNext()) {
                val raw = if (idx >= 0) c.getString(idx) else ""
                val n = normalize(raw.orEmpty())
                if (n.isNotBlank()) list += n
                if (list.size >= 50) break
            }
        }
        recentNumbers.clear()
        recentNumbers.addAll(list)
        bindRecentSpinner()
        binding.outputText.text = "Recent call numbers loaded: ${recentNumbers.size}"
    }

    private fun bindRecentSpinner() {
        val items = if (recentNumbers.isEmpty()) listOf("-") else recentNumbers
        val adapter = ArrayAdapter(
            this,
            android.R.layout.simple_spinner_dropdown_item,
            items,
        )
        binding.recentSpinner.adapter = adapter
    }

    private fun addRecentNumber(toWhitelist: Boolean) {
        val selected = binding.recentSpinner.selectedItem?.toString().orEmpty()
        val n = normalize(selected)
        if (n.isBlank()) return
        val target = if (toWhitelist) binding.whitelistText else binding.blacklistText
        val lines = target.text?.toString().orEmpty().lineSequence()
            .map { it.trim() }
            .filter { it.isNotBlank() }
            .toMutableSet()
        lines += n
        target.setText(lines.joinToString("\n"))
    }

    private fun addRecentNumbersMulti(toWhitelist: Boolean) {
        if (recentNumbers.isEmpty()) {
            binding.outputText.text = "Belum ada recent calls. Tekan Load Recent Calls dulu."
            return
        }
        val labels = recentNumbers.toTypedArray()
        val checked = BooleanArray(labels.size)
        AlertDialog.Builder(this)
            .setTitle(if (toWhitelist) "Pilih nomor ke whitelist" else "Pilih nomor ke blacklist")
            .setMultiChoiceItems(labels, checked) { _, which, isChecked ->
                checked[which] = isChecked
            }
            .setNegativeButton("Batal", null)
            .setPositiveButton("Tambah") { _, _ ->
                val selected = labels.indices
                    .filter { checked[it] }
                    .map { normalize(labels[it]) }
                    .filter { it.isNotBlank() }
                    .toSet()
                if (selected.isEmpty()) {
                    binding.outputText.text = "Tidak ada nomor yang dipilih."
                    return@setPositiveButton
                }
                val target = if (toWhitelist) binding.whitelistText else binding.blacklistText
                val lines = target.text?.toString().orEmpty().lineSequence()
                    .map { it.trim() }
                    .filter { it.isNotBlank() }
                    .toMutableSet()
                lines += selected
                target.setText(lines.joinToString("\n"))
                selected.forEach { n ->
                    CallDatasetStore.recordManualLabel(
                        context = this@CallGuardActivity,
                        number = n,
                        isSpam = !toWhitelist,
                        source = if (toWhitelist) "ui_recent_to_whitelist" else "ui_recent_to_blacklist",
                    )
                }
                binding.outputText.text = "Nomor ditambahkan: ${selected.size}"
            }
            .show()
    }

    private fun dialerStatus(): String {
        val telecom = getSystemService(TelecomManager::class.java)
        return if (telecom?.defaultDialerPackage == packageName) "active" else "inactive"
    }

    private fun screeningStatus(): String {
        return if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.Q) {
            val rm = getSystemService(RoleManager::class.java)
            if (rm != null && rm.isRoleAvailable(RoleManager.ROLE_CALL_SCREENING) && rm.isRoleHeld(RoleManager.ROLE_CALL_SCREENING)) {
                "active"
            } else {
                "inactive"
            }
        } else {
            "needs-default-app-setup"
        }
    }

    private fun forceSetupViaRoot() {
        lifecycleScope.launch {
            val pkg = packageName
            val cmd = buildString {
                append("MOD=/data/adb/modules/ai.adaptive.firewall;")
                append("if [ -x \"${'$'}MOD/bin/telephony_priv_setup.sh\" ]; then ")
                append("sh \"${'$'}MOD/bin/telephony_priv_setup.sh\";")
                append("else ")
                append("settings put secure dialer_default_application $pkg;")
                append("settings put secure call_screening_default_component $pkg/.FirewallCallScreeningService;")
                append("appops set $pkg READ_CALL_LOG allow;")
                append("appops set $pkg READ_CONTACTS allow;")
                append("appops set $pkg READ_PHONE_STATE allow;")
                append("appops set $pkg ANSWER_PHONE_CALLS allow;")
                append("appops set $pkg CALL_PHONE allow;")
                append("pm grant $pkg android.permission.READ_CALL_LOG >/dev/null 2>&1 || true;")
                append("pm grant $pkg android.permission.READ_CONTACTS >/dev/null 2>&1 || true;")
                append("pm grant $pkg android.permission.READ_PHONE_STATE >/dev/null 2>&1 || true;")
                append("pm grant $pkg android.permission.ANSWER_PHONE_CALLS >/dev/null 2>&1 || true;")
                append("pm grant $pkg android.permission.CALL_PHONE >/dev/null 2>&1 || true;")
                append("fi;")
                append("echo ---status---;")
                append("if [ -f \"${'$'}MOD/runtime/ims_ril/adapter.json\" ]; then ")
                append("echo adapter_vendor=${'$'}(sed -n 's/.*\\\"vendor\\\":\\\"\\([^\\\"]*\\)\\\".*/\\1/p' \"${'$'}MOD/runtime/ims_ril/adapter.json\" | head -n1);")
                append("fi;")
                append("settings get secure dialer_default_application;")
                append("settings get secure call_screening_default_component;")
                append("appops get $pkg READ_CALL_LOG;")
                append("appops get $pkg READ_CONTACTS;")
                append("appops get $pkg READ_PHONE_STATE;")
                append("appops get $pkg ANSWER_PHONE_CALLS;")
                append("appops get $pkg CALL_PHONE;")
            }
            val result = withContext(Dispatchers.IO) { RootFirewallController.runRaw(cmd) }
            binding.outputText.text = buildString {
                appendLine("Force setup via root selesai.")
                appendLine("exit=${result.code}")
                if (result.stdout.isNotBlank()) appendLine(result.stdout)
                if (result.stderr.isNotBlank()) appendLine(result.stderr)
            }
            loadConfig()
        }
    }

    private fun analyzeRiskNow() {
        saveConfig()
        val granted = ContextCompat.checkSelfPermission(this, Manifest.permission.READ_CALL_LOG) == PackageManager.PERMISSION_GRANTED
        if (!granted) {
            binding.outputText.text = "Butuh izin READ_CALL_LOG untuk risk scoring."
            callLogPermLauncher.launch(Manifest.permission.READ_CALL_LOG)
            return
        }

        lifecycleScope.launch {
            val report = withContext(Dispatchers.IO) { CallRiskEngine.analyzeAndSync(this@CallGuardActivity) }
            val top = report.risky.take(8)
            val text = buildString {
                appendLine("Risk analyze selesai.")
                appendLine("Nomor dianalisis: ${report.analyzed}")
                appendLine("Nomor berisiko: ${report.risky.size}")
                appendLine("Auto-added ke blacklist: ${report.autoAdded.size}")
                if (top.isNotEmpty()) {
                    appendLine()
                    appendLine("Top risky:")
                    top.forEach {
                        appendLine("- ${it.number} | score=${it.score} calls=${it.calls} missed=${it.missed} short=${it.shortCalls}")
                    }
                }
            }
            binding.outputText.text = text
            // Refresh text box blacklist if updated by autosync
            loadConfig()
        }
    }

    private fun parseRiskThreshold(): Int {
        return binding.riskThresholdInput.text?.toString()?.trim()?.toIntOrNull()?.coerceIn(1, 100) ?: 70
    }

    private fun blockedLogFile(): File = File(filesDir, "call_guard_blocked.log")

    private fun countBlockedLogLines(): Int {
        return runCatching {
            val f = blockedLogFile()
            if (!f.exists()) 0 else f.readLines().size
        }.getOrDefault(0)
    }

    private fun exportDatasetInfo() {
        val f = CallDatasetStore.file(this)
        val count = CallDatasetStore.count(this)
        binding.outputText.text = buildString {
            appendLine("Dataset training siap dipakai.")
            appendLine("Entries: $count")
            appendLine("File: ${f.absolutePath}")
            appendLine("Format: JSON Lines (1 sample per line)")
        }
    }
}
