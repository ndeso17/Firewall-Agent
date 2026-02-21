package com.mrksvt.firewallagent

import android.Manifest
import android.content.Intent
import android.content.pm.PackageManager
import android.net.Uri
import android.os.Bundle
import android.telecom.TelecomManager
import android.widget.Toast
import android.widget.ImageButton
import android.widget.TextView
import androidx.activity.result.contract.ActivityResultContracts
import androidx.appcompat.app.AppCompatActivity
import androidx.core.content.ContextCompat

class CallGuardDialerActivity : AppCompatActivity() {
    private lateinit var numberText: TextView
    private val digits = StringBuilder()
    private val callPermLauncher = registerForActivityResult(
        ActivityResultContracts.RequestPermission(),
    ) { granted ->
        if (granted) {
            placeCall()
        } else {
            Toast.makeText(this, "Izin telepon ditolak.", Toast.LENGTH_SHORT).show()
        }
    }

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        setContentView(R.layout.activity_call_guard_dialer)

        numberText = findViewById(R.id.dialNumberText)
        val initial = intent?.getStringExtra("dialer_tel")
            ?.removePrefix("tel:")
            ?.trim()
            .orEmpty()
        if (initial.isNotBlank()) {
            digits.clear()
            digits.append(initial)
            numberText.text = digits.toString()
        }

        findViewById<ImageButton>(R.id.topFilterBtn).setOnClickListener { /* reserved */ }
        findViewById<ImageButton>(R.id.topSearchBtn).setOnClickListener { /* reserved */ }
        findViewById<ImageButton>(R.id.topSettingsBtn).setOnClickListener {
            startActivity(Intent(this, CallGuardActivity::class.java))
        }

        wireDigit(R.id.key1, "1")
        wireDigit(R.id.key2, "2")
        wireDigit(R.id.key3, "3")
        wireDigit(R.id.key4, "4")
        wireDigit(R.id.key5, "5")
        wireDigit(R.id.key6, "6")
        wireDigit(R.id.key7, "7")
        wireDigit(R.id.key8, "8")
        wireDigit(R.id.key9, "9")
        wireDigit(R.id.keyStar, "*")
        wireDigit(R.id.key0, "0")
        wireDigit(R.id.keyHash, "#")

        findViewById<ImageButton>(R.id.callBtn1).setOnClickListener { onCallPressed() }
        findViewById<ImageButton>(R.id.callBtn2).setOnClickListener { onCallPressed() }
        findViewById<ImageButton>(R.id.keypadBtn).setOnClickListener { /* already keypad */ }
    }

    private fun wireDigit(id: Int, value: String) {
        findViewById<TextView>(id).setOnClickListener {
            digits.append(value)
            numberText.text = digits.toString()
        }
    }

    private fun onCallPressed() {
        val out = numberText.text?.toString().orEmpty().trim()
        if (out.isEmpty()) return
        val hasCallPerm =
            ContextCompat.checkSelfPermission(this, Manifest.permission.CALL_PHONE) == PackageManager.PERMISSION_GRANTED
        if (hasCallPerm) {
            placeCall()
        } else {
            callPermLauncher.launch(Manifest.permission.CALL_PHONE)
        }
    }

    private fun placeCall() {
        val out = numberText.text?.toString().orEmpty().trim()
        if (out.isEmpty()) return
        val telUri = Uri.parse("tel:$out")

        // If app is current default dialer, ask telecom to place call directly.
        runCatching {
            val telecom = getSystemService(TelecomManager::class.java)
            if (telecom != null && telecom.defaultDialerPackage == packageName) {
                telecom.placeCall(telUri, Bundle())
                return
            }
        }

        // Generic fallback for non-default dialer mode.
        runCatching {
            startActivity(Intent(Intent.ACTION_CALL, telUri))
            return
        }

        // Last resort: only open dial screen.
        runCatching {
            startActivity(Intent(Intent.ACTION_DIAL, telUri))
        }.onFailure {
            Toast.makeText(this, "Gagal memulai panggilan.", Toast.LENGTH_SHORT).show()
        }
    }
}
