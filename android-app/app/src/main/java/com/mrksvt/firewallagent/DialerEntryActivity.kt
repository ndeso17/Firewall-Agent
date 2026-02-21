package com.mrksvt.firewallagent

import android.content.Intent
import android.os.Bundle
import androidx.appcompat.app.AppCompatActivity

class DialerEntryActivity : AppCompatActivity() {
    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)

        // Minimal dialer entry point for ROLE_DIALER eligibility.
        val tel = intent?.dataString ?: intent?.getStringExtra(Intent.EXTRA_PHONE_NUMBER)
        val target = Intent(this, CallGuardDialerActivity::class.java).apply {
            putExtra("dialer_tel", tel)
            addFlags(Intent.FLAG_ACTIVITY_NEW_TASK or Intent.FLAG_ACTIVITY_CLEAR_TOP)
        }
        startActivity(target)
        finish()
    }
}
