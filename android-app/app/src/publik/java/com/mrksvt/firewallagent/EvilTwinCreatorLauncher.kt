package com.mrksvt.firewallagent

import android.content.Context
import android.widget.Toast

object EvilTwinCreatorLauncher {
    fun launch(context: Context) {
        // Publik version: Do nothing or tell user it's absent
        Toast.makeText(context, "Fitur internal Lab tidak tersedia di versi ini.", Toast.LENGTH_SHORT).show()
    }
}
