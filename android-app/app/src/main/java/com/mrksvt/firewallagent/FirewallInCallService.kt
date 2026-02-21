package com.mrksvt.firewallagent

import android.telecom.Call
import android.telecom.InCallService

class FirewallInCallService : InCallService() {
    override fun onCallAdded(call: Call) {
        super.onCallAdded(call)
        // Stub service for ROLE_DIALER eligibility.
    }

    override fun onCallRemoved(call: Call) {
        super.onCallRemoved(call)
    }
}

