package com.mrksvt.firewallagent

import android.app.Notification
import android.app.NotificationChannel
import android.app.NotificationManager
import android.app.PendingIntent
import android.app.Service
import android.content.Context
import android.content.Intent
import android.content.IntentFilter
import android.net.wifi.WifiManager
import android.os.Build
import android.os.Handler
import android.os.IBinder
import android.os.Looper
import android.util.Log
import androidx.core.app.NotificationCompat
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.cancel
import kotlinx.coroutines.launch
import java.util.concurrent.ConcurrentHashMap

class EvilTwinDetectionService : Service() {
    
    private lateinit var wifiManager: WifiManager
    private val handler = Handler(Looper.getMainLooper())
    private val serviceScope = CoroutineScope(SupervisorJob() + Dispatchers.IO)
    
    private val scanInterval = 30000L // 30 detik
    private var isMonitoring = false
    private val threatHistory = ConcurrentHashMap<String, Int>() // BSSID -> threat count
    
    private val evilTwinReceiver = EvilTwinReceiver()
    
    companion object {
        private const val TAG = "EvilTwinService"
        private const val NOTIFICATION_CHANNEL_ID = "evil_twin_channel"
        private const val NOTIFICATION_ID = 1001
        private const val MAX_THREAT_COUNT = 3
        private const val ACTION_START_MONITOR = "com.mrksvt.firewallagent.action.START_EVIL_TWIN_MONITOR"
        private const val ACTION_STOP_MONITOR = "com.mrksvt.firewallagent.action.STOP_EVIL_TWIN_MONITOR"
        private const val ACTION_RECORD_THREAT = "RECORD_THREAT"
        private const val ACTION_SEND_THREAT_NOTIFICATION = "SEND_THREAT_NOTIFICATION"
        @Volatile
        private var running = false

        fun isRunning(): Boolean = running
        
        fun startService(context: Context) {
            val intent = Intent(context, EvilTwinDetectionService::class.java).apply {
                action = ACTION_START_MONITOR
            }
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
                context.startForegroundService(intent)
            } else {
                context.startService(intent)
            }
        }
        
        fun stopService(context: Context): Boolean {
            val intent = Intent(context, EvilTwinDetectionService::class.java).apply {
                action = ACTION_STOP_MONITOR
            }
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
                context.startForegroundService(intent)
            } else {
                context.startService(intent)
            }
            // Fallback hard-stop in case action dispatch is delayed on some OEM ROMs.
            val hardStop = context.stopService(Intent(context, EvilTwinDetectionService::class.java))
            return hardStop
        }
    }
    
    override fun onCreate() {
        super.onCreate()
        wifiManager = applicationContext.getSystemService(Context.WIFI_SERVICE) as WifiManager
        createNotificationChannel()
        registerReceiver()
    }
    
    override fun onStartCommand(intent: Intent?, flags: Int, startId: Int): Int {
        when (intent?.action) {
            ACTION_STOP_MONITOR -> {
                Log.d(TAG, "Evil Twin detection service stop requested")
                stopMonitoring()
                running = false
                if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.N) {
                    stopForeground(STOP_FOREGROUND_REMOVE)
                } else {
                    @Suppress("DEPRECATION")
                    stopForeground(true)
                }
                stopSelf()
                return START_NOT_STICKY
            }
            ACTION_RECORD_THREAT -> {
                val bssid = intent.getStringExtra("BSSID")
                if (!bssid.isNullOrBlank()) {
                    recordThreat(bssid)
                }
                return START_STICKY
            }
            ACTION_SEND_THREAT_NOTIFICATION -> {
                val details = intent.getStringExtra("THREAT_DETAILS")
                if (!details.isNullOrBlank()) {
                    sendThreatNotification(details)
                }
                return START_STICKY
            }
            else -> {
                Log.d(TAG, "Evil Twin detection service started")
                val notification = createNotification()
                startForeground(NOTIFICATION_ID, notification)
                startMonitoring()
                running = true
                return START_STICKY
            }
        }
    }
    
    override fun onBind(intent: Intent?): IBinder? = null
    
    override fun onDestroy() {
        super.onDestroy()
        Log.d(TAG, "Evil Twin detection service stopped")
        stopMonitoring()
        running = false
        unregisterReceiver()
        serviceScope.cancel()
    }
    
    private fun createNotificationChannel() {
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
            val channel = NotificationChannel(
                NOTIFICATION_CHANNEL_ID,
                "Evil Twin Detection",
                NotificationManager.IMPORTANCE_HIGH
            ).apply {
                description = "Notifikasi untuk deteksi serangan Evil Twin"
                enableVibration(true)
                setSound(null, null)
            }
            
            val notificationManager = getSystemService(NotificationManager::class.java)
            notificationManager.createNotificationChannel(channel)
        }
    }
    
    private fun createNotification(content: String = "Monitoring WiFi untuk serangan Evil Twin..."): Notification {
        val intent = Intent(this, EvilTwinActivity::class.java).apply {
            flags = Intent.FLAG_ACTIVITY_NEW_TASK or Intent.FLAG_ACTIVITY_CLEAR_TASK
        }
        
        val pendingIntent = PendingIntent.getActivity(
            this, 0, intent, PendingIntent.FLAG_UPDATE_CURRENT or PendingIntent.FLAG_IMMUTABLE
        )
        
        return NotificationCompat.Builder(this, NOTIFICATION_CHANNEL_ID)
            .setSmallIcon(R.drawable.ic_notif_security)
            .setContentTitle("Evil Twin Detection")
            .setContentText(content)
            .setPriority(NotificationCompat.PRIORITY_HIGH)
            .setContentIntent(pendingIntent)
            .setOngoing(true)
            .build()
    }
    
    private fun startMonitoring() {
        if (isMonitoring) return
        
        isMonitoring = true
        running = true
        scheduleNextScan()
        Log.d(TAG, "Started monitoring for Evil Twin attacks")
    }
    
    private fun stopMonitoring() {
        isMonitoring = false
        running = false
        handler.removeCallbacksAndMessages(null)
        Log.d(TAG, "Stopped monitoring for Evil Twin attacks")
    }
    
    private fun scheduleNextScan() {
        if (!isMonitoring) return
        
        handler.postDelayed({
            performScan()
            scheduleNextScan()
        }, scanInterval)
    }
    
    private fun performScan() {
        serviceScope.launch {
            try {
                val success = wifiManager.startScan()
                if (success) {
                    Log.d(TAG, "WiFi scan initiated")
                }
            } catch (e: SecurityException) {
                Log.e(TAG, "Security exception during scan", e)
            } catch (e: Exception) {
                Log.e(TAG, "Error during scan", e)
            }
        }
    }
    
    private fun registerReceiver() {
        val filter = IntentFilter().apply {
            addAction(WifiManager.SCAN_RESULTS_AVAILABLE_ACTION)
            addAction(WifiManager.NETWORK_STATE_CHANGED_ACTION)
            addAction(WifiManager.WIFI_STATE_CHANGED_ACTION)
        }
        
        registerReceiver(evilTwinReceiver, filter)
    }
    
    private fun unregisterReceiver() {
        try {
            unregisterReceiver(evilTwinReceiver)
        } catch (e: IllegalArgumentException) {
            // Receiver not registered
        }
    }
    
    fun updateNotification(content: String) {
        val notification = createNotification(content)
        val notificationManager = getSystemService(NotificationManager::class.java)
        notificationManager.notify(NOTIFICATION_ID, notification)
    }
    
    fun sendThreatNotification(threatDetails: String) {
        val intent = Intent(this, EvilTwinActivity::class.java).apply {
            flags = Intent.FLAG_ACTIVITY_NEW_TASK or Intent.FLAG_ACTIVITY_CLEAR_TASK
        }
        
        val pendingIntent = PendingIntent.getActivity(
            this, 0, intent, PendingIntent.FLAG_UPDATE_CURRENT or PendingIntent.FLAG_IMMUTABLE
        )
        
        val notification = NotificationCompat.Builder(this, NOTIFICATION_CHANNEL_ID)
            .setSmallIcon(R.drawable.ic_status_error)
            .setContentTitle("🚨 Evil Twin Attack Detected!")
            .setContentText(threatDetails)
            .setPriority(NotificationCompat.PRIORITY_HIGH)
            .setContentIntent(pendingIntent)
            .setAutoCancel(true)
            .setStyle(NotificationCompat.BigTextStyle().bigText(threatDetails))
            .build()
        
        val notificationManager = getSystemService(NotificationManager::class.java)
        notificationManager.notify(System.currentTimeMillis().toInt(), notification)
    }
    
    fun recordThreat(bssid: String) {
        val count = threatHistory.getOrDefault(bssid, 0) + 1
        threatHistory[bssid] = count
        
        if (count >= MAX_THREAT_COUNT) {
            // Persistent threat detected
            sendThreatNotification("Persistent Evil Twin threat detected from BSSID: $bssid")
            threatHistory[bssid] = 0 // Reset counter after alert
        }
    }
}
