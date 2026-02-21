package com.mrksvt.firewallagent

import android.Manifest
import android.app.PendingIntent
import android.app.Notification
import android.app.NotificationChannel
import android.app.NotificationManager
import android.content.Context
import android.content.Intent
import android.content.pm.PackageManager
import android.os.Build
import androidx.core.app.NotificationCompat
import androidx.core.app.NotificationManagerCompat
import androidx.core.content.ContextCompat

object NotifyHelper {
    private const val statusChannelId = "fw_agent_root_status"
    private const val eventChannelId = "fw_agent_root_event"
    private const val persistentId = 9001
    private const val applyProgressId = 9002

    fun ensureChannel(context: Context) {
        if (Build.VERSION.SDK_INT < Build.VERSION_CODES.O) return
        val manager = context.getSystemService(NotificationManager::class.java)
        val statusChannel = NotificationChannel(
            statusChannelId,
            "Firewall Agent",
            NotificationManager.IMPORTANCE_LOW,
        )
        statusChannel.setShowBadge(false)
        manager.createNotificationChannel(statusChannel)

        val eventChannel = NotificationChannel(
            eventChannelId,
            "Firewall Agent Alerts",
            NotificationManager.IMPORTANCE_DEFAULT,
        )
        eventChannel.setShowBadge(true)
        manager.createNotificationChannel(eventChannel)
    }

    fun post(context: Context, title: String, content: String, id: Int) {
        if (!isNotifGranted(context)) return

        val notif = NotificationCompat.Builder(context, eventChannelId)
            .setSmallIcon(R.drawable.ic_notif_security)
            .setColor(0xFF1FA122.toInt())
            .setContentTitle(title)
            .setContentText(content)
            .setStyle(NotificationCompat.BigTextStyle().bigText(content))
            .setPriority(NotificationCompat.PRIORITY_DEFAULT)
            .setAutoCancel(true)
            .build()
        NotificationManagerCompat.from(context).notify(id, notif)
    }

    fun postNewAppNeedsRules(context: Context, packageName: String) {
        if (!isNotifGranted(context)) return
        val content = "$packageName diblokir default. Atur rules Firewall Agent sebelum digunakan."
        val openIntent = Intent(context, MainActivity::class.java).apply {
            flags = Intent.FLAG_ACTIVITY_NEW_TASK or Intent.FLAG_ACTIVITY_CLEAR_TOP or Intent.FLAG_ACTIVITY_SINGLE_TOP
            putExtra("focus_package", packageName)
        }
        val pendingIntent = PendingIntent.getActivity(
            context,
            packageName.hashCode(),
            openIntent,
            PendingIntent.FLAG_UPDATE_CURRENT or PendingIntent.FLAG_IMMUTABLE,
        )
        val notif = NotificationCompat.Builder(context, eventChannelId)
            .setSmallIcon(R.drawable.ic_notif_security)
            .setColor(0xFF1FA122.toInt())
            .setContentTitle("Aplikasi baru terdeteksi")
            .setContentText(content)
            .setStyle(NotificationCompat.BigTextStyle().bigText(content))
            .setCategory(NotificationCompat.CATEGORY_REMINDER)
            .setPriority(NotificationCompat.PRIORITY_HIGH)
            .setContentIntent(pendingIntent)
            .setAutoCancel(true)
            .setOnlyAlertOnce(false)
            .build()
        val id = ((System.currentTimeMillis() % 100000) + 20000).toInt()
        NotificationManagerCompat.from(context).notify(id, notif)
    }

    fun syncPersistentStatus(
        context: Context,
        enabled: Boolean,
        mode: String,
        service: String,
        ml: String,
    ) {
        if (!isNotifGranted(context)) return
        val nm = NotificationManagerCompat.from(context)
        if (!enabled) {
            nm.cancel(persistentId)
            return
        }
        val notif = buildPersistentStatusNotification(context, enabled, mode, service, ml)
        nm.notify(persistentId, notif)
    }

    fun buildPersistentStatusNotification(
        context: Context,
        enabled: Boolean,
        mode: String,
        service: String,
        ml: String,
    ): Notification {
        val content = if (enabled) {
            "Firewall diaktifkan (${mode.lowercase()})"
        } else {
            "Firewall nonaktif"
        }
        val detail = "Service: $service | ML: $ml"
        return NotificationCompat.Builder(context, statusChannelId)
            .setSmallIcon(R.drawable.ic_notif_security)
            .setColor(0xFF1FA122.toInt())
            .setContentTitle("Firewall Agent")
            .setContentText(content)
            .setStyle(NotificationCompat.BigTextStyle().bigText("$content\n$detail"))
            .setOngoing(true)
            .setSilent(true)
            .setOnlyAlertOnce(true)
            .setPriority(NotificationCompat.PRIORITY_LOW)
            .build()
    }

    fun postApplyProgress(context: Context, processed: Int, totalUid: Int, totalApps: Int) {
        if (!isNotifGranted(context)) return
        val title = "Applying rules"
        val text = "Menerapkan rules $processed/$totalUid UID (dari $totalApps aplikasi)"
        val notif = NotificationCompat.Builder(context, statusChannelId)
            .setSmallIcon(R.drawable.ic_notif_security)
            .setColor(0xFF1FA122.toInt())
            .setContentTitle(title)
            .setContentText(text)
            .setStyle(NotificationCompat.BigTextStyle().bigText(text))
            .setOngoing(true)
            .setOnlyAlertOnce(true)
            .setSilent(true)
            .setPriority(NotificationCompat.PRIORITY_LOW)
            .setProgress(if (totalUid <= 0) 1 else totalUid, processed, totalUid <= 0)
            .build()
        NotificationManagerCompat.from(context).notify(applyProgressId, notif)
    }

    fun clearApplyProgress(context: Context) {
        NotificationManagerCompat.from(context).cancel(applyProgressId)
    }

    fun postApplyResult(context: Context, success: Boolean, content: String, id: Int = 105) {
        if (!isNotifGranted(context)) return
        val notif = NotificationCompat.Builder(context, eventChannelId)
            .setSmallIcon(R.drawable.ic_notif_security)
            .setColor(0xFF1FA122.toInt())
            .setContentTitle("Firewall Agent")
            .setContentText(content)
            .setStyle(NotificationCompat.BigTextStyle().bigText(content))
            .setPriority(if (success) NotificationCompat.PRIORITY_DEFAULT else NotificationCompat.PRIORITY_HIGH)
            .setAutoCancel(true)
            .build()
        NotificationManagerCompat.from(context).notify(id, notif)
    }

    private fun isNotifGranted(context: Context): Boolean {
        if (Build.VERSION.SDK_INT >= 33) {
            val granted = ContextCompat.checkSelfPermission(
                context,
                Manifest.permission.POST_NOTIFICATIONS,
            ) == PackageManager.PERMISSION_GRANTED
            if (!granted) return false
        }
        return true
    }
}
