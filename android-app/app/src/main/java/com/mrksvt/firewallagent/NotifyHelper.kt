package com.mrksvt.firewallagent

import android.Manifest
import android.app.NotificationManager
import android.app.PendingIntent
import android.app.Notification
import android.app.NotificationChannel
import android.media.AudioAttributes
import android.media.RingtoneManager
import android.net.Uri
import android.content.Context
import android.content.Intent
import android.content.pm.PackageManager
import android.os.Build
import androidx.core.app.NotificationCompat
import androidx.core.app.NotificationManagerCompat
import androidx.core.content.ContextCompat
import java.util.concurrent.ConcurrentHashMap

object NotifyHelper {
    private const val statusChannelId = "fw_agent_root_status"
    private const val eventChannelId = "fw_agent_root_event"
    private const val eventMalwareChannelId = "fw_agent_root_event_malware"
    private const val eventTrafficChannelId = "fw_agent_root_event_traffic"
    private const val eventCallChannelId = "fw_agent_root_event_call"
    private const val eventDnsChannelId = "fw_agent_root_event_dns"
    private const val persistentId = 9001
    private const val applyProgressId = 9002
    private val lastPostAtById = ConcurrentHashMap<Int, Long>()
    private val lastPayloadById = ConcurrentHashMap<Int, String>()
    private const val minPostIntervalMs = 1500L
    private const val samePayloadTtlMs = 90_000L

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
        eventChannel.setSound(
            RingtoneManager.getDefaultUri(RingtoneManager.TYPE_NOTIFICATION),
            buildAudioAttrs(),
        )
        manager.createNotificationChannel(eventChannel)

        val malwareChannel = NotificationChannel(
            eventMalwareChannelId,
            "Firewall Agent - Malware Threat",
            NotificationManager.IMPORTANCE_HIGH,
        )
        malwareChannel.setShowBadge(true)
        malwareChannel.setSound(
            RingtoneManager.getDefaultUri(RingtoneManager.TYPE_ALARM),
            buildAudioAttrs(),
        )
        manager.createNotificationChannel(malwareChannel)

        val trafficChannel = NotificationChannel(
            eventTrafficChannelId,
            "Firewall Agent - Traffic Anomaly",
            NotificationManager.IMPORTANCE_HIGH,
        )
        trafficChannel.setShowBadge(true)
        trafficChannel.setSound(
            RingtoneManager.getDefaultUri(RingtoneManager.TYPE_NOTIFICATION),
            buildAudioAttrs(),
        )
        manager.createNotificationChannel(trafficChannel)

        val callChannel = NotificationChannel(
            eventCallChannelId,
            "Firewall Agent - Call Threat",
            NotificationManager.IMPORTANCE_HIGH,
        )
        callChannel.setShowBadge(true)
        callChannel.setSound(
            RingtoneManager.getDefaultUri(RingtoneManager.TYPE_RINGTONE),
            buildAudioAttrs(),
        )
        manager.createNotificationChannel(callChannel)

        val dnsChannel = NotificationChannel(
            eventDnsChannelId,
            "Firewall Agent - DNS Threat",
            NotificationManager.IMPORTANCE_HIGH,
        )
        dnsChannel.setShowBadge(true)
        dnsChannel.setSound(
            RingtoneManager.getDefaultUri(RingtoneManager.TYPE_NOTIFICATION),
            buildAudioAttrs(),
        )
        manager.createNotificationChannel(dnsChannel)
    }

    fun post(context: Context, title: String, content: String, id: Int) {
        if (!isNotifGranted(context)) return
        if (id == persistentId) return // protect persistent foreground notification path

        val channelId = selectThreatChannel(title, content)
        if (!shouldPost(id, "$channelId|$title|$content")) return
        val notif = NotificationCompat.Builder(context, channelId)
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
        val channelId = selectThreatChannel("Aplikasi baru terdeteksi", content)
        val id = ((System.currentTimeMillis() % 100000) + 20000).toInt()
        if (!shouldPost(id, "$channelId|new-app|$packageName|$content")) return
        val notif = NotificationCompat.Builder(context, channelId)
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
        if (id == persistentId) return
        val channelId = selectThreatChannel("Apply Result", content)
        if (!shouldPost(id, "$channelId|apply-result|$success|$content")) return
        val notif = NotificationCompat.Builder(context, channelId)
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

    private fun shouldPost(id: Int, payload: String): Boolean {
        val now = System.currentTimeMillis()
        val lastAt = lastPostAtById[id] ?: 0L
        val lastPayload = lastPayloadById[id]
        val tooFrequent = (now - lastAt) < minPostIntervalMs
        val samePayloadWithinTtl = lastPayload == payload && (now - lastAt) < samePayloadTtlMs
        if (tooFrequent || samePayloadWithinTtl) return false
        lastPostAtById[id] = now
        lastPayloadById[id] = payload
        return true
    }

    private fun buildAudioAttrs(): AudioAttributes {
        return AudioAttributes.Builder()
            .setUsage(AudioAttributes.USAGE_NOTIFICATION_EVENT)
            .setContentType(AudioAttributes.CONTENT_TYPE_SONIFICATION)
            .build()
    }

    private fun soundForChannel(channelId: String): Uri {
        return when (channelId) {
            eventMalwareChannelId -> RingtoneManager.getDefaultUri(RingtoneManager.TYPE_ALARM)
            eventCallChannelId -> RingtoneManager.getDefaultUri(RingtoneManager.TYPE_RINGTONE)
            eventTrafficChannelId, eventDnsChannelId, eventChannelId ->
                RingtoneManager.getDefaultUri(RingtoneManager.TYPE_NOTIFICATION)
            else -> RingtoneManager.getDefaultUri(RingtoneManager.TYPE_NOTIFICATION)
        }
    }

    private fun selectThreatChannel(title: String, content: String): String {
        val text = "${title.lowercase()} ${content.lowercase()}"
        return when {
            text.contains("trojan") ||
                text.contains("ransom") ||
                text.contains("spyware") ||
                text.contains("malware") ||
                text.contains("virus") -> eventMalwareChannelId
            text.contains("call") ||
                text.contains("panggilan") ||
                text.contains("unknown number") -> eventCallChannelId
            text.contains("dns") ||
                text.contains("doh") ||
                text.contains("private dns") -> eventDnsChannelId
            text.contains("anomaly") ||
                text.contains("anomali") ||
                text.contains("ml-traffic") ||
                text.contains("traffic") ||
                text.contains("blocked host") -> eventTrafficChannelId
            else -> eventChannelId
        }
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
