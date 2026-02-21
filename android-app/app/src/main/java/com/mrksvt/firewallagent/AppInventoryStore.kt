package com.mrksvt.firewallagent

import android.content.Context
import android.content.pm.PackageManager
import android.os.Build
import org.json.JSONObject

object AppInventoryStore {
    private const val PREF = "fw_app_inventory"
    private const val KEY_JSON = "apps_json"
    private const val KEY_VERSION = "apps_version"

    fun read(context: Context): Map<String, Int> {
        val raw = context.getSharedPreferences(PREF, Context.MODE_PRIVATE)
            .getString(KEY_JSON, "{}")
            .orEmpty()
        return try {
            val j = JSONObject(raw)
            buildMap {
                j.keys().forEach { pkg ->
                    val uid = j.optInt(pkg, -1)
                    if (uid > 0) put(pkg, uid)
                }
            }
        } catch (_: Throwable) {
            emptyMap()
        }
    }

    fun version(context: Context): Long {
        return context.getSharedPreferences(PREF, Context.MODE_PRIVATE)
            .getLong(KEY_VERSION, 0L)
    }

    fun refreshSnapshot(context: Context) {
        val pm = context.packageManager
        val packages = if (Build.VERSION.SDK_INT >= 33) {
            pm.getInstalledPackages(PackageManager.PackageInfoFlags.of(0))
        } else {
            @Suppress("DEPRECATION")
            pm.getInstalledPackages(0)
        }
        val obj = JSONObject()
        packages.forEach { pi ->
            val pkg = pi.packageName.orEmpty()
            val uid = pi.applicationInfo?.uid ?: -1
            if (pkg.isNotBlank() && uid > 0) obj.put(pkg, uid)
        }
        save(context, obj)
    }

    fun upsert(context: Context, pkg: String, uid: Int) {
        if (pkg.isBlank() || uid <= 0) return
        val obj = JSONObject(
            context.getSharedPreferences(PREF, Context.MODE_PRIVATE)
                .getString(KEY_JSON, "{}")
                .orEmpty(),
        )
        obj.put(pkg, uid)
        save(context, obj)
    }

    fun remove(context: Context, pkg: String) {
        if (pkg.isBlank()) return
        val obj = JSONObject(
            context.getSharedPreferences(PREF, Context.MODE_PRIVATE)
                .getString(KEY_JSON, "{}")
                .orEmpty(),
        )
        obj.remove(pkg)
        save(context, obj)
    }

    private fun save(context: Context, obj: JSONObject) {
        context.getSharedPreferences(PREF, Context.MODE_PRIVATE)
            .edit()
            .putString(KEY_JSON, obj.toString())
            .putLong(KEY_VERSION, System.currentTimeMillis())
            .apply()
    }
}

