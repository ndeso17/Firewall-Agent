package com.mrksvt.firewallagent

import android.content.Context
import android.content.pm.ApplicationInfo
import android.content.pm.PackageManager
import android.os.Build
import org.json.JSONArray
import org.json.JSONObject

data class CachedAppMeta(
    val packageName: String,
    val appName: String,
    val uid: Int,
    val type: String,
    val installTime: Long,
)

object AppMetaCacheStore {
    private const val PREF = "fw_app_meta_cache"
    private const val KEY_JSON = "apps_json"
    private const val KEY_VERSION = "apps_version"

    fun read(context: Context): List<CachedAppMeta> {
        val raw = context.getSharedPreferences(PREF, Context.MODE_PRIVATE)
            .getString(KEY_JSON, "[]")
            .orEmpty()
        return runCatching {
            val arr = JSONArray(raw)
            buildList {
                for (i in 0 until arr.length()) {
                    val o = arr.optJSONObject(i) ?: continue
                    val pkg = o.optString("pkg").trim()
                    val name = o.optString("name").trim().ifBlank { pkg }
                    val uid = o.optInt("uid", -1)
                    val type = o.optString("type").trim().ifBlank { "user" }
                    val install = o.optLong("install", 0L)
                    if (pkg.isNotBlank() && uid > 0) {
                        add(
                            CachedAppMeta(
                                packageName = pkg,
                                appName = name,
                                uid = uid,
                                type = type,
                                installTime = install,
                            ),
                        )
                    }
                }
            }
        }.getOrDefault(emptyList())
    }

    fun version(context: Context): Long {
        return context.getSharedPreferences(PREF, Context.MODE_PRIVATE).getLong(KEY_VERSION, 0L)
    }

    fun refreshSnapshot(context: Context) {
        val pm = context.packageManager
        val packages = if (Build.VERSION.SDK_INT >= 33) {
            pm.getInstalledPackages(PackageManager.PackageInfoFlags.of(0))
        } else {
            @Suppress("DEPRECATION")
            pm.getInstalledPackages(0)
        }

        val out = JSONArray()
        packages.forEach { pi ->
            val ai = pi.applicationInfo ?: return@forEach
            val pkg = pi.packageName.orEmpty().trim()
            val uid = ai.uid
            if (pkg.isBlank() || uid <= 0) return@forEach
            val name = ai.loadLabel(pm)?.toString()?.trim().orEmpty().ifBlank { pkg }
            val row = JSONObject()
            row.put("pkg", pkg)
            row.put("name", name)
            row.put("uid", uid)
            row.put("type", classifyType(ai, uid))
            row.put("install", pi.firstInstallTime)
            out.put(row)
        }
        save(context, out)
    }

    fun upsert(context: Context, pkg: String, uid: Int) {
        if (pkg.isBlank() || uid <= 0) return
        val now = read(context).associateBy { it.packageName }.toMutableMap()
        val pm = context.packageManager
        val ai = runCatching {
            if (Build.VERSION.SDK_INT >= 33) {
                pm.getApplicationInfo(pkg, PackageManager.ApplicationInfoFlags.of(0))
            } else {
                @Suppress("DEPRECATION")
                pm.getApplicationInfo(pkg, 0)
            }
        }.getOrNull()
        val name = ai?.loadLabel(pm)?.toString()?.trim().orEmpty().ifBlank { pkg }
        val type = if (ai != null) classifyType(ai, uid) else "user"
        val install = runCatching {
            if (Build.VERSION.SDK_INT >= 33) {
                pm.getPackageInfo(pkg, PackageManager.PackageInfoFlags.of(0)).firstInstallTime
            } else {
                @Suppress("DEPRECATION")
                pm.getPackageInfo(pkg, 0).firstInstallTime
            }
        }.getOrDefault(0L)

        now[pkg] = CachedAppMeta(pkg, name, uid, type, install)
        saveList(context, now.values.toList())
    }

    fun remove(context: Context, pkg: String) {
        if (pkg.isBlank()) return
        val next = read(context).filterNot { it.packageName == pkg }
        saveList(context, next)
    }

    private fun saveList(context: Context, list: List<CachedAppMeta>) {
        val arr = JSONArray()
        list.forEach { row ->
            val o = JSONObject()
            o.put("pkg", row.packageName)
            o.put("name", row.appName)
            o.put("uid", row.uid)
            o.put("type", row.type)
            o.put("install", row.installTime)
            arr.put(o)
        }
        save(context, arr)
    }

    private fun save(context: Context, arr: JSONArray) {
        context.getSharedPreferences(PREF, Context.MODE_PRIVATE)
            .edit()
            .putString(KEY_JSON, arr.toString())
            .putLong(KEY_VERSION, System.currentTimeMillis())
            .apply()
    }

    private fun classifyType(ai: ApplicationInfo, uid: Int): String {
        if (uid in 1000..1999) return "protected"
        if (uid < 10_000 || ai.packageName == "android") return "core"
        val systemFlag = (ai.flags and ApplicationInfo.FLAG_SYSTEM) != 0
        val updatedSystemFlag = (ai.flags and ApplicationInfo.FLAG_UPDATED_SYSTEM_APP) != 0
        return if (systemFlag || updatedSystemFlag) "system" else "user"
    }
}

