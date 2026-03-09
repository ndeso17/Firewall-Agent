package com.mrksvt.firewallagent

import android.content.Context
import android.graphics.Bitmap
import android.graphics.Canvas
import android.graphics.drawable.Drawable
import android.graphics.drawable.BitmapDrawable
import android.util.Log
import androidx.core.graphics.createBitmap
import java.io.File
import java.io.FileOutputStream

object AppIconCacheStore {
    private const val TAG = "FA.AppIconCache"
    private const val DIR_NAME = "app_icon_cache"

    private fun iconDir(context: Context): File {
        val dir = File(context.filesDir, DIR_NAME)
        if (!dir.exists()) {
            dir.mkdirs()
        }
        return dir
    }

    private fun iconFile(context: Context, pkg: String): File {
        val safe = pkg.replace(Regex("[^a-zA-Z0-9._-]"), "_")
        return File(iconDir(context), "$safe.png")
    }

    fun save(context: Context, pkg: String, drawable: Drawable?) {
        if (pkg.isBlank() || drawable == null) return
        runCatching {
            val bmp = drawableToBitmap(drawable) ?: return
            val file = iconFile(context, pkg)
            FileOutputStream(file).use { out ->
                bmp.compress(Bitmap.CompressFormat.PNG, 100, out)
                out.flush()
            }
        }.onFailure {
            Log.w(TAG, "save icon failed for $pkg: ${it.message}")
        }
    }

    fun load(context: Context, pkg: String): Drawable? {
        if (pkg.isBlank()) return null
        val file = iconFile(context, pkg)
        if (!file.exists() || file.length() <= 0L) return null
        return runCatching {
            BitmapDrawable(context.resources, file.absolutePath)
        }.getOrNull()
    }

    fun remove(context: Context, pkg: String) {
        if (pkg.isBlank()) return
        runCatching {
            val file = iconFile(context, pkg)
            if (file.exists()) file.delete()
        }
    }

    private fun drawableToBitmap(drawable: Drawable): Bitmap? {
        if (drawable is BitmapDrawable && drawable.bitmap != null) {
            return drawable.bitmap
        }
        val w = drawable.intrinsicWidth.takeIf { it > 0 } ?: 96
        val h = drawable.intrinsicHeight.takeIf { it > 0 } ?: 96
        val bitmap = createBitmap(w, h)
        val canvas = Canvas(bitmap)
        drawable.setBounds(0, 0, canvas.width, canvas.height)
        drawable.draw(canvas)
        return bitmap
    }
}

