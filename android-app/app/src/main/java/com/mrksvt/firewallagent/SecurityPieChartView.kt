package com.mrksvt.firewallagent

import android.content.Context
import android.graphics.Canvas
import android.graphics.Color
import android.graphics.Paint
import android.graphics.RectF
import android.util.AttributeSet
import android.view.View
import kotlin.math.min

class SecurityPieChartView @JvmOverloads constructor(
    context: Context,
    attrs: AttributeSet? = null,
) : View(context, attrs) {
    data class Slice(val label: String, val value: Float, val colorHex: String)

    private var slices: List<Slice> = emptyList()
    private var centerText: String = "-"

    private val arcPaint = Paint(Paint.ANTI_ALIAS_FLAG).apply {
        style = Paint.Style.FILL
    }
    private val labelPaint = Paint(Paint.ANTI_ALIAS_FLAG).apply {
        color = Color.parseColor("#CBD5E1")
        textSize = 24f
    }
    private val centerPaint = Paint(Paint.ANTI_ALIAS_FLAG).apply {
        color = Color.parseColor("#E5E7EB")
        textSize = 28f
        textAlign = Paint.Align.CENTER
    }
    private val bgPaint = Paint(Paint.ANTI_ALIAS_FLAG).apply {
        style = Paint.Style.FILL
        color = Color.parseColor("#1E293B")
    }

    fun setData(items: List<Slice>, center: String) {
        slices = items.filter { it.value > 0f }
        centerText = center
        invalidate()
    }

    override fun onDraw(canvas: Canvas) {
        super.onDraw(canvas)
        if (width <= 0 || height <= 0) return

        val legendTop = 16f
        val legendLeft = 16f
        val legendGap = 30f
        val pieTop = legendTop + (legendGap * 3f) + 12f
        val pieSize = min(width.toFloat() - 32f, height.toFloat() - pieTop - 12f)
        if (pieSize <= 20f) return

        val rect = RectF(16f, pieTop, 16f + pieSize, pieTop + pieSize)

        if (slices.isEmpty()) {
            canvas.drawArc(rect, 0f, 360f, true, bgPaint)
            canvas.drawText(centerText, rect.centerX(), rect.centerY() + 10f, centerPaint)
            return
        }

        val total = slices.sumOf { it.value.toDouble() }.toFloat().coerceAtLeast(1f)
        var start = -90f
        slices.forEachIndexed { idx, s ->
            val sweep = if (idx == slices.lastIndex) {
                360f - (start + 90f)
            } else {
                (s.value / total) * 360f
            }
            runCatching { arcPaint.color = Color.parseColor(s.colorHex) }.onFailure {
                arcPaint.color = Color.parseColor("#22C55E")
            }
            canvas.drawArc(rect, start, sweep, true, arcPaint)
            start += sweep
        }

        canvas.drawCircle(rect.centerX(), rect.centerY(), pieSize * 0.34f, bgPaint)
        canvas.drawText(centerText, rect.centerX(), rect.centerY() + 10f, centerPaint)

        slices.forEachIndexed { i, s ->
            val y = legendTop + (i * legendGap)
            runCatching { arcPaint.color = Color.parseColor(s.colorHex) }.onFailure {
                arcPaint.color = Color.parseColor("#22C55E")
            }
            canvas.drawRect(legendLeft, y - 16f, legendLeft + 18f, y + 2f, arcPaint)
            canvas.drawText("${s.label}: ${s.value.toInt()}", legendLeft + 26f, y, labelPaint)
        }
    }
}

