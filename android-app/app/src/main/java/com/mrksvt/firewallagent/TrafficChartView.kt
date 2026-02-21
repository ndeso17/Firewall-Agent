package com.mrksvt.firewallagent

import android.content.Context
import android.graphics.Canvas
import android.graphics.Color
import android.graphics.Paint
import android.graphics.Path
import android.util.AttributeSet
import android.view.View
import kotlin.math.max

class TrafficChartView @JvmOverloads constructor(
    context: Context,
    attrs: AttributeSet? = null,
) : View(context, attrs) {
    private val maxPoints = 60
    private val rxSeries = ArrayDeque<Float>()
    private val txSeries = ArrayDeque<Float>()
    private var sourceLabel = "WiFi"

    private val gridPaint = Paint(Paint.ANTI_ALIAS_FLAG).apply {
        color = Color.parseColor("#334155")
        strokeWidth = 1f
        style = Paint.Style.STROKE
    }
    private val axisPaint = Paint(Paint.ANTI_ALIAS_FLAG).apply {
        color = Color.parseColor("#64748B")
        strokeWidth = 1.5f
        style = Paint.Style.STROKE
    }
    private val labelPaint = Paint(Paint.ANTI_ALIAS_FLAG).apply {
        color = Color.parseColor("#CBD5E1")
        textSize = 22f
    }
    private val rxPaint = Paint(Paint.ANTI_ALIAS_FLAG).apply {
        color = Color.parseColor("#22D3EE")
        strokeWidth = 3.5f
        style = Paint.Style.STROKE
    }
    private val txPaint = Paint(Paint.ANTI_ALIAS_FLAG).apply {
        color = Color.parseColor("#22C55E")
        strokeWidth = 3.5f
        style = Paint.Style.STROKE
    }

    fun setSourceLabel(label: String) {
        sourceLabel = label
        applySourcePalette(label)
        invalidate()
    }

    fun resetSeries() {
        rxSeries.clear()
        txSeries.clear()
        invalidate()
    }

    fun pushPoint(rx: Float, tx: Float) {
        append(rxSeries, rx)
        append(txSeries, tx)
        postInvalidateOnAnimation()
    }

    private fun append(target: ArrayDeque<Float>, value: Float) {
        target.addLast(max(0f, value))
        while (target.size > maxPoints) target.removeFirst()
    }

    override fun onDraw(canvas: Canvas) {
        super.onDraw(canvas)
        if (width <= 0 || height <= 0) return

        val plotLeft = 60f
        val plotTop = 10f
        val plotRight = width.toFloat() - 12f
        val plotBottom = height.toFloat() - 32f
        val plotHeight = plotBottom - plotTop

        val maxY = max(
            16f,
            max(
                rxSeries.maxOrNull() ?: 0f,
                txSeries.maxOrNull() ?: 0f,
            ),
        )

        for (i in 0..4) {
            val y = plotTop + (plotHeight * i / 4f)
            canvas.drawLine(plotLeft, y, plotRight, y, gridPaint)
            val v = maxY * ((4 - i) / 4f)
            canvas.drawText(formatAxis(v), 2f, y + 6f, labelPaint)
        }
        canvas.drawLine(plotLeft, plotBottom, plotRight, plotBottom, axisPaint)
        canvas.drawLine(plotLeft, plotTop, plotLeft, plotBottom, axisPaint)

        canvas.drawText("$sourceLabel (Download & Upload)", plotLeft + 10f, height - 8f, labelPaint)

        drawSeries(canvas, rxSeries, rxPaint, maxY, plotLeft, plotRight, plotTop, plotBottom)
        drawSeries(canvas, txSeries, txPaint, maxY, plotLeft, plotRight, plotTop, plotBottom)
    }

    private fun drawSeries(
        canvas: Canvas,
        series: ArrayDeque<Float>,
        paint: Paint,
        maxY: Float,
        left: Float,
        right: Float,
        top: Float,
        bottom: Float,
    ) {
        if (series.size < 2) return
        val path = Path()
        val step = (right - left) / (maxPoints - 1).toFloat()
        val h = bottom - top
        series.forEachIndexed { idx, value ->
            val x = left + (idx * step)
            val y = bottom - ((value / maxY).coerceIn(0f, 1f) * h)
            if (idx == 0) path.moveTo(x, y) else path.lineTo(x, y)
        }
        canvas.drawPath(path, paint)
    }

    private fun formatAxis(kbPerSec: Float): String {
        if (kbPerSec < 1024f) return "${kbPerSec.toInt()}KB"
        val mb = kbPerSec / 1024f
        if (mb < 1024f) return String.format("%.1fMB", mb)
        return String.format("%.2fGB", mb / 1024f)
    }

    private fun applySourcePalette(label: String) {
        when (label.lowercase()) {
            "wifi" -> {
                rxPaint.color = Color.parseColor("#22D3EE")
                txPaint.color = Color.parseColor("#22C55E")
            }
            "seluler" -> {
                rxPaint.color = Color.parseColor("#F59E0B")
                txPaint.color = Color.parseColor("#F97316")
            }
            "vpn" -> {
                rxPaint.color = Color.parseColor("#A78BFA")
                txPaint.color = Color.parseColor("#C084FC")
            }
            "lan" -> {
                rxPaint.color = Color.parseColor("#10B981")
                txPaint.color = Color.parseColor("#14B8A6")
            }
            "tor" -> {
                rxPaint.color = Color.parseColor("#EAB308")
                txPaint.color = Color.parseColor("#84CC16")
            }
            else -> {
                rxPaint.color = Color.parseColor("#22D3EE")
                txPaint.color = Color.parseColor("#22C55E")
            }
        }
    }
}
