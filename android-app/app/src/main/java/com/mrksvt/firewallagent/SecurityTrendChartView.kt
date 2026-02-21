package com.mrksvt.firewallagent

import android.content.Context
import android.graphics.Canvas
import android.graphics.Color
import android.graphics.Paint
import android.graphics.Path
import android.util.AttributeSet
import android.view.View
import kotlin.math.max

class SecurityTrendChartView @JvmOverloads constructor(
    context: Context,
    attrs: AttributeSet? = null,
) : View(context, attrs) {
    private var series: List<Float> = emptyList()
    private var startLabel: String = ""
    private var endLabel: String = ""
    private var unitLabel: String = "count"

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
    private val linePaint = Paint(Paint.ANTI_ALIAS_FLAG).apply {
        color = Color.parseColor("#22C55E")
        strokeWidth = 4f
        style = Paint.Style.STROKE
    }

    fun setData(
        values: List<Float>,
        startText: String,
        endText: String,
        unit: String,
        colorHex: String,
    ) {
        series = values.ifEmpty { listOf(0f, 0f) }
        startLabel = startText
        endLabel = endText
        unitLabel = unit
        runCatching { linePaint.color = Color.parseColor(colorHex) }
        invalidate()
    }

    override fun onDraw(canvas: Canvas) {
        super.onDraw(canvas)
        if (width <= 0 || height <= 0) return

        val plotLeft = 64f
        val plotTop = 16f
        val plotRight = width.toFloat() - 16f
        val plotBottom = height.toFloat() - 36f
        val plotHeight = plotBottom - plotTop

        val maxY = max(1f, series.maxOrNull() ?: 1f)

        for (i in 0..4) {
            val y = plotTop + (plotHeight * i / 4f)
            canvas.drawLine(plotLeft, y, plotRight, y, gridPaint)
            val v = maxY * ((4 - i) / 4f)
            canvas.drawText(formatAxis(v), 2f, y + 6f, labelPaint)
        }
        canvas.drawLine(plotLeft, plotBottom, plotRight, plotBottom, axisPaint)
        canvas.drawLine(plotLeft, plotTop, plotLeft, plotBottom, axisPaint)

        canvas.drawText(startLabel, plotLeft + 6f, height - 8f, labelPaint)
        val endX = plotRight - labelPaint.measureText(endLabel) - 4f
        canvas.drawText(endLabel, endX, height - 8f, labelPaint)

        drawSeries(canvas, maxY, plotLeft, plotRight, plotTop, plotBottom)
    }

    private fun drawSeries(
        canvas: Canvas,
        maxY: Float,
        left: Float,
        right: Float,
        top: Float,
        bottom: Float,
    ) {
        if (series.size < 2) return
        val path = Path()
        val step = (right - left) / (series.size - 1).toFloat()
        val h = bottom - top
        series.forEachIndexed { idx, value ->
            val x = left + (idx * step)
            val y = bottom - ((value / maxY).coerceIn(0f, 1f) * h)
            if (idx == 0) path.moveTo(x, y) else path.lineTo(x, y)
        }
        canvas.drawPath(path, linePaint)
    }

    private fun formatAxis(v: Float): String {
        return if (unitLabel == "count") {
            v.toInt().toString()
        } else {
            "${v.toInt()} $unitLabel"
        }
    }
}

