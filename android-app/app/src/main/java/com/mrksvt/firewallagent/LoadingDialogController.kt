package com.mrksvt.firewallagent

import androidx.appcompat.app.AlertDialog
import androidx.appcompat.app.AppCompatActivity
import androidx.compose.animation.core.LinearOutSlowInEasing
import androidx.compose.animation.core.animateFloatAsState
import androidx.compose.animation.core.tween
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.material3.Button
import androidx.compose.material3.CircularProgressIndicator
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Surface
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.MutableState
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.ui.Alignment
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.platform.ComposeView
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import kotlin.math.roundToInt

data class LoadingProgressModel(
    val title: String,
    val processed: Int,
    val total: Int,
    val phase: String,
)

@Composable
private fun LoadingProgressContent(progress: LoadingProgressModel) {
    val safeTotal = if (progress.total <= 0) 1 else progress.total
    val targetProgress = (progress.processed.toFloat() / safeTotal.toFloat()).coerceIn(0f, 1f)
    val percent = (targetProgress * 100f).roundToInt().coerceIn(0, 100)
    val animatedProgress by animateFloatAsState(
        targetValue = targetProgress,
        animationSpec = tween(durationMillis = 220, easing = LinearOutSlowInEasing),
        label = "generic_loading_progress",
    )

    Column(
        modifier = androidx.compose.ui.Modifier.fillMaxWidth(),
        horizontalAlignment = Alignment.CenterHorizontally,
        verticalArrangement = Arrangement.Center,
    ) {
        Surface(
            color = Color(0xFF1F2430),
            tonalElevation = 2.dp,
            shadowElevation = 6.dp,
        ) {
            Column(
                modifier = androidx.compose.ui.Modifier
                    .fillMaxWidth()
                    .padding(horizontal = 20.dp, vertical = 18.dp),
                horizontalAlignment = Alignment.CenterHorizontally,
                verticalArrangement = Arrangement.Center,
            ) {
                Text(
                    text = progress.title,
                    fontSize = 30.sp,
                    fontWeight = FontWeight.Bold,
                    color = Color(0xFFFFFFFF),
                )
                Spacer(modifier = androidx.compose.ui.Modifier.height(14.dp))
                Box(contentAlignment = Alignment.Center) {
                    CircularProgressIndicator(
                        progress = { animatedProgress },
                        strokeWidth = 8.dp,
                        color = Color(0xFF22C55E),
                        trackColor = Color(0xFF3B4252),
                        modifier = androidx.compose.ui.Modifier.size(112.dp),
                    )
                    Text(
                        text = if (percent >= 100) "✓" else "$percent%",
                        fontSize = 20.sp,
                        fontWeight = FontWeight.SemiBold,
                        color = if (percent >= 100) Color(0xFF22C55E) else Color(0xFFFFFFFF),
                    )
                }
                Spacer(modifier = androidx.compose.ui.Modifier.height(14.dp))
                Text(
                    text = progress.phase,
                    fontSize = 14.sp,
                    color = Color(0xFFFFFFFF),
                )
            }
        }
    }
}

@Composable
private fun LoadingSuccessContent(title: String, message: String, onOk: () -> Unit) {
    Surface(
        color = Color(0xFF1F2430),
        tonalElevation = 2.dp,
        shadowElevation = 6.dp,
    ) {
        Column(
            modifier = androidx.compose.ui.Modifier
                .fillMaxWidth()
                .padding(horizontal = 20.dp, vertical = 18.dp),
            horizontalAlignment = Alignment.CenterHorizontally,
            verticalArrangement = Arrangement.Center,
        ) {
            Text(
                text = "✓",
                fontSize = 38.sp,
                fontWeight = FontWeight.Bold,
                color = Color(0xFF22C55E),
            )
            Spacer(modifier = androidx.compose.ui.Modifier.height(8.dp))
            Text(
                text = title,
                fontSize = 24.sp,
                fontWeight = FontWeight.Bold,
                color = Color(0xFFFFFFFF),
            )
            Spacer(modifier = androidx.compose.ui.Modifier.height(8.dp))
            Text(
                text = message,
                fontSize = 14.sp,
                color = Color(0xFFFFFFFF),
            )
            Spacer(modifier = androidx.compose.ui.Modifier.height(16.dp))
            Button(onClick = onOk) {
                Text("OK")
            }
        }
    }
}

class LoadingDialogController(private val activity: AppCompatActivity) {
    private var progressDialog: AlertDialog? = null
    private var progressState: MutableState<LoadingProgressModel>? = null

    fun showProgress(title: String, processed: Int, total: Int, phase: String) {
        if (progressDialog == null) {
            val state = mutableStateOf(
                LoadingProgressModel(
                    title = title,
                    processed = processed,
                    total = total,
                    phase = phase,
                ),
            )
            progressState = state
            val content = ComposeView(activity).apply {
                setContent {
                    MaterialTheme {
                        LoadingProgressContent(state.value)
                    }
                }
            }
            progressDialog = AlertDialog.Builder(activity)
                .setView(content)
                .setCancelable(false)
                .create()
            progressDialog?.show()
            return
        }
        updateProgress(title, processed, total, phase)
    }

    fun updateProgress(title: String, processed: Int, total: Int, phase: String) {
        progressState?.value = LoadingProgressModel(
            title = title,
            processed = processed,
            total = total,
            phase = phase,
        )
    }

    fun dismissProgress() {
        progressDialog?.dismiss()
        progressDialog = null
        progressState = null
    }

    fun showSuccess(title: String, message: String) {
        var dialogRef: AlertDialog? = null
        val content = ComposeView(activity).apply {
            setContent {
                MaterialTheme {
                    LoadingSuccessContent(
                        title = title,
                        message = message,
                    ) {
                        dialogRef?.dismiss()
                    }
                }
            }
        }
        val dialog = AlertDialog.Builder(activity)
            .setView(content)
            .setCancelable(false)
            .create()
        dialogRef = dialog
        dialog.show()
    }
}
