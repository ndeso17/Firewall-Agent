package com.mrksvt.firewallagent

import android.os.Bundle
import android.widget.ArrayAdapter
import android.widget.Spinner
import androidx.appcompat.app.AppCompatActivity
import com.mrksvt.firewallagent.databinding.ActivityModelUpdateBinding
import org.json.JSONObject

class ModelUpdateActivity : AppCompatActivity() {
    private lateinit var binding: ActivityModelUpdateBinding

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        binding = ActivityModelUpdateBinding.inflate(layoutInflater)
        setContentView(binding.root)

        binding.reloadBtn.setOnClickListener { loadConfig() }
        binding.saveBtn.setOnClickListener { saveConfig() }
        loadConfig()
    }

    private fun loadConfig() {
        val cfg = AppConfigStore.loadModelUpdate(this)
        binding.manifestUrlInput.setText(cfg.optString("manifest_url", ""))
        binding.onnxUrlInput.setText(cfg.optString("onnx_url", ""))
        setSpinnerValue(binding.channelSpinner, cfg.optString("channel", "stable"))
        binding.autoUpdateCheck.isChecked = cfg.optBoolean("auto_update", false)
        binding.intervalInput.setText(cfg.optInt("check_interval_minutes", 60).toString())
        binding.outputText.text = "Loaded model update config."
    }

    private fun saveConfig() {
        val data = JSONObject()
            .put("manifest_url", binding.manifestUrlInput.text?.toString()?.trim().orEmpty())
            .put("onnx_url", binding.onnxUrlInput.text?.toString()?.trim().orEmpty())
            .put("channel", binding.channelSpinner.selectedItem.toString())
            .put("auto_update", binding.autoUpdateCheck.isChecked)
            .put("check_interval_minutes", binding.intervalInput.text?.toString()?.toIntOrNull() ?: 60)
        AppConfigStore.saveModelUpdate(this, data)
        binding.outputText.text = "Saved model update config locally.\n${data.toString(2)}"
    }

    private fun setSpinnerValue(spinner: Spinner, value: String) {
        val adapter = spinner.adapter as? ArrayAdapter<*> ?: return
        for (i in 0 until adapter.count) {
            if (adapter.getItem(i).toString().equals(value, ignoreCase = true)) {
                spinner.setSelection(i)
                return
            }
        }
    }
}
