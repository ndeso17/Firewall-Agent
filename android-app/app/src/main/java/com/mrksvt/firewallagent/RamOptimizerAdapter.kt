package com.mrksvt.firewallagent

import android.view.LayoutInflater
import android.view.ViewGroup
import androidx.recyclerview.widget.RecyclerView
import com.mrksvt.firewallagent.databinding.ItemRamOptimizerRowBinding

class RamOptimizerAdapter(
    private var items: List<RamOptimizerActivity.RamAppRow>,
    private val isChecked: (String) -> Boolean,
    private val onCheckedChanged: (RamOptimizerActivity.RamAppRow, Boolean) -> Unit,
) : RecyclerView.Adapter<RamOptimizerAdapter.VH>() {

    fun submit(newItems: List<RamOptimizerActivity.RamAppRow>) {
        items = newItems
        notifyDataSetChanged()
    }

    fun currentItems(): List<RamOptimizerActivity.RamAppRow> = items

    override fun onCreateViewHolder(parent: ViewGroup, viewType: Int): VH {
        val binding = ItemRamOptimizerRowBinding.inflate(
            LayoutInflater.from(parent.context),
            parent,
            false,
        )
        return VH(binding)
    }

    override fun getItemCount(): Int = items.size

    override fun onBindViewHolder(holder: VH, position: Int) {
        holder.bind(items[position], isChecked, onCheckedChanged)
    }

    class VH(private val binding: ItemRamOptimizerRowBinding) : RecyclerView.ViewHolder(binding.root) {
        fun bind(
            row: RamOptimizerActivity.RamAppRow,
            isChecked: (String) -> Boolean,
            onCheckedChanged: (RamOptimizerActivity.RamAppRow, Boolean) -> Unit,
        ) {
            binding.appName.text = row.appName
            binding.appPkg.text = row.packageName
            binding.appMeta.text = buildString {
                append(if (row.isRunning) "[RUNNING]" else "[IDLE]")
                append(" | RAM ")
                append(row.ramLabel)
                if (row.lastActionLabel.isNotBlank()) {
                    append(" | ")
                    append(row.lastActionLabel)
                }
                if (!row.selectable) {
                    append(" | LOCKED")
                }
            }
            if (row.icon != null) {
                binding.appIcon.setImageDrawable(row.icon)
            } else {
                binding.appIcon.setImageResource(android.R.drawable.sym_def_app_icon)
            }

            binding.selectCheck.setOnCheckedChangeListener(null)
            binding.selectCheck.isEnabled = row.selectable
            binding.selectCheck.alpha = if (row.selectable) 1.0f else 0.45f
            binding.selectCheck.isChecked = isChecked(row.packageName) && row.selectable
            binding.selectCheck.setOnCheckedChangeListener { _, checked ->
                onCheckedChanged(row, checked)
            }

            binding.root.alpha = if (row.selectable) 1.0f else 0.6f
            binding.root.setOnClickListener {
                if (!row.selectable) return@setOnClickListener
                val newState = !binding.selectCheck.isChecked
                binding.selectCheck.isChecked = newState
            }
        }
    }
}

