package com.mrksvt.firewallagent

import android.view.LayoutInflater
import android.view.ViewGroup
import androidx.recyclerview.widget.RecyclerView
import com.mrksvt.firewallagent.databinding.ItemAppRuleBinding

data class AppRuleEntry(
    val packageName: String,
    val appName: String,
    val uid: Int,
    val type: String,
    val installTime: Long,
    val icon: android.graphics.drawable.Drawable?,
    val perms: MutableMap<String, Boolean>,
)

class AppRulesAdapter(
    private var items: List<AppRuleEntry>,
    private val onPermChanged: (AppRuleEntry) -> Unit,
) : RecyclerView.Adapter<AppRulesAdapter.VH>() {

    fun submit(newItems: List<AppRuleEntry>) {
        items = newItems
        notifyDataSetChanged()
    }

    fun currentItems(): List<AppRuleEntry> = items

    override fun onCreateViewHolder(parent: ViewGroup, viewType: Int): VH {
        val binding = ItemAppRuleBinding.inflate(LayoutInflater.from(parent.context), parent, false)
        return VH(binding)
    }

    override fun onBindViewHolder(holder: VH, position: Int) {
        holder.bind(items[position], onPermChanged)
    }

    override fun getItemCount(): Int = items.size

    class VH(private val binding: ItemAppRuleBinding) : RecyclerView.ViewHolder(binding.root) {
        fun bind(item: AppRuleEntry, onPermChanged: (AppRuleEntry) -> Unit) {
            binding.appName.text = item.appName
            binding.appPkg.text = item.packageName
            if (item.icon != null) {
                binding.appIcon.setImageDrawable(item.icon)
            } else {
                binding.appIcon.setImageResource(android.R.drawable.sym_def_app_icon)
            }

            fun bindCheck(key: String, view: android.widget.CheckBox) {
                view.setOnCheckedChangeListener(null)
                view.isChecked = item.perms[key] == true
                view.setOnCheckedChangeListener { _, isChecked ->
                    item.perms[key] = isChecked
                    onPermChanged(item)
                }
            }

            bindCheck("local", binding.checkLocal)
            bindCheck("wifi", binding.checkWifi)
            bindCheck("cellular", binding.checkCell)
            bindCheck("roaming", binding.checkRoam)
            bindCheck("vpn", binding.checkVpn)
            bindCheck("bluetooth_tethering", binding.checkBt)
            bindCheck("tor", binding.checkTor)
            bindCheck("download", binding.checkDownload)
            bindCheck("upload", binding.checkUpload)
        }
    }
}
