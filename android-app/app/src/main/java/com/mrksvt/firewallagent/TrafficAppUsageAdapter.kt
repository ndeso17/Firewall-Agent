package com.mrksvt.firewallagent

import android.view.LayoutInflater
import android.view.View
import android.view.ViewGroup
import android.widget.ImageView
import android.widget.TextView
import androidx.recyclerview.widget.RecyclerView

data class TrafficAppUsage(
    val uid: Int,
    val appName: String,
    val packageName: String,
    val downloadBytes: Long,
    val uploadBytes: Long,
    val icon: android.graphics.drawable.Drawable?,
)

class TrafficAppUsageAdapter(
    private val onDownloadClick: (TrafficAppUsage) -> Unit,
    private val onUploadClick: (TrafficAppUsage) -> Unit,
) : RecyclerView.Adapter<TrafficAppUsageAdapter.Holder>() {
    private val items = mutableListOf<TrafficAppUsage>()

    fun submitList(data: List<TrafficAppUsage>) {
        items.clear()
        items.addAll(data)
        notifyDataSetChanged()
    }

    override fun onCreateViewHolder(parent: ViewGroup, viewType: Int): Holder {
        val view = LayoutInflater.from(parent.context).inflate(R.layout.item_traffic_app, parent, false)
        return Holder(view, onDownloadClick, onUploadClick)
    }

    override fun getItemCount(): Int = items.size

    override fun onBindViewHolder(holder: Holder, position: Int) {
        holder.bind(items[position])
    }

    class Holder(
        itemView: View,
        private val onDownloadClick: (TrafficAppUsage) -> Unit,
        private val onUploadClick: (TrafficAppUsage) -> Unit,
    ) : RecyclerView.ViewHolder(itemView) {
        private val icon: ImageView = itemView.findViewById(R.id.appIcon)
        private val appName: TextView = itemView.findViewById(R.id.appName)
        private val appPkg: TextView = itemView.findViewById(R.id.appPkg)
        private val downloadIcon: ImageView = itemView.findViewById(R.id.downloadIcon)
        private val downloadText: TextView = itemView.findViewById(R.id.downloadText)
        private val uploadIcon: ImageView = itemView.findViewById(R.id.uploadIcon)
        private val uploadText: TextView = itemView.findViewById(R.id.uploadText)

        fun bind(item: TrafficAppUsage) {
            icon.setImageDrawable(item.icon)
            appName.text = item.appName
            appPkg.text = item.packageName
            downloadText.text = human(item.downloadBytes)
            uploadText.text = human(item.uploadBytes)
            downloadIcon.setOnClickListener { onDownloadClick(item) }
            downloadText.setOnClickListener { onDownloadClick(item) }
            uploadIcon.setOnClickListener { onUploadClick(item) }
            uploadText.setOnClickListener { onUploadClick(item) }
        }

        private fun human(v: Long): String {
            if (v < 1024L) return "${v}B"
            val kb = v / 1024.0
            if (kb < 1024.0) return String.format("%.1fKB", kb)
            val mb = kb / 1024.0
            if (mb < 1024.0) return String.format("%.1fMB", mb)
            return String.format("%.2fGB", mb / 1024.0)
        }
    }
}
