package com.mrksvt.firewallagent

import android.view.LayoutInflater
import android.view.View
import android.view.ViewGroup
import android.widget.TextView
import androidx.core.content.ContextCompat
import androidx.recyclerview.widget.RecyclerView

class EvilTwinAdapter(
    private val items: List<EvilTwinNetwork>,
    private val onClick: (EvilTwinNetwork) -> Unit
) : RecyclerView.Adapter<EvilTwinAdapter.ViewHolder>() {

    class ViewHolder(itemView: View) : RecyclerView.ViewHolder(itemView) {
        val tvSsid: TextView = itemView.findViewById(R.id.tvSsid)
        val tvBssid: TextView = itemView.findViewById(R.id.tvBssid)
        val tvThreat: TextView = itemView.findViewById(R.id.tvThreat)
        val tvReason: TextView = itemView.findViewById(R.id.tvReason)
    }

    override fun onCreateViewHolder(parent: ViewGroup, viewType: Int): ViewHolder {
        val view = LayoutInflater.from(parent.context)
            .inflate(R.layout.item_evil_twin_network, parent, false)
        return ViewHolder(view)
    }

    override fun onBindViewHolder(holder: ViewHolder, position: Int) {
        val item = items[position]
        holder.tvSsid.text = item.ssid
        holder.tvBssid.text = "BSSID: ${item.bssid}"
        holder.tvThreat.text = "Threat: ${item.threatLevel}"
        holder.tvReason.text = if (item.reason.isNotBlank()) {
            "Reason: ${item.reason}"
        } else {
            "Reason: -"
        }

        val colorRes = when (item.threatLevel) {
            ThreatLevel.LOW -> android.R.color.holo_green_dark
            ThreatLevel.MEDIUM -> android.R.color.holo_orange_light
            ThreatLevel.HIGH -> android.R.color.holo_orange_dark
            ThreatLevel.CRITICAL -> android.R.color.holo_red_dark
        }
        holder.tvThreat.setTextColor(ContextCompat.getColor(holder.itemView.context, colorRes))

        holder.itemView.setOnClickListener { onClick(item) }
    }

    override fun getItemCount(): Int = items.size
}
