package com.mrksvt.firewallagent

import java.net.InetAddress
import java.nio.ByteBuffer
import java.nio.ByteOrder

data class EndpointUsage(
    val src: String,
    val dst: String,
    val download: Long,
    val upload: Long,
)

object TrafficEndpointInspector {
    fun readUidEndpointDetails(uid: Int): List<EndpointUsage> {
        val sockets = parseProcNetForUid(uid)
        if (sockets.isEmpty()) return emptyList()
        val conntrackMap = parseConntrackBytes()
        return sockets
            .groupBy { "${it.localIp}:${it.localPort}|${it.remoteIp}:${it.remotePort}|${it.proto}" }
            .map { (key, values) ->
                val sample = values.first()
                val revKey = "${sample.remoteIp}:${sample.remotePort}|${sample.localIp}:${sample.localPort}|${sample.proto}"
                val bytes = conntrackMap[key] ?: conntrackMap[revKey]
                EndpointUsage(
                    src = "${sample.localIp}:${sample.localPort}",
                    dst = "${sample.remoteIp}:${sample.remotePort}",
                    download = bytes?.first ?: 0L,
                    upload = bytes?.second ?: 0L,
                )
            }
    }

    private data class UidSocket(
        val proto: String,
        val localIp: String,
        val localPort: Int,
        val remoteIp: String,
        val remotePort: Int,
    )

    private fun parseProcNetForUid(uid: Int): List<UidSocket> {
        val cmd = """
            echo '##tcp'; cat /proc/net/tcp 2>/dev/null;
            echo '##tcp6'; cat /proc/net/tcp6 2>/dev/null;
            echo '##udp'; cat /proc/net/udp 2>/dev/null;
            echo '##udp6'; cat /proc/net/udp6 2>/dev/null;
        """.trimIndent()
        val out = RootFirewallController.runRaw(cmd).stdout
        if (out.isBlank()) return emptyList()
        val list = mutableListOf<UidSocket>()
        var proto = "tcp"
        out.lineSequence().forEach { line ->
            when {
                line.startsWith("##tcp6") -> { proto = "tcp6"; return@forEach }
                line.startsWith("##udp6") -> { proto = "udp6"; return@forEach }
                line.startsWith("##udp") -> { proto = "udp"; return@forEach }
                line.startsWith("##tcp") -> { proto = "tcp"; return@forEach }
                line.contains("local_address", ignoreCase = true) && line.contains("rem_address", ignoreCase = true) -> return@forEach
            }
            val p = line.trim().split(Regex("\\s+"))
            if (p.size < 8) return@forEach
            val local = p.getOrNull(1) ?: return@forEach
            val remote = p.getOrNull(2) ?: return@forEach
            val rowUid = p.getOrNull(7)?.toIntOrNull() ?: return@forEach
            if (rowUid != uid) return@forEach
            val localPair = decodeAddrPort(local) ?: return@forEach
            val remotePair = decodeAddrPort(remote) ?: return@forEach
            list += UidSocket(proto, localPair.first, localPair.second, remotePair.first, remotePair.second)
        }
        return list
    }

    private fun decodeAddrPort(encoded: String): Pair<String, Int>? {
        val parts = encoded.split(":")
        if (parts.size != 2) return null
        val ipHex = parts[0]
        val port = parts[1].toIntOrNull(16) ?: return null
        val ip = try {
            if (ipHex.length == 8) {
                val b = ByteBuffer.allocate(4).order(ByteOrder.LITTLE_ENDIAN).putInt(ipHex.toLong(16).toInt()).array()
                InetAddress.getByAddress(b).hostAddress ?: "0.0.0.0"
            } else if (ipHex.length == 32) {
                val bytes = ByteArray(16)
                for (i in 0 until 16) bytes[i] = ipHex.substring(i * 2, i * 2 + 2).toInt(16).toByte()
                InetAddress.getByAddress(bytes).hostAddress ?: "::"
            } else return null
        } catch (_: Throwable) {
            return null
        }
        return ip to port
    }

    private fun parseConntrackBytes(): Map<String, Pair<Long, Long>> {
        val out = RootFirewallController.runRaw("cat /proc/net/nf_conntrack /proc/net/ip_conntrack 2>/dev/null").stdout
        if (out.isBlank()) return emptyMap()
        val map = linkedMapOf<String, Pair<Long, Long>>()
        val srcRe = Regex("src=([^ ]+)")
        val dstRe = Regex("dst=([^ ]+)")
        val sportRe = Regex("sport=(\\d+)")
        val dportRe = Regex("dport=(\\d+)")
        val bytesRe = Regex("bytes=(\\d+)")
        out.lineSequence().forEach { line ->
            val srcAll = srcRe.findAll(line).map { it.groupValues[1] }.toList()
            val dstAll = dstRe.findAll(line).map { it.groupValues[1] }.toList()
            val sportAll = sportRe.findAll(line).map { it.groupValues[1] }.toList()
            val dportAll = dportRe.findAll(line).map { it.groupValues[1] }.toList()
            val bytesAll = bytesRe.findAll(line).map { it.groupValues[1].toLongOrNull() ?: 0L }.toList()
            if (srcAll.size < 2 || dstAll.size < 2 || sportAll.size < 2 || dportAll.size < 2 || bytesAll.size < 2) return@forEach
            val proto = if (line.contains("udp")) "udp" else "tcp"
            val key = "${srcAll[0]}:${sportAll[0]}|${dstAll[0]}:${dportAll[0]}|$proto"
            map[key] = (bytesAll.getOrNull(1) ?: 0L) to (bytesAll.firstOrNull() ?: 0L)
        }
        return map
    }
}
