package com.mrksvt.firewallagent

import android.os.Bundle
import android.widget.ArrayAdapter
import android.widget.AdapterView
import androidx.appcompat.app.AppCompatActivity
import androidx.lifecycle.lifecycleScope
import com.mrksvt.firewallagent.databinding.ActivityAdguardBinding
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext
import java.net.InetSocketAddress
import java.net.Socket
import java.net.URI

class AdGuardActivity : AppCompatActivity() {
    private lateinit var binding: ActivityAdguardBinding
    private val adguardV4 = listOf("94.140.14.14", "94.140.15.15")
    private val adHostPatterns = listOf(
        "doubleclick.net",
        "googleads.g.doubleclick.net",
        "adservice.google.com",
        "adservice.google.",
        "googlesyndication.com",
        "admob.com",
        "app-measurement.com",
        "unityads.",
        "applovin.",
        "ironsource.",
        "startappservice.",
        "inmobi.",
        "mintegral.",
        "vungle.com",
        "chartboost.",
        "adsystem.",
        "ads.",
        "adnxs.com",
        "criteo.com",
    )
    private data class DnsProvider(
        val name: String,
        val dohUrl: String,
        val host: String,
        val detail: String,
        val probeIps: List<String> = emptyList(),
    )

    private val providers = listOf(
        DnsProvider(
            "Mullvad Base",
            "https://base.dns.mullvad.net/dns-query",
            "base.dns.mullvad.net",
            "Mullvad DNS standar, fokus privasi dan minim logging.",
            probeIps = listOf("194.242.2.2", "194.242.2.3"),
        ),
        DnsProvider(
            "Mullvad Family",
            "https://family.dns.mullvad.net/dns-query",
            "family.dns.mullvad.net",
            "Filter konten dewasa, cocok untuk perangkat keluarga/anak.",
            probeIps = listOf("194.242.2.4", "194.242.2.5"),
        ),
        DnsProvider(
            "Quad9 Primary",
            "https://dns.quad9.net/dns-query",
            "dns.quad9.net",
            "Blok domain berbahaya (malware/phishing) berbasis threat intel.",
            probeIps = listOf("9.9.9.9", "149.112.112.112"),
        ),
        DnsProvider(
            "Quad9 Alternate",
            "https://dns11.quad9.net/dns-query",
            "dns11.quad9.net",
            "Endpoint alternatif Quad9 dengan proteksi keamanan.",
            probeIps = listOf("9.9.9.11", "149.112.112.11"),
        ),
        DnsProvider(
            "DNS Guard",
            "https://dns.dnsguard.pub/dns-query",
            "dns.dnsguard.pub",
            "DNS fokus stabilitas + filtering dasar domain berisiko.",
        ),
        DnsProvider(
            "AdGuard Default",
            "https://dns.adguard-dns.com/dns-query",
            "dns.adguard-dns.com",
            "Blok iklan/tracker dengan dampak kecil ke kompatibilitas situs.",
            probeIps = listOf("94.140.14.14", "94.140.15.15"),
        ),
        DnsProvider(
            "AdGuard Family",
            "https://family.adguard-dns.com/dns-query",
            "family.adguard-dns.com",
            "AdGuard dengan family filter (dewasa + safe search).",
            probeIps = listOf("94.140.14.15", "94.140.15.16"),
        ),
        DnsProvider(
            "CleanBrowsing Family",
            "https://doh.cleanbrowsing.org/doh/family-filter/",
            "doh.cleanbrowsing.org",
            "Family filter ketat, blok konten dewasa + proxy/VPN tertentu.",
            probeIps = listOf("185.228.168.168", "185.228.169.168"),
        ),
        DnsProvider(
            "CleanBrowsing Security",
            "https://doh.cleanbrowsing.org/doh/security-filter/",
            "doh.cleanbrowsing.org",
            "Fokus blokir malware/phishing, konten umum tetap lebih longgar.",
            probeIps = listOf("185.228.168.9", "185.228.169.9"),
        ),
        DnsProvider(
            "Cloudflare Security",
            "https://security.cloudflare-dns.com/dns-query",
            "security.cloudflare-dns.com",
            "Cloudflare 1.1.1.2/1.0.0.2, proteksi malware/phishing.",
            probeIps = listOf("1.1.1.2", "1.0.0.2"),
        ),
    )
    private var latencyByHost: Map<String, Int> = emptyMap()

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        binding = ActivityAdguardBinding.inflate(layoutInflater)
        setContentView(binding.root)

        setupProviderSpinner()
        binding.dnsInput.setText(providers.firstOrNull()?.host ?: "dns.adguard-dns.com")
        binding.enableBtn.setOnClickListener { setPrivateDns(true) }
        binding.pingOneBtn.setOnClickListener { pingSelectedDns() }
        binding.disableBtn.setOnClickListener { setPrivateDns(false) }
        binding.firewallEnableBtn.setOnClickListener { setDnsFirewallLock(true) }
        binding.firewallDisableBtn.setOnClickListener { setDnsFirewallLock(false) }
        binding.reloadBtn.setOnClickListener { readCurrent() }
        binding.pingAllBtn.setOnClickListener { pingAllProviders(selectBest = false) }
        binding.autoBestBtn.setOnClickListener { pingAllProviders(selectBest = true) }
        pingAllProviders(selectBest = true)
        readCurrent()
    }

    private fun pingSelectedDns() {
        lifecycleScope.launch {
            val host = sanitizeHost(binding.dnsInput.text?.toString()?.trim().orEmpty())
            if (host.isBlank()) {
                binding.outputText.text = "Host DNS kosong. Pilih provider atau isi host dulu."
                return@launch
            }
            binding.outputText.text = "Ping DNS: $host ..."
            val selected = providers.firstOrNull { it.host == host }
            val ms = withContext(Dispatchers.IO) {
                if (selected != null) pingProviderMs(selected) else pingHostMs(host)
            }
            if (ms >= 0) {
                latencyByHost = latencyByHost.toMutableMap().apply { put(host, ms) }
                binding.outputText.text = "Ping DNS berhasil: $host (${ms} ms)"
                val selectedUi = providers.getOrNull(binding.dnsProviderSpinner.selectedItemPosition)
                if (selectedUi != null) updateProviderDetail(selectedUi)
            } else {
                binding.outputText.text = "Ping DNS gagal/timeout: $host\nCoba Disable Lock atau ganti jaringan dulu."
            }
        }
    }

    private fun setupProviderSpinner() {
        val labels = providers.map { "${it.name} (${it.host})" }
        val adapter = ArrayAdapter(this, android.R.layout.simple_spinner_item, labels)
        adapter.setDropDownViewResource(android.R.layout.simple_spinner_dropdown_item)
        binding.dnsProviderSpinner.adapter = adapter
        binding.dnsProviderSpinner.onItemSelectedListener = object : AdapterView.OnItemSelectedListener {
            override fun onItemSelected(parent: android.widget.AdapterView<*>?, view: android.view.View?, position: Int, id: Long) {
                val p = providers.getOrNull(position) ?: return
                binding.dnsInput.setText(p.host)
                updateProviderDetail(p)
            }

            override fun onNothingSelected(parent: android.widget.AdapterView<*>?) = Unit
        }
        providers.firstOrNull()?.let { updateProviderDetail(it) }
    }

    private fun updateProviderDetail(provider: DnsProvider) {
        val latency = latencyByHost[provider.host]?.let { "${it} ms" } ?: "n/a"
        binding.providerDetailText.text = buildString {
            appendLine(provider.detail)
            appendLine("DoH URL: ${provider.dohUrl}")
            append("Host Private DNS: ${provider.host} | Latency: $latency")
        }
    }

    private fun pingAllProviders(selectBest: Boolean) {
        lifecycleScope.launch {
            binding.latencyListText.text = "Mengukur latency DNS..."
            val pingResults = withContext(Dispatchers.IO) {
                providers.associate { p -> p.host to pingProviderMs(p) }
            }
            latencyByHost = pingResults.filterValues { it >= 0 }
            renderLatencyList(pingResults)

            val best = pingResults
                .filterValues { it >= 0 }
                .minByOrNull { it.value }

            if (best != null) {
                val bestProvider = providers.firstOrNull { it.host == best.key }
                binding.bestDnsText.text = "DNS tercepat: ${bestProvider?.name ?: best.key} (${best.key}) • ${best.value} ms"
                if (selectBest) {
                    val pos = providers.indexOfFirst { it.host == best.key }
                    if (pos >= 0) binding.dnsProviderSpinner.setSelection(pos)
                    binding.dnsInput.setText(best.key)
                    binding.outputText.text = "Default DNS diset ke latency terkecil: ${best.key} (${best.value} ms)"
                }
            } else {
                binding.bestDnsText.text = "DNS tercepat: tidak tersedia (ping gagal)."
                if (selectBest) {
                    binding.outputText.text = buildString {
                        appendLine("Gagal menentukan DNS tercepat (semua timeout).")
                        appendLine("Kemungkinan DNS aktif saat ini tidak reachable dari jaringan Anda.")
                        appendLine("Saran cepat:")
                        appendLine("1) Tekan 'Disable Lock'")
                        appendLine("2) Tekan 'Disable' (Private DNS off)")
                        appendLine("3) Coba 'Ping Semua DNS' lagi")
                    }
                }
            }

            val selected = providers.getOrNull(binding.dnsProviderSpinner.selectedItemPosition)
            if (selected != null) updateProviderDetail(selected)
        }
    }

    private fun renderLatencyList(results: Map<String, Int>) {
        binding.latencyListText.text = buildString {
            providers.forEach { p ->
                val ms = results[p.host]
                if (ms == null || ms < 0) {
                    appendLine("${p.name.padEnd(24)} ${p.host.padEnd(32)} timeout")
                } else {
                    appendLine("${p.name.padEnd(24)} ${p.host.padEnd(32)} ${ms} ms")
                }
            }
        }
    }

    private fun pingHostMs(host: String): Int {
        val rootMs = pingHostMsViaRoot(host)
        if (rootMs >= 0) return rootMs

        val samples = mutableListOf<Int>()
        val ports = intArrayOf(443, 853, 53)
        ports.forEach { port ->
            val ms = tcpConnectLatency(host, port, 1800)
            if (ms >= 0) samples += ms
        }
        if (samples.isEmpty()) return -1
        return samples.minOrNull() ?: -1
    }

    private fun pingHostMsViaRoot(host: String): Int {
        return try {
            RootFirewallController.init(this)
            if (!RootFirewallController.checkRoot()) return -1
            val safeHost = host.filter { it.isLetterOrDigit() || it == '.' || it == '-' }
            if (safeHost.isBlank()) return -1
            val cmd = "ping -c 1 -W 2 $safeHost 2>/dev/null | sed -n 's/.*time=\\([0-9.]*\\).*/\\1/p' | head -n 1"
            val out = RootFirewallController.runRaw(cmd).stdout.trim()
            if (out.isBlank()) -1 else out.substringBefore('.').toIntOrNull() ?: out.toFloatOrNull()?.toInt() ?: -1
        } catch (_: Throwable) {
            -1
        }
    }

    private fun pingProviderMs(provider: DnsProvider): Int {
        val fromHost = pingHostMs(provider.host)
        if (fromHost >= 0) return fromHost
        provider.probeIps.forEach { ip ->
            val ms = pingHostMs(ip)
            if (ms >= 0) return ms
        }
        return -1
    }

    private fun tcpConnectLatency(host: String, port: Int, timeoutMs: Int): Int {
        return try {
            val started = System.nanoTime()
            Socket().use { socket ->
                socket.connect(InetSocketAddress(host, port), timeoutMs)
            }
            val elapsedMs = (System.nanoTime() - started) / 1_000_000.0
            elapsedMs.toInt()
        } catch (_: Exception) {
            -1
        }
    }

    private fun setPrivateDns(enable: Boolean) {
        lifecycleScope.launch {
            val host = sanitizeHost(binding.dnsInput.text?.toString()?.trim().orEmpty().ifBlank { "dns.adguard-dns.com" })
            val cmd = if (enable) {
                "settings put global private_dns_mode hostname; settings put global private_dns_specifier $host"
            } else {
                "settings put global private_dns_mode off; settings delete global private_dns_specifier"
            }
            val result = withContext(Dispatchers.IO) { RootFirewallController.runRaw(cmd) }
            binding.outputText.text = buildString {
                appendLine(if (enable) "AdGuard DNS enabled: $host" else "AdGuard DNS disabled")
                appendLine("exit=${result.code}")
                if (result.stdout.isNotBlank()) appendLine(result.stdout)
                if (result.stderr.isNotBlank()) appendLine(result.stderr)
            }
            if (result.ok) {
                val pref = getSharedPreferences("adguard_dns", MODE_PRIVATE)
                if (enable) {
                    pref.edit().putString("saved_dns_host", host).apply()
                } else {
                    pref.edit().remove("saved_dns_host").apply()
                }
            }
        }
    }

    private fun setDnsFirewallLock(enable: Boolean) {
        lifecycleScope.launch {
            val mergedPatterns = if (enable) {
                withContext(Dispatchers.IO) { buildMergedAdPatterns() }
            } else {
                adHostPatterns
            }
            val cmd = if (enable) {
                buildString {
                    append("iptables -N FA_DNS >/dev/null 2>&1 || true;")
                    append("iptables -F FA_DNS >/dev/null 2>&1 || true;")
                    // Jangan ganggu resolver level sistem (netd/system daemons) saat handover jaringan.
                    append("iptables -A FA_DNS -m owner --uid-owner 0-9999 -j RETURN;")
                    append("iptables -A FA_DNS -o lo -j RETURN;")
                    append("iptables -A FA_DNS -d 127.0.0.0/8 -j RETURN;")
                    adguardV4.forEach { ip ->
                        append("iptables -A FA_DNS -p udp --dport 53 -d $ip -j RETURN;")
                        append("iptables -A FA_DNS -p tcp --dport 53 -d $ip -j RETURN;")
                        append("iptables -A FA_DNS -p tcp --dport 853 -d $ip -j RETURN;")
                    }
                    // Fallback resolver dari network aktif (net.dns1..4),
                    // penting supaya transisi WiFi <-> seluler tidak putus DNS.
                    append(
                        "for p in net.dns1 net.dns2 net.dns3 net.dns4; do " +
                            "d=$(getprop ${'$'}p); " +
                            "case \"${'$'}d\" in ''|'0.0.0.0'|'::') continue;; esac; " +
                            "echo \"${'$'}d\" | grep -q ':' && continue; " +
                            "iptables -A FA_DNS -p udp --dport 53 -d \"${'$'}d\" -j RETURN; " +
                            "iptables -A FA_DNS -p tcp --dport 53 -d \"${'$'}d\" -j RETURN; " +
                            "iptables -A FA_DNS -p tcp --dport 853 -d \"${'$'}d\" -j RETURN; " +
                            "done;",
                    )
                    append("iptables -A FA_DNS -p udp --dport 53 -j REJECT;")
                    append("iptables -A FA_DNS -p tcp --dport 53 -j REJECT;")
                    // Jangan blok 853 globally: private DNS/DoT perlu tetap bisa handshake saat network berubah.
                    append("while iptables -C OUTPUT -j FA_DNS >/dev/null 2>&1; do iptables -D OUTPUT -j FA_DNS >/dev/null 2>&1 || break; done;")
                    append("iptables -I OUTPUT 1 -j FA_DNS;")
                    append(buildAdsFirewallEnableScript(mergedPatterns))
                    append("echo dns_firewall_lock=enabled;")
                }
            } else {
                "while iptables -C OUTPUT -j FA_DNS >/dev/null 2>&1; do iptables -D OUTPUT -j FA_DNS >/dev/null 2>&1 || break; done;" +
                    "iptables -F FA_DNS >/dev/null 2>&1 || true;" +
                    "iptables -X FA_DNS >/dev/null 2>&1 || true;" +
                    "while iptables -C OUTPUT -j FA_ADS >/dev/null 2>&1; do iptables -D OUTPUT -j FA_ADS >/dev/null 2>&1 || break; done;" +
                    "iptables -F FA_ADS >/dev/null 2>&1 || true;" +
                    "iptables -X FA_ADS >/dev/null 2>&1 || true;" +
                    "echo dns_firewall_lock=disabled;"
            }
            val result = withContext(Dispatchers.IO) { RootFirewallController.runRaw(cmd) }
            binding.outputText.text = buildString {
                if (enable) {
                    appendLine("DNS Firewall Lock enabled (safe mode).")
                    appendLine("- Block: DNS biasa (port 53) ke resolver non-whitelist")
                    appendLine("- Allow: AdGuard DNS + resolver aktif sistem + DoT 853")
                    appendLine("- Ad block level app: ON (hybrid + ML pattern scoring)")
                    appendLine("- Patterns loaded: ${mergedPatterns.size}")
                } else {
                    appendLine("DNS Firewall Lock disabled.")
                }
                appendLine("exit=${result.code}")
                if (result.stdout.isNotBlank()) appendLine(result.stdout)
                if (result.stderr.isNotBlank()) appendLine(result.stderr)
            }
        }
    }

    private fun readCurrent() {
        lifecycleScope.launch {
            val result = withContext(Dispatchers.IO) {
                RootFirewallController.runRaw(
                    "settings get global private_dns_mode; settings get global private_dns_specifier;" +
                        "if iptables -S OUTPUT 2>/dev/null | grep -q ' -j FA_DNS'; then echo FA_DNS_LOCK=on; else echo FA_DNS_LOCK=off; fi",
                )
            }
            val currentHost = result.stdout
                .lineSequence()
                .map { it.trim() }
                .filter { it.isNotEmpty() && it != "hostname" && it != "off" && !it.startsWith("FA_DNS_LOCK=") }
                .firstOrNull()
                .orEmpty()
            val selectedHost = sanitizeHost(binding.dnsInput.text?.toString()?.trim().orEmpty())
            binding.outputText.text = buildString {
                appendLine("Current Private DNS:")
                if (result.stdout.isNotBlank()) appendLine(result.stdout) else appendLine("-")
                if (currentHost.isNotBlank() && selectedHost.isNotBlank() && currentHost != selectedHost) {
                    appendLine("NOTE: Host aktif berbeda dengan host yang dipilih UI.")
                    appendLine("Aktif: $currentHost | Dipilih: $selectedHost")
                }
                if (result.stderr.isNotBlank()) appendLine(result.stderr)
            }
        }
    }

    private fun sanitizeHost(value: String): String {
        val parsed = try {
            if (value.startsWith("http://") || value.startsWith("https://")) URI(value).host ?: value else value
        } catch (_: Exception) {
            value
        }
        return parsed.filter { it.isLetterOrDigit() || it == '.' || it == '-' }.ifBlank { "dns.adguard-dns.com" }
    }

    private fun buildMergedAdPatterns(): List<String> {
        val hookTail = RootFirewallController.runRaw(
            "tail -n 2000 /data/adb/lspd/log/modules_*.log 2>/dev/null | grep -E 'FA.HybridAdHook|blocked loadUrl|blocked SDK' || true",
        )
        val generated = AdMlScorer.buildMlPatterns(adHostPatterns, hookTail.stdout)
        if (generated.isNotEmpty()) AdMlScorer.saveDynamicPatterns(this, generated)
        val persisted = AdMlScorer.loadDynamicPatterns(this)
        return AdMlScorer.mergePatterns(adHostPatterns, persisted)
    }

    private fun buildAdsFirewallEnableScript(patterns: List<String>): String = buildString {
        append("iptables -N FA_ADS >/dev/null 2>&1 || true;")
        append("iptables -F FA_ADS >/dev/null 2>&1 || true;")
        append("iptables -A FA_ADS -m owner --uid-owner 0-9999 -j RETURN;")
        append("iptables -A FA_ADS -o lo -j RETURN;")
        append("if iptables -m string -h >/dev/null 2>&1; then ")
        patterns.forEach { pattern ->
            append("iptables -A FA_ADS -p tcp --dport 80 -m string --algo bm --icase --string \"$pattern\" -j DROP >/dev/null 2>&1 || true;")
            append("iptables -A FA_ADS -p tcp --dport 443 -m string --algo bm --icase --string \"$pattern\" -j DROP >/dev/null 2>&1 || true;")
        }
        append("fi;")
        append("while iptables -C OUTPUT -j FA_ADS >/dev/null 2>&1; do iptables -D OUTPUT -j FA_ADS >/dev/null 2>&1 || break; done;")
        append("iptables -I OUTPUT 1 -j FA_ADS;")
    }
}
