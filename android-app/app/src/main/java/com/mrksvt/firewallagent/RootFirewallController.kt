package com.mrksvt.firewallagent

import android.content.Context
import com.topjohnwu.superuser.Shell
import java.io.File

data class ExecResult(
    val code: Int,
    val stdout: String,
    val stderr: String,
) {
    val ok: Boolean get() = code == 0
}

data class AppNetRule(
    val uid: Int,
    val local: Boolean,
    val wifi: Boolean,
    val cellular: Boolean,
    val roaming: Boolean,
    val vpn: Boolean,
    val bluetooth: Boolean,
    val tor: Boolean,
)

data class ApplyRulesSummary(
    val totalUids: Int,
    val processedUids: Int,
    val restrictedUids: Int,
    val appliedUids: Int,
    val failedUids: Int,
)

object RootFirewallController {
    private const val assetCtl = "bin/firewall_ctl.sh"
    private var ctlPath: String = ""
    @Volatile private var initialized = false
    private const val MIN_APP_UID = 10000

    fun isProtectedSystemUid(uid: Int): Boolean = uid in 1 until MIN_APP_UID
    fun isManagedAppUid(uid: Int): Boolean = uid >= MIN_APP_UID

    @Synchronized
    fun init(context: Context) {
        if (!initialized) {
            runCatching {
                Shell.setDefaultBuilder(
                    Shell.Builder.create().setFlags(Shell.FLAG_REDIRECT_STDERR or Shell.FLAG_MOUNT_MASTER),
                )
            }
            initialized = true
        }
        ctlPath = installBundledCtl(context)
    }

    fun checkRoot(): Boolean {
        val shell = Shell.getShell()
        if (shell.isRoot) return true
        val probe = Shell.cmd("su -c id -u").exec()
        return probe.code == 0 && probe.out.any { it.trim() == "0" }
    }

    fun requestRootAccess(): ExecResult {
        // Trigger su flow so Magisk/KSU can show grant dialog if needed.
        val r = Shell.cmd("su -c id -u").exec()
        return ExecResult(
            code = r.code,
            stdout = r.out.joinToString("\n"),
            stderr = r.err.joinToString("\n"),
        )
    }

    fun status(): ExecResult = runRoot("/system/bin/sh $ctlPath status")

    fun setMode(mode: String): ExecResult = runRoot("/system/bin/sh $ctlPath mode $mode")

    fun enable(): ExecResult = runRoot("/system/bin/sh $ctlPath enable")

    fun disable(): ExecResult {
        val cmd = buildString {
            append("/system/bin/sh $ctlPath disable;")
            append(clearAppChainsScript())
        }
        return runRoot(cmd)
    }

    fun clearAppChains(): ExecResult = runRoot(clearAppChainsScript())

    fun apply(): ExecResult = runRoot("/system/bin/sh $ctlPath apply")

    fun applyUidBlocks(blockedUids: List<Int>): ExecResult {
        val chain4 = "FA_APP"
        val chain6 = "FA_APP6"
        val uids = blockedUids.distinct().filter { it > 0 }
        val uidList = if (uids.isEmpty()) "" else uids.joinToString(" ")
        val command = buildString {
            append("iptables -N $chain4 >/dev/null 2>&1 || true;")
            append("while iptables -C OUTPUT -j $chain4 >/dev/null 2>&1; do iptables -D OUTPUT -j $chain4 >/dev/null 2>&1 || break; done;")
            append("iptables -F $chain4 >/dev/null 2>&1 || true;")
            append("if command -v ip6tables >/dev/null 2>&1; then ")
            append("ip6tables -N $chain6 >/dev/null 2>&1 || true;")
            append("while ip6tables -C OUTPUT -j $chain6 >/dev/null 2>&1; do ip6tables -D OUTPUT -j $chain6 >/dev/null 2>&1 || break; done;")
            append("ip6tables -F $chain6 >/dev/null 2>&1 || true;")
            append("fi;")
            append("applied4=0; applied6=0;")
            append("for uid in $uidList; do ")
            append("if iptables -A $chain4 -m owner --uid-owner \"${'$'}uid\" -j REJECT; then applied4=${'$'}((applied4+1)); fi;")
            append("if command -v ip6tables >/dev/null 2>&1; then ")
            append("if ip6tables -A $chain6 -m owner --uid-owner \"${'$'}uid\" -j REJECT; then applied6=${'$'}((applied6+1)); fi;")
            append("fi;")
            append("done;")
            append("iptables -I OUTPUT 1 -j $chain4 >/dev/null 2>&1 || true;")
            append("if command -v ip6tables >/dev/null 2>&1; then ip6tables -I OUTPUT 1 -j $chain6 >/dev/null 2>&1 || true; fi;")
            append("requested=${uids.size};")
            append("echo requested=${'$'}requested applied4=${'$'}applied4 applied6=${'$'}applied6;")
            append("if [ \"${'$'}requested\" -gt 0 ] && [ \"${'$'}applied4\" -eq 0 ] && [ \"${'$'}applied6\" -eq 0 ]; then echo owner_match_failed >&2; exit 2; fi;")
        }
        return runRoot(command)
    }

    fun applyAppRules(rules: List<AppNetRule>): ExecResult {
        val normalized = rules
            .filter { isManagedAppUid(it.uid) }
            .distinctBy { it.uid }

        val cmd = StringBuilder()
        cmd.append("iptables -N FA_APP >/dev/null 2>&1 || true;")
        cmd.append("iptables -N FA_APP_IN >/dev/null 2>&1 || true;")
        cmd.append("while iptables -C OUTPUT -j FA_APP >/dev/null 2>&1; do iptables -D OUTPUT -j FA_APP >/dev/null 2>&1 || break; done;")
        cmd.append("while iptables -C INPUT -j FA_APP_IN >/dev/null 2>&1; do iptables -D INPUT -j FA_APP_IN >/dev/null 2>&1 || break; done;")
        cmd.append("iptables -F FA_APP >/dev/null 2>&1 || true;")
        cmd.append("iptables -F FA_APP_IN >/dev/null 2>&1 || true;")
        // Cleanup previous per-uid chains.
        cmd.append("for c in $(iptables -S 2>/dev/null | awk '{print ${'$'}2}' | grep '^FAU_' 2>/dev/null); do iptables -F \"${'$'}c\" >/dev/null 2>&1 || true; iptables -X \"${'$'}c\" >/dev/null 2>&1 || true; done;")

        var appliedUids = 0
        normalized.forEach { r ->
            // If all paths are allowed, no restriction needed for this UID.
            val allAllowed = r.local && r.wifi && r.cellular && r.vpn && r.bluetooth && r.tor && (r.roaming || r.cellular)
            if (allAllowed) return@forEach

            val chain = "FAU_${r.uid}"
            cmd.append("iptables -N $chain >/dev/null 2>&1 || true;")
            cmd.append("iptables -F $chain >/dev/null 2>&1 || true;")
            cmd.append("iptables -A FA_APP -m owner --uid-owner ${r.uid} -j $chain >/dev/null 2>&1;")

            if (r.local) {
                cmd.append("iptables -A $chain -o lo -j RETURN >/dev/null 2>&1;")
                cmd.append("iptables -A $chain -d 127.0.0.0/8 -j RETURN >/dev/null 2>&1;")
            }
            if (r.wifi) {
                cmd.append("iptables -A $chain -o wlan+ -j RETURN >/dev/null 2>&1;")
            }
            if (r.cellular || r.roaming) {
                // Roaming generally shares the same cellular interfaces at iptables layer.
                cmd.append("iptables -A $chain -o rmnet+ -j RETURN >/dev/null 2>&1;")
                cmd.append("iptables -A $chain -o ccmni+ -j RETURN >/dev/null 2>&1;")
                cmd.append("iptables -A $chain -o pdp+ -j RETURN >/dev/null 2>&1;")
                cmd.append("iptables -A $chain -o clat+ -j RETURN >/dev/null 2>&1;")
            }
            if (r.vpn) {
                cmd.append("iptables -A $chain -o tun+ -j RETURN >/dev/null 2>&1;")
                cmd.append("iptables -A $chain -o ppp+ -j RETURN >/dev/null 2>&1;")
                cmd.append("iptables -A $chain -o wg+ -j RETURN >/dev/null 2>&1;")
            }
            if (r.bluetooth) {
                cmd.append("iptables -A $chain -o bnep+ -j RETURN >/dev/null 2>&1;")
            }
            if (r.tor) {
                cmd.append("iptables -A $chain -d 127.0.0.1/32 -p tcp -m tcp --dport 9040 -j RETURN >/dev/null 2>&1;")
                cmd.append("iptables -A $chain -d 127.0.0.1/32 -p tcp -m tcp --dport 9050 -j RETURN >/dev/null 2>&1;")
            }

            // Block anything else for this UID.
            cmd.append("iptables -A $chain -j REJECT --reject-with icmp-port-unreachable >/dev/null 2>&1;")
            appliedUids++
        }

        cmd.append("iptables -I OUTPUT 1 -j FA_APP >/dev/null 2>&1 || true;")
        cmd.append("iptables -I INPUT 1 -j FA_APP_IN >/dev/null 2>&1 || true;")
        cmd.append(normalizeCellularInterfaceRulesScript())
        cmd.append("echo rule_mode=per_app applied_uids=$appliedUids total_uids=${normalized.size};")
        return runRoot(cmd.toString())
    }

    fun applyAppRulesWithProgress(
        rules: List<AppNetRule>,
        onProgress: (processed: Int, total: Int) -> Unit,
    ): Pair<ExecResult, ApplyRulesSummary> {
        val normalized = rules
            .filter { isManagedAppUid(it.uid) }
            .distinctBy { it.uid }

        val total = normalized.size
        var processed = 0
        var restricted = 0
        var applied = 0
        var failed = 0
        val outLines = mutableListOf<String>()
        val errLines = mutableListOf<String>()

        val setup = runRoot(
            buildString {
                append("iptables -N FA_APP >/dev/null 2>&1 || true;")
                append("iptables -N FA_APP_IN >/dev/null 2>&1 || true;")
                append("while iptables -C OUTPUT -j FA_APP >/dev/null 2>&1; do iptables -D OUTPUT -j FA_APP >/dev/null 2>&1 || break; done;")
                append("while iptables -C INPUT -j FA_APP_IN >/dev/null 2>&1; do iptables -D INPUT -j FA_APP_IN >/dev/null 2>&1 || break; done;")
                append("iptables -F FA_APP >/dev/null 2>&1 || true;")
                append("iptables -F FA_APP_IN >/dev/null 2>&1 || true;")
                append("for c in $(iptables -S 2>/dev/null | awk '{print ${'$'}2}' | grep '^FAU_' 2>/dev/null); do iptables -F \"${'$'}c\" >/dev/null 2>&1 || true; iptables -X \"${'$'}c\" >/dev/null 2>&1 || true; done;")
            },
        )
        if (!setup.ok) {
            val summary = ApplyRulesSummary(total, processed, restricted, applied, failed)
            return setup to summary
        }

        normalized.forEach { r ->
            val allAllowed = r.local && r.wifi && r.cellular && r.vpn && r.bluetooth && r.tor && (r.roaming || r.cellular)
            if (!allAllowed) {
                restricted++
                val chain = "FAU_${r.uid}"
                val cmd = buildString {
                    append("iptables -N $chain >/dev/null 2>&1 || true;")
                    append("iptables -F $chain >/dev/null 2>&1 || true;")
                    append("iptables -A FA_APP -m owner --uid-owner ${r.uid} -j $chain >/dev/null 2>&1;")
                    if (r.local) {
                        append("iptables -A $chain -o lo -j RETURN >/dev/null 2>&1;")
                        append("iptables -A $chain -d 127.0.0.0/8 -j RETURN >/dev/null 2>&1;")
                    }
                    if (r.wifi) {
                        append("iptables -A $chain -o wlan+ -j RETURN >/dev/null 2>&1;")
                    }
                    if (r.cellular || r.roaming) {
                        append("iptables -A $chain -o rmnet+ -j RETURN >/dev/null 2>&1;")
                        append("iptables -A $chain -o ccmni+ -j RETURN >/dev/null 2>&1;")
                        append("iptables -A $chain -o pdp+ -j RETURN >/dev/null 2>&1;")
                        append("iptables -A $chain -o clat+ -j RETURN >/dev/null 2>&1;")
                    }
                    if (r.vpn) {
                        append("iptables -A $chain -o tun+ -j RETURN >/dev/null 2>&1;")
                        append("iptables -A $chain -o ppp+ -j RETURN >/dev/null 2>&1;")
                        append("iptables -A $chain -o wg+ -j RETURN >/dev/null 2>&1;")
                    }
                    if (r.bluetooth) {
                        append("iptables -A $chain -o bnep+ -j RETURN >/dev/null 2>&1;")
                    }
                    if (r.tor) {
                        append("iptables -A $chain -d 127.0.0.1/32 -p tcp -m tcp --dport 9040 -j RETURN >/dev/null 2>&1;")
                        append("iptables -A $chain -d 127.0.0.1/32 -p tcp -m tcp --dport 9050 -j RETURN >/dev/null 2>&1;")
                    }
                    append("iptables -A $chain -j REJECT --reject-with icmp-port-unreachable >/dev/null 2>&1;")
                }
                val res = runRoot(cmd)
                if (!res.ok) {
                    failed++
                    errLines += "uid=${r.uid} apply_failed code=${res.code}"
                    if (res.stderr.isNotBlank()) errLines += res.stderr
                    if (res.stdout.isNotBlank()) outLines += res.stdout
                    processed++
                    onProgress(processed, total)
                    return@forEach
                }
                applied++
                if (res.stdout.isNotBlank()) outLines += res.stdout
                if (res.stderr.isNotBlank()) errLines += res.stderr
            }
            processed++
            onProgress(processed, total)
        }

        val finish = runRoot(
            buildString {
                append("iptables -I OUTPUT 1 -j FA_APP >/dev/null 2>&1 || true;")
                append("iptables -I INPUT 1 -j FA_APP_IN >/dev/null 2>&1 || true;")
                append(normalizeCellularInterfaceRulesScript())
                append("echo rule_mode=per_app applied_uids=$applied total_uids=$total restricted_uids=$restricted failed_uids=$failed;")
            },
        )
        if (finish.stdout.isNotBlank()) outLines += finish.stdout
        if (finish.stderr.isNotBlank()) errLines += finish.stderr

        val final = ExecResult(
            code = finish.code,
            stdout = outLines.joinToString("\n").ifBlank { finish.stdout },
            stderr = errLines.joinToString("\n").ifBlank { finish.stderr },
        )
        val summary = ApplyRulesSummary(total, processed, restricted, applied, failed)
        return final to summary
    }

    fun listManagedUids(): Set<Int> {
        val res = runRoot("iptables -S FA_APP 2>/dev/null")
        if (!res.ok) return emptySet()
        val out = res.stdout
        val re = Regex("""--uid-owner\s+(\d+)""")
        return re.findAll(out)
            .mapNotNull { it.groupValues.getOrNull(1)?.toIntOrNull() }
            .toSet()
    }

    fun removeUidRules(uids: Set<Int>): ExecResult {
        if (uids.isEmpty()) return ExecResult(0, "removed_uids=0", "")
        val list = uids.filter { it > 0 }.toSet()
        if (list.isEmpty()) return ExecResult(0, "removed_uids=0", "")
        val cmd = buildString {
            list.forEach { uid ->
                append("while iptables -C FA_APP -m owner --uid-owner $uid -j FAU_$uid >/dev/null 2>&1; do iptables -D FA_APP -m owner --uid-owner $uid -j FAU_$uid >/dev/null 2>&1 || break; done;")
                append("while iptables -C FA_APP_IN -m connmark --mark $uid -j REJECT --reject-with icmp-port-unreachable >/dev/null 2>&1; do iptables -D FA_APP_IN -m connmark --mark $uid -j REJECT --reject-with icmp-port-unreachable >/dev/null 2>&1 || break; done;")
                append("iptables -F FAU_$uid >/dev/null 2>&1 || true;")
                append("iptables -X FAU_$uid >/dev/null 2>&1 || true;")
            }
            append("echo removed_uids=${list.size};")
        }
        return runRoot(cmd)
    }

    fun readUidChainSpecs(uids: Set<Int>): Map<Int, String> {
        if (uids.isEmpty()) return emptyMap()
        val uidList = uids.filter { it > 0 }.joinToString(" ")
        if (uidList.isBlank()) return emptyMap()
        val res = runRoot(
            buildString {
                append("for uid in $uidList; do ")
                append("echo __FA_BEGIN_${'$'}uid;")
                append("iptables -S FAU_${'$'}uid 2>/dev/null || true;")
                append("echo __FA_END_${'$'}uid;")
                append("done;")
            },
        )
        if (!res.ok && res.stdout.isBlank()) return emptyMap()

        val lines = res.stdout.lines()
        val out = mutableMapOf<Int, String>()
        var currentUid: Int? = null
        val buf = mutableListOf<String>()

        fun flush() {
            val uid = currentUid ?: return
            out[uid] = buf
                .asSequence()
                .map { it.trim() }
                .filter { it.startsWith("-A FAU_") }
                .joinToString("\n")
            buf.clear()
            currentUid = null
        }

        for (line in lines) {
            when {
                line.startsWith("__FA_BEGIN_") -> {
                    flush()
                    currentUid = line.removePrefix("__FA_BEGIN_").trim().toIntOrNull()
                }
                line.startsWith("__FA_END_") -> {
                    flush()
                }
                currentUid != null -> {
                    buf += line
                }
            }
        }
        flush()
        return out
    }

    fun expectedUidChainSpec(rule: AppNetRule): String {
        if (!isManagedAppUid(rule.uid)) return ""
        val chain = "FAU_${rule.uid}"
        val lines = mutableListOf<String>()

        if (rule.local) {
            lines += "-A $chain -o lo -j RETURN"
            lines += "-A $chain -d 127.0.0.0/8 -j RETURN"
        }
        if (rule.wifi) {
            lines += "-A $chain -o wlan+ -j RETURN"
        }
        if (rule.cellular || rule.roaming) {
            lines += "-A $chain -o rmnet+ -j RETURN"
            lines += "-A $chain -o ccmni+ -j RETURN"
            lines += "-A $chain -o pdp+ -j RETURN"
            lines += "-A $chain -o clat+ -j RETURN"
        }
        if (rule.vpn) {
            lines += "-A $chain -o tun+ -j RETURN"
            lines += "-A $chain -o ppp+ -j RETURN"
            lines += "-A $chain -o wg+ -j RETURN"
        }
        if (rule.bluetooth) {
            lines += "-A $chain -o bnep+ -j RETURN"
        }
        if (rule.tor) {
            lines += "-A $chain -d 127.0.0.1/32 -p tcp -m tcp --dport 9040 -j RETURN"
            lines += "-A $chain -d 127.0.0.1/32 -p tcp -m tcp --dport 9050 -j RETURN"
        }
        lines += "-A $chain -j REJECT --reject-with icmp-port-unreachable"
        return lines.joinToString("\n")
    }

    fun applyAppRulesIncremental(
        upsertRules: List<AppNetRule>,
        removeUids: Set<Int>,
        onProgress: (processed: Int, total: Int) -> Unit,
    ): Pair<ExecResult, ApplyRulesSummary> {
        val normalizedUpsert = upsertRules
            .filter { isManagedAppUid(it.uid) }
            .distinctBy { it.uid }
        val normalizedRemove = removeUids.filter { it > 0 }.toSet()

        val total = normalizedUpsert.size + normalizedRemove.size
        var processed = 0
        var applied = 0
        var failed = 0
        val outLines = mutableListOf<String>()
        val errLines = mutableListOf<String>()

        val setup = runRoot(
            buildString {
                append("iptables -N FA_APP >/dev/null 2>&1 || true;")
                append("iptables -N FA_APP_IN >/dev/null 2>&1 || true;")
                append("iptables -C OUTPUT -j FA_APP >/dev/null 2>&1 || iptables -I OUTPUT 1 -j FA_APP >/dev/null 2>&1 || true;")
                append("iptables -C INPUT -j FA_APP_IN >/dev/null 2>&1 || iptables -I INPUT 1 -j FA_APP_IN >/dev/null 2>&1 || true;")
            },
        )
        if (!setup.ok) {
            val summary = ApplyRulesSummary(total, processed, normalizedUpsert.size, applied, failed)
            return setup to summary
        }

        normalizedRemove.forEach { uid ->
            val cmd = buildString {
                append("while iptables -C FA_APP -m owner --uid-owner $uid -j FAU_$uid >/dev/null 2>&1; do iptables -D FA_APP -m owner --uid-owner $uid -j FAU_$uid >/dev/null 2>&1 || break; done;")
                append("while iptables -C FA_APP_IN -m connmark --mark $uid -j REJECT --reject-with icmp-port-unreachable >/dev/null 2>&1; do iptables -D FA_APP_IN -m connmark --mark $uid -j REJECT --reject-with icmp-port-unreachable >/dev/null 2>&1 || break; done;")
                append("iptables -F FAU_$uid >/dev/null 2>&1 || true;")
                append("iptables -X FAU_$uid >/dev/null 2>&1 || true;")
            }
            val res = runRoot(cmd)
            if (res.ok) applied++ else failed++
            if (res.stdout.isNotBlank()) outLines += res.stdout
            if (res.stderr.isNotBlank()) errLines += "uid=$uid remove_failed: ${res.stderr}"
            processed++
            onProgress(processed, total)
        }

        normalizedUpsert.forEach { r ->
            val chain = "FAU_${r.uid}"
            val cmd = buildString {
                append("while iptables -C FA_APP -m owner --uid-owner ${r.uid} -j $chain >/dev/null 2>&1; do iptables -D FA_APP -m owner --uid-owner ${r.uid} -j $chain >/dev/null 2>&1 || break; done;")
                append("while iptables -C FA_APP_IN -m connmark --mark ${r.uid} -j REJECT --reject-with icmp-port-unreachable >/dev/null 2>&1; do iptables -D FA_APP_IN -m connmark --mark ${r.uid} -j REJECT --reject-with icmp-port-unreachable >/dev/null 2>&1 || break; done;")
                append("iptables -N $chain >/dev/null 2>&1 || true;")
                append("iptables -F $chain >/dev/null 2>&1 || true;")

                if (r.local) {
                    append("iptables -A $chain -o lo -j RETURN >/dev/null 2>&1;")
                    append("iptables -A $chain -d 127.0.0.0/8 -j RETURN >/dev/null 2>&1;")
                }
                if (r.wifi) {
                    append("iptables -A $chain -o wlan+ -j RETURN >/dev/null 2>&1;")
                }
                if (r.cellular || r.roaming) {
                    append("iptables -A $chain -o rmnet+ -j RETURN >/dev/null 2>&1;")
                    append("iptables -A $chain -o ccmni+ -j RETURN >/dev/null 2>&1;")
                    append("iptables -A $chain -o pdp+ -j RETURN >/dev/null 2>&1;")
                    append("iptables -A $chain -o clat+ -j RETURN >/dev/null 2>&1;")
                }
                if (r.vpn) {
                    append("iptables -A $chain -o tun+ -j RETURN >/dev/null 2>&1;")
                    append("iptables -A $chain -o ppp+ -j RETURN >/dev/null 2>&1;")
                    append("iptables -A $chain -o wg+ -j RETURN >/dev/null 2>&1;")
                }
                if (r.bluetooth) {
                    append("iptables -A $chain -o bnep+ -j RETURN >/dev/null 2>&1;")
                }
                if (r.tor) {
                    append("iptables -A $chain -d 127.0.0.1/32 -p tcp -m tcp --dport 9040 -j RETURN >/dev/null 2>&1;")
                    append("iptables -A $chain -d 127.0.0.1/32 -p tcp -m tcp --dport 9050 -j RETURN >/dev/null 2>&1;")
                }
                append("iptables -A $chain -j REJECT --reject-with icmp-port-unreachable >/dev/null 2>&1;")
                append("iptables -A FA_APP -m owner --uid-owner ${r.uid} -j $chain >/dev/null 2>&1;")
            }
            val res = runRoot(cmd)
            if (res.ok) applied++ else failed++
            if (res.stdout.isNotBlank()) outLines += res.stdout
            if (res.stderr.isNotBlank()) errLines += "uid=${r.uid} upsert_failed: ${res.stderr}"
            processed++
            onProgress(processed, total)
        }

        val final = ExecResult(
            code = if (failed == 0) 0 else 4,
            stdout = outLines.joinToString("\n"),
            stderr = errLines.joinToString("\n"),
        )
        val summary = ApplyRulesSummary(total, processed, normalizedUpsert.size, applied, failed)
        return final to summary
    }

    fun normalizeCellularInterfaceRules(): ExecResult = runRoot(normalizeCellularInterfaceRulesScript())

    fun cleanupProtectedSystemUidRules(): ExecResult {
        val managed = listManagedUids()
        val protected = managed.filter { isProtectedSystemUid(it) }.toSet()
        return removeUidRules(protected)
    }

    fun tailServiceLog(lines: Int = 80): ExecResult =
        runRoot("tail -n $lines /data/local/tmp/firewall_agent/logs/controller.log")

    fun runRaw(command: String): ExecResult = runRoot(command)

    fun applyGlobalStrict(firewallUid: Int): ExecResult {
        val out4 = "FA_GLOBAL_OUT"
        val in4 = "FA_GLOBAL_IN"
        val out6 = "FA_GLOBAL_OUT6"
        val in6 = "FA_GLOBAL_IN6"
        val cmd = buildString {
            append("if command -v ipset >/dev/null 2>&1; then ")
            append("ipset -exist create fa_allow_v4 hash:ip family inet;")
            append("ipset -exist create fa_allow_v6 hash:ip family inet6;")
            append("ipset -exist create fa_block_v4 hash:ip family inet;")
            append("ipset -exist create fa_block_v6 hash:ip family inet6;")
            append("fi;")
            append("iptables -N $out4 >/dev/null 2>&1 || true;")
            append("iptables -N $in4 >/dev/null 2>&1 || true;")
            append("iptables -F $out4 >/dev/null 2>&1 || true;")
            append("iptables -F $in4 >/dev/null 2>&1 || true;")

            append("iptables -A $out4 -o lo -j RETURN >/dev/null 2>&1;")
            append("iptables -A $out4 -m conntrack --ctstate ESTABLISHED,RELATED -j RETURN >/dev/null 2>&1;")
            append("iptables -A $out4 -m owner --uid-owner $firewallUid -j RETURN >/dev/null 2>&1;")
            append("iptables -A $out4 -m owner --uid-owner 2000 -j RETURN >/dev/null 2>&1;")
            append("iptables -A $out4 -p tcp --dport 5555 -j RETURN >/dev/null 2>&1;")
            append("iptables -A $out4 -m set --match-set fa_block_v4 dst -j DROP >/dev/null 2>&1;")
            append("iptables -A $out4 -m set --match-set fa_allow_v4 dst -j RETURN >/dev/null 2>&1;")
            append("iptables -A $out4 -j DROP >/dev/null 2>&1;")

            append("iptables -A $in4 -i lo -j RETURN >/dev/null 2>&1;")
            append("iptables -A $in4 -m conntrack --ctstate ESTABLISHED,RELATED -j RETURN >/dev/null 2>&1;")
            append("iptables -A $in4 -p tcp --dport 5555 -j RETURN >/dev/null 2>&1;")
            append("iptables -A $in4 -j DROP >/dev/null 2>&1;")

            append("while iptables -C OUTPUT -j $out4 >/dev/null 2>&1; do iptables -D OUTPUT -j $out4 >/dev/null 2>&1 || break; done;")
            append("while iptables -C INPUT -j $in4 >/dev/null 2>&1; do iptables -D INPUT -j $in4 >/dev/null 2>&1 || break; done;")
            append("iptables -I OUTPUT 1 -j $out4 >/dev/null 2>&1 || true;")
            append("iptables -I INPUT 1 -j $in4 >/dev/null 2>&1 || true;")

            append("if command -v ip6tables >/dev/null 2>&1; then ")
            append("ip6tables -N $out6 >/dev/null 2>&1 || true;")
            append("ip6tables -N $in6 >/dev/null 2>&1 || true;")
            append("ip6tables -F $out6 >/dev/null 2>&1 || true;")
            append("ip6tables -F $in6 >/dev/null 2>&1 || true;")
            append("ip6tables -A $out6 -o lo -j RETURN >/dev/null 2>&1;")
            append("ip6tables -A $out6 -m conntrack --ctstate ESTABLISHED,RELATED -j RETURN >/dev/null 2>&1;")
            append("ip6tables -A $out6 -m owner --uid-owner $firewallUid -j RETURN >/dev/null 2>&1;")
            append("ip6tables -A $out6 -m owner --uid-owner 2000 -j RETURN >/dev/null 2>&1;")
            append("ip6tables -A $out6 -m set --match-set fa_block_v6 dst -j DROP >/dev/null 2>&1;")
            append("ip6tables -A $out6 -m set --match-set fa_allow_v6 dst -j RETURN >/dev/null 2>&1;")
            append("ip6tables -A $out6 -j DROP >/dev/null 2>&1;")
            append("ip6tables -A $in6 -i lo -j RETURN >/dev/null 2>&1;")
            append("ip6tables -A $in6 -m conntrack --ctstate ESTABLISHED,RELATED -j RETURN >/dev/null 2>&1;")
            append("ip6tables -A $in6 -j DROP >/dev/null 2>&1;")
            append("while ip6tables -C OUTPUT -j $out6 >/dev/null 2>&1; do ip6tables -D OUTPUT -j $out6 >/dev/null 2>&1 || break; done;")
            append("while ip6tables -C INPUT -j $in6 >/dev/null 2>&1; do ip6tables -D INPUT -j $in6 >/dev/null 2>&1 || break; done;")
            append("ip6tables -I OUTPUT 1 -j $out6 >/dev/null 2>&1 || true;")
            append("ip6tables -I INPUT 1 -j $in6 >/dev/null 2>&1 || true;")
            append("fi;")
            append("echo global_strict=on firewall_uid=$firewallUid;")
        }
        return runRoot(cmd)
    }

    fun disableGlobalStrict(): ExecResult {
        val cmd = buildString {
            append("for ch in FA_GLOBAL_OUT FA_GLOBAL_IN; do ")
            append("while iptables -C OUTPUT -j ${'$'}ch >/dev/null 2>&1; do iptables -D OUTPUT -j ${'$'}ch >/dev/null 2>&1 || break; done;")
            append("while iptables -C INPUT -j ${'$'}ch >/dev/null 2>&1; do iptables -D INPUT -j ${'$'}ch >/dev/null 2>&1 || break; done;")
            append("iptables -F ${'$'}ch >/dev/null 2>&1 || true;")
            append("iptables -X ${'$'}ch >/dev/null 2>&1 || true;")
            append("done;")
            append("if command -v ip6tables >/dev/null 2>&1; then ")
            append("for ch in FA_GLOBAL_OUT6 FA_GLOBAL_IN6; do ")
            append("while ip6tables -C OUTPUT -j ${'$'}ch >/dev/null 2>&1; do ip6tables -D OUTPUT -j ${'$'}ch >/dev/null 2>&1 || break; done;")
            append("while ip6tables -C INPUT -j ${'$'}ch >/dev/null 2>&1; do ip6tables -D INPUT -j ${'$'}ch >/dev/null 2>&1 || break; done;")
            append("ip6tables -F ${'$'}ch >/dev/null 2>&1 || true;")
            append("ip6tables -X ${'$'}ch >/dev/null 2>&1 || true;")
            append("done;")
            append("fi;")
            append("echo global_strict=off;")
        }
        return runRoot(cmd)
    }

    fun syncIpSets(
        allowV4: Set<String>,
        allowV6: Set<String>,
        blockV4: Set<String>,
        blockV6: Set<String>,
    ): ExecResult {
        val cmd = buildString {
            append("if ! command -v ipset >/dev/null 2>&1; then echo ipset_missing >&2; exit 12; fi;")
            append("ipset -exist create fa_allow_v4 hash:ip family inet;")
            append("ipset -exist create fa_allow_v6 hash:ip family inet6;")
            append("ipset -exist create fa_block_v4 hash:ip family inet;")
            append("ipset -exist create fa_block_v6 hash:ip family inet6;")
            append("ipset -exist create fa_allow_v4_tmp hash:ip family inet;")
            append("ipset -exist create fa_allow_v6_tmp hash:ip family inet6;")
            append("ipset -exist create fa_block_v4_tmp hash:ip family inet;")
            append("ipset -exist create fa_block_v6_tmp hash:ip family inet6;")
            append("ipset flush fa_allow_v4_tmp;")
            append("ipset flush fa_allow_v6_tmp;")
            append("ipset flush fa_block_v4_tmp;")
            append("ipset flush fa_block_v6_tmp;")
            allowV4.forEach { ip -> append("ipset -exist add fa_allow_v4_tmp ${shellWord(ip)};") }
            allowV6.forEach { ip -> append("ipset -exist add fa_allow_v6_tmp ${shellWord(ip)};") }
            blockV4.forEach { ip -> append("ipset -exist add fa_block_v4_tmp ${shellWord(ip)};") }
            blockV6.forEach { ip -> append("ipset -exist add fa_block_v6_tmp ${shellWord(ip)};") }
            append("ipset swap fa_allow_v4_tmp fa_allow_v4;")
            append("ipset swap fa_allow_v6_tmp fa_allow_v6;")
            append("ipset swap fa_block_v4_tmp fa_block_v4;")
            append("ipset swap fa_block_v6_tmp fa_block_v6;")
            append("echo ipset_sync=ok allow_v4=${allowV4.size} allow_v6=${allowV6.size} block_v4=${blockV4.size} block_v6=${blockV6.size};")
        }
        return runRoot(cmd)
    }

    private fun clearAppChainsScript(): String {
        return buildString {
            append("for ch in FA_APP FA_APP_IN FA_APP6; do ")
            append("while iptables -C OUTPUT -j ${'$'}ch >/dev/null 2>&1; do iptables -D OUTPUT -j ${'$'}ch >/dev/null 2>&1 || break; done;")
            append("while iptables -C INPUT -j ${'$'}ch >/dev/null 2>&1; do iptables -D INPUT -j ${'$'}ch >/dev/null 2>&1 || break; done;")
            append("iptables -F ${'$'}ch >/dev/null 2>&1 || true;")
            append("iptables -X ${'$'}ch >/dev/null 2>&1 || true;")
            append("done;")
            append("if command -v ip6tables >/dev/null 2>&1; then ")
            append("for ch in FA_APP FA_APP6; do ")
            append("while ip6tables -C OUTPUT -j ${'$'}ch >/dev/null 2>&1; do ip6tables -D OUTPUT -j ${'$'}ch >/dev/null 2>&1 || break; done;")
            append("ip6tables -F ${'$'}ch >/dev/null 2>&1 || true;")
            append("ip6tables -X ${'$'}ch >/dev/null 2>&1 || true;")
            append("done;")
            append("fi;")
            append("echo chains_cleared=FA_APP,FA_APP6;")
        }
    }

    private fun normalizeCellularInterfaceRulesScript(): String {
        // Some devices switch between rmnet/ccmni/pdp/clat for cellular path.
        // If a UID chain allows one cellular interface, ensure all aliases exist.
        return buildString {
            append("for ch in $(iptables -S 2>/dev/null | awk '{if ($1==\"-N\" && $2 ~ /^FAU_/) print $2}'); do ")
            append("has_cell=0; ")
            append("iptables -C ${'$'}ch -o rmnet+ -j RETURN >/dev/null 2>&1 && has_cell=1; ")
            append("iptables -C ${'$'}ch -o ccmni+ -j RETURN >/dev/null 2>&1 && has_cell=1; ")
            append("iptables -C ${'$'}ch -o pdp+ -j RETURN >/dev/null 2>&1 && has_cell=1; ")
            append("iptables -C ${'$'}ch -o clat+ -j RETURN >/dev/null 2>&1 && has_cell=1; ")
            append("if [ \"${'$'}has_cell\" -eq 1 ]; then ")
            append("iptables -C ${'$'}ch -o rmnet+ -j RETURN >/dev/null 2>&1 || iptables -I ${'$'}ch 1 -o rmnet+ -j RETURN >/dev/null 2>&1; ")
            append("iptables -C ${'$'}ch -o ccmni+ -j RETURN >/dev/null 2>&1 || iptables -I ${'$'}ch 1 -o ccmni+ -j RETURN >/dev/null 2>&1; ")
            append("iptables -C ${'$'}ch -o pdp+ -j RETURN >/dev/null 2>&1 || iptables -I ${'$'}ch 1 -o pdp+ -j RETURN >/dev/null 2>&1; ")
            append("iptables -C ${'$'}ch -o clat+ -j RETURN >/dev/null 2>&1 || iptables -I ${'$'}ch 1 -o clat+ -j RETURN >/dev/null 2>&1; ")
            append("fi; ")
            append("done; ")
            append("echo normalized_cellular_interfaces=1;")
        }
    }

    private fun installBundledCtl(context: Context): String {
        val dir = File(context.filesDir, "bin")
        if (!dir.exists()) dir.mkdirs()

        val target = File(dir, "firewall_ctl.sh")
        context.assets.open(assetCtl).use { input ->
            target.outputStream().use { output ->
                input.copyTo(output)
            }
        }

        target.setExecutable(true, false)
        return target.absolutePath
    }

    private fun runRoot(cmd: String): ExecResult {
        val escaped = cmd.replace("'", "'\"'\"'")
        val wrapped = "su -c '$escaped'"
        val result = Shell.cmd(wrapped).exec()
        if (result.code == 0) {
            return ExecResult(
                code = result.code,
                stdout = result.out.joinToString("\n"),
                stderr = result.err.joinToString("\n"),
            )
        }

        val fallback = Shell.cmd(cmd).exec()
        return ExecResult(
            code = fallback.code,
            stdout = fallback.out.joinToString("\n"),
            stderr = fallback.err.joinToString("\n"),
        )
    }

    private fun shellWord(value: String): String = "'${value.replace("'", "'\"'\"'")}'"
}
