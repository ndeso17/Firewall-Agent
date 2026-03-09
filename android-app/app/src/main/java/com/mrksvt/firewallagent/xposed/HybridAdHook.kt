package com.mrksvt.firewallagent.xposed

import android.app.DownloadManager
import android.app.Application
import android.app.Activity
import android.app.Dialog
import android.content.Intent
import android.net.Uri
import android.view.WindowManager
import android.webkit.WebResourceRequest
import android.webkit.WebResourceResponse
import com.mrksvt.firewallagent.AdMlScorer
import de.robv.android.xposed.IXposedHookLoadPackage
import de.robv.android.xposed.XC_MethodHook
import de.robv.android.xposed.XposedBridge
import de.robv.android.xposed.callbacks.XC_LoadPackage
import android.os.Process
import org.json.JSONArray
import java.io.ByteArrayInputStream
import java.io.File
import java.lang.reflect.Method
import java.util.Locale
import java.util.concurrent.ConcurrentHashMap


private object BlockedUrlMap {
    private val map = java.util.concurrent.ConcurrentHashMap<de.robv.android.xposed.XC_MethodHook.MethodHookParam, String>()
    fun put(param: de.robv.android.xposed.XC_MethodHook.MethodHookParam, url: String) { map[param] = url }
    fun remove(param: de.robv.android.xposed.XC_MethodHook.MethodHookParam): String? = map.remove(param)
}
class HybridAdHook : IXposedHookLoadPackage {
    // Extended ad patterns: includes gambling, scam, and adult ad networks
    private val adPatterns = listOf(
        // Google Ad Networks
        "doubleclick.net",
        "googleadservices.com",
        "googlesyndication.com",
        "adservice.google.",
        "admob.com",
        "pagead2.googlesyndication.com",
        "tpc.googlesyndication.com",
        "securepubads.g.doubleclick.net",
        // Mobile Ad SDKs
        "unityads.unity3d.com",
        "iads.unity3d.com",        // UnityAds via IronSource mediation
        "gw-is.iads.unity3d.com",  // UnityAds gateway via IS
        "auction.unityads.unity3d.com",
        "applovin",
        "ironsrc",
        "vungle",
        "adnxs.com",
        "mintegral.",
        "hyprmx.com",
        "inmobi.",
        "liftoff.",
        "moloco.",
        "pangle.io",
        "pangolin-sdk-toutiao.com",
        "byteoversea.com",
        "snssdk.com",
        "sgsnssdk.com",
        "zijieapi.com",
        "bytedance.com",
        "toutiao.com",
        "adx.opera.com",
        "op-mobile.opera.com",
        // Display / Programmatic
        "taboola",
        "outbrain",
        "criteo.",
        "pubmatic.",
        "openx.net",
        "rubiconproject.com",
        "smartadserver.",
        "media.net",
        "bidswitch.net",
        "adsystem",
        ".ads.",
        // Tracking / Attribution (prevent data exfil even if ad blocked at DNS)
        "appsflyer.com",
        "adjust.com",
        "branch.io",
        "singular.net",
        "kochava.com",
        "tenjin.io",
        "fyber.",
        // Gambling-specific ad networks (high-risk)
        "b-1x2.com",
        "betsson.",
        "bettingads.",
        "casino-ads.",
        "casinoads.",
        "gamingads.",
        "gamblingads.",
        "beting-ads.",
        "adbet.",
        "bookiesads.",
        "betads.",
        "casinomedia.",
        "gamblingaffiliates.",
        // Scam / Phishing ad networks
        "trafficjunky.",
        "propellerads.",
        "clickadu.",
        "adcash.",
        "exoclick.",
        "hilltopads.",
        "adsterra.",
        "popcash.",
        "ero-advertising.",
        "txxx.",
        "juicyads.",
        "trafficfactory.",
        "tsyndicate.",
        // Adult content ad networks
        "ero-advertising.",
        "juicyads.",
        "trafficjunky.",
        "exoclick.",
        "adultforce.",
        "adxxx.",
        "trafficfactory.",
        "naiadsystems.",
        "plugrush.",
        "xclicks.",
        "adult-ads.",
        "adultadvertising.",
        "ero-advertising.",
    )

    // DNS Hide Hook — handles Private DNS detection masking
    private val dnsHideHook = DnsHideHook()
    @Volatile private var cachedExtraPatterns: List<String> = emptyList()
    @Volatile private var lastExtraPatternLoadMs: Long = 0L
    @Volatile private var cachedExternalBlockedHosts: Set<String> = emptySet()
    @Volatile private var lastExternalBlockedHostLoadMs: Long = 0L
    private val scopedPackages = linkedSetOf(
        "com.freereels.app",
        "com.worldance.drama",
        "com.stream.drakorindoawet",
        "com.happymod.apk",
        "com.happymod",
        "com.google.android.webview",
        "com.android.webview",
        "com.android.chrome",
    )
    private val riskyClickRedirectPackages = listOf(
        "shopee",
        "tokopedia",
        "lazada",
        "bukalapak",
    )
    private val strictAdPackages = linkedSetOf(
        "com.happymod.apk",
        "com.worldance.drama",
        "com.freereels.app",
        "com.stream.drakorindoawet",
    )
    private val relaxedStrictPackages = linkedSetOf(
        // Keep ad hooks enabled, but avoid strict blanket deny while debugging via Ads Matcher.
        "com.stream.drakorindoawet",
    )
    private val browserGuardPackages = linkedSetOf(
        "com.android.chrome",
        "com.google.android.webview",
        "com.android.webview",
    )
    private val webViewBridgePackages = linkedSetOf(
        "com.google.android.webview",
        "com.android.webview",
    )
    private val knownMalwareHosts = linkedSetOf(
        "rejekibetasia02.com",
        "bw88cdn.com",
        "bw88cdn.net",
        "rejekibet",
        "plx193.com",
        "ppv99b.xyz",
        "55rp.plx193.com",
        "fb-dl.ppv99b.xyz",
        "77rpfhk425.com",
        "77rp.77rpfhk425.com",
        "66qifei.com",
        "www.66qifei.com",
    )
    private val officialTrustedHosts = linkedSetOf(
        "telegram.org",
        "t.me",
        "whatsapp.com",
        "facebook.com",
        "fb.com",
        "fbcdn.net",
        "instagram.com",
        "cdninstagram.com",
        "google.com",
        "googleapis.com",
        "gstatic.com",
        "youtube.com",
        "ytimg.com",
        "android.com",
    )
    private val officialPackageHosts = mapOf(
        "com.happymod.apk" to linkedSetOf("happymod.com", "mtgglobals.com"),
        "com.happymod" to linkedSetOf("happymod.com", "mtgglobals.com"),
        "com.freereels.app" to linkedSetOf(
            "freereels.app",
            "freereels.com",
            "free-reels.com",
            "apiv2.free-reels.com",
            "mydramawave.com",
            "static-v1.mydramawave.com",
        ),
        "com.worldance.drama" to linkedSetOf("worldance.drama", "worldance.com"),
    )
    private val strictAdMlScoreThreshold = 1.0
    private val strictAdHostScoreCeiling = 2.4
    private val highRiskKeywordSet = linkedSetOf(
        "casino",
        "bet",
        "betting",
        "judi",
        "slot",
        "slots",
        "poker",
        "roulette",
        "adult",
        "porn",
        "xxx",
        "bet365",
        "betano",
        "w88",
        "bookmaker",
        "livecasino",
        "jackpot",
    )
    private val networkEventDedup = ConcurrentHashMap<String, Long>()
    private val requestDecisionEngine by lazy {
        val strictDenyDefaultPackages = strictAdPackages.filterNot { relaxedStrictPackages.contains(it) }.toSet()
        val strictCrossAppPackages = strictAdPackages.filterNot { relaxedStrictPackages.contains(it) }.toSet()
        RequestDecisionEngine(
            strictPackages = strictAdPackages,
            strictDenyDefaultPackages = strictDenyDefaultPackages,
            strictCrossAppPackages = strictCrossAppPackages,
            browserGuardPackages = browserGuardPackages,
            officialTrustedHosts = officialTrustedHosts,
            officialPackageHosts = officialPackageHosts,
            highRiskKeywordSet = highRiskKeywordSet,
            knownMalwareHosts = knownMalwareHosts,
            adPatternProvider = { activeAdPatterns() },
            externalBlockedHostProvider = { loadExternalBlockedHosts() },
        )
    }

    override fun handleLoadPackage(lpparam: XC_LoadPackage.LoadPackageParam) {
        val pkg = (lpparam.packageName ?: "").trim()
        if (pkg.isBlank()) {
            return
        }
        if (pkg == "android" || pkg == "com.android.systemui" || pkg == "com.mrksvt.firewallagent") {
            return
        }
        val isScoped = scopedPackages.contains(pkg)
        val isWebViewBridgeForStrictUid = isWebViewBridgePackageForStrictUid(pkg)
        val isBrowserGuard = isBrowserGuardPackage(pkg)
        if (!isScoped && !isWebViewBridgeForStrictUid && !isBrowserGuard) {
            return
        }
        if (isWebViewBridgeForStrictUid) {
            XposedBridge.log("FA.HybridAdHook allow webview bridge pkg=$pkg for strict uid=${Process.myUid()}")
        }
        if (isBrowserGuard) {
            XposedBridge.log("FA.HybridAdHook browser guard active in $pkg")
        }

        var anyHookFailed = false
        fun runHookGroup(group: String, block: () -> Unit) {
            try {
                XposedBridge.log("FA.HybridAdHook group $group start in $pkg")
                block()
                XposedBridge.log("FA.HybridAdHook group $group done in $pkg")
            } catch (t: Throwable) {
                anyHookFailed = true
                XposedBridge.log(
                    "FA.HybridAdHook group $group failed for $pkg: " +
                        "${t::class.java.name} ${t.message}",
                )
            }
        }

        runHookGroup("webview") {
            hookWebViewLoads(lpparam)
            hookWebViewClientIntercept(lpparam)
            hookWebViewShouldOverrideUrlLoading(lpparam)
        }
        runHookGroup("ad-sdk") {
            hookAdSdkLoads(lpparam)
            hookIronSourceAdapters(lpparam)  // Dedicated IronSource mediation adapter hooks
        }
        runHookGroup("ad-activity") {
            hookAdActivityLifecycles(lpparam)
            hookKnownFullscreenAdActivities(lpparam)
            hookGenericAdUiKillSwitch(lpparam)
        }
        runHookGroup("ad-overlay-bypass") {
            hookAdOverlayAndTimerBypass(lpparam)
        }
        runHookGroup("aggressive-app") {
            hookAggressivePackageMitigations(lpparam)
        }
        runHookGroup("aggressive-network") {
            hookAggressivePackageNetworkLayer(lpparam)
        }
        runHookGroup("launch-guard") {
            hookActivityLaunchGuards(lpparam)
        }
        runHookGroup("atm-guard") {
            hookActivityTaskManagerGuards(lpparam)
        }
        runHookGroup("chrome-guard") {
            hookChromeExternalNavigation(lpparam)
        }
        runHookGroup("download-guard") {
            hookDownloadManagerGuards(lpparam)
        }
        runHookGroup("screenshot-bypass") {
            hookScreenshotBypass(lpparam)
        }

        if (anyHookFailed) {
            XposedBridge.log("FA.HybridAdHook init partial in $pkg")
        } else {
            XposedBridge.log("FA.HybridAdHook init ok in $pkg")
        }

        // Apply DNS hide hooks — prevents apps from detecting Private DNS as active
        // and prevents ad SDK connectivity checks from failing with UnknownHostException
        try {
            dnsHideHook.handleLoadPackage(lpparam)
        } catch (t: Throwable) {
            XposedBridge.log("FA.DnsHideHook init failed for $pkg: ${t.message}")
        }
    }

    private fun hookActivityLaunchGuards(lpparam: XC_LoadPackage.LoadPackageParam) {
        if (!shouldBlockIntentForThisPackage(lpparam.packageName)) {
            XposedBridge.log("FA.HybridAdHook launch guard skip for non-target pkg=${lpparam.packageName}")
            return
        }
        val cl = lpparam.classLoader

        runCatching {
            val activityClass = Class.forName("android.app.Activity", false, cl)
            XposedBridge.hookAllMethods(activityClass, "startActivity", object : XC_MethodHook() {
                override fun beforeHookedMethod(param: MethodHookParam) {
                    val intent = extractIntentFromHookParams(param.args) ?: return
                    val blockReason = getIntentBlockReason(intent, lpparam.packageName) ?: return
                    setBlockedMethodResult(param)
                    XposedBridge.log(
                        "FA.HybridAdHook blocked Activity.startActivity in ${lpparam.packageName}: " +
                            "action=${intent.action} data=${intent.dataString} " +
                            "target=${intent.component?.packageName ?: intent.`package`} reason=$blockReason",
                    )
                }
            })
            XposedBridge.hookAllMethods(activityClass, "startActivityForResult", object : XC_MethodHook() {
                override fun beforeHookedMethod(param: MethodHookParam) {
                    val intent = extractIntentFromHookParams(param.args) ?: return
                    val blockReason = getIntentBlockReason(intent, lpparam.packageName) ?: return
                    setBlockedMethodResult(param)
                    XposedBridge.log(
                        "FA.HybridAdHook blocked Activity.startActivityForResult in ${lpparam.packageName}: " +
                            "action=${intent.action} data=${intent.dataString} " +
                            "target=${intent.component?.packageName ?: intent.`package`} reason=$blockReason",
                    )
                }
            })
            XposedBridge.hookAllMethods(activityClass, "startActivityIfNeeded", object : XC_MethodHook() {
                override fun beforeHookedMethod(param: MethodHookParam) {
                    val intent = extractIntentFromHookParams(param.args) ?: return
                    val blockReason = getIntentBlockReason(intent, lpparam.packageName) ?: return
                    setBlockedMethodResult(param)
                    XposedBridge.log(
                        "FA.HybridAdHook blocked Activity.startActivityIfNeeded in ${lpparam.packageName}: " +
                            "action=${intent.action} data=${intent.dataString} " +
                            "target=${intent.component?.packageName ?: intent.`package`} reason=$blockReason",
                        )
                }
            })
            XposedBridge.hookAllMethods(activityClass, "startIntentSender", object : XC_MethodHook() {
                override fun beforeHookedMethod(param: MethodHookParam) {
                    val intent = extractIntentFromHookParams(param.args) ?: return
                    val blockReason = getIntentBlockReason(intent, lpparam.packageName) ?: return
                    setBlockedMethodResult(param)
                    XposedBridge.log(
                        "FA.HybridAdHook blocked Activity.startIntentSender in ${lpparam.packageName}: " +
                            "action=${intent.action} data=${intent.dataString} reason=$blockReason",
                    )
                }
            })
            XposedBridge.hookAllMethods(activityClass, "startIntentSenderForResult", object : XC_MethodHook() {
                override fun beforeHookedMethod(param: MethodHookParam) {
                    val intent = extractIntentFromHookParams(param.args) ?: return
                    val blockReason = getIntentBlockReason(intent, lpparam.packageName) ?: return
                    setBlockedMethodResult(param)
                    XposedBridge.log(
                        "FA.HybridAdHook blocked Activity.startIntentSenderForResult in ${lpparam.packageName}: " +
                            "action=${intent.action} data=${intent.dataString} reason=$blockReason",
                    )
                }
            })
        }.getOrElse { throw it }

        runCatching {
            val instrClass = Class.forName("android.app.Instrumentation", false, cl)
            XposedBridge.hookAllMethods(instrClass, "execStartActivity", object : XC_MethodHook() {
                override fun beforeHookedMethod(param: MethodHookParam) {
                    val intent = extractIntentFromHookParams(param.args) ?: return
                    val blockReason = getIntentBlockReason(intent, lpparam.packageName) ?: return
                    setBlockedMethodResult(param)
                    XposedBridge.log(
                        "FA.HybridAdHook blocked Instrumentation.execStartActivity in ${lpparam.packageName}: " +
                            "action=${intent.action} data=${intent.dataString} " +
                            "target=${intent.component?.packageName ?: intent.`package`} reason=$blockReason",
                    )
                }
            })
        }.getOrElse { throw it }

        runCatching {
            val ctxClass = Class.forName("android.content.ContextWrapper", false, cl)
            listOf("startActivity", "startActivities", "startActivityAsUser", "startActivityForResult", "startIntentSender", "startIntentSenderAsUser").forEach { method ->
                XposedBridge.hookAllMethods(ctxClass, method, object : XC_MethodHook() {
                    override fun beforeHookedMethod(param: MethodHookParam) {
                        val intent = extractIntentFromHookParams(param.args) ?: return
                        val blockReason = getIntentBlockReason(intent, lpparam.packageName) ?: return
                        setBlockedMethodResult(param)
                        XposedBridge.log(
                            "FA.HybridAdHook blocked ContextWrapper.$method in ${lpparam.packageName}: " +
                                "action=${intent.action} data=${intent.dataString} " +
                                "target=${intent.component?.packageName ?: intent.`package`} reason=$blockReason",
                        )
                    }
                })
            }
            val browserMethodGuards = listOf(
                "androidx.browser.customtabs.CustomTabsIntent", "android.support.customtabs.CustomTabsIntent",
            )
            browserMethodGuards.forEach { className ->
                runCatching {
                    val tabsClass = Class.forName(className, false, cl)
                    XposedBridge.hookAllMethods(tabsClass, "launchUrl", object : XC_MethodHook() {
                        override fun beforeHookedMethod(param: MethodHookParam) {
                            val uri = param.args.getOrNull(1)
                            val target = uri?.toString().orEmpty()
                            if (target.isBlank()) return
                            val launcher = param.args.getOrNull(0)?.javaClass?.name.orEmpty()
                            val parsedUri = runCatching { android.net.Uri.parse(target) }.getOrNull() ?: return
                            val dataIntent = Intent(android.content.Intent.ACTION_VIEW, parsedUri)
                            val blockReason = if (target.isNotBlank()) {
                                getIntentBlockReason(dataIntent, lpparam.packageName)
                            } else {
                                null
                            }
                            if (blockReason == null) return
                            setBlockedMethodResult(param)
                            XposedBridge.log(
                                "FA.HybridAdHook blocked $className.launchUrl in ${lpparam.packageName}: " +
                                    "uri=$target launcher=$launcher reason=$blockReason",
                            )
                        }
                    })
                }
            }
        }.getOrElse { throw it }

        runCatching {
            val ctxImplClass = Class.forName("android.app.ContextImpl", false, cl)
            listOf("startActivity", "startActivities", "startActivityAsUser", "startIntentSender", "startIntentSenderAsUser").forEach { method ->
                XposedBridge.hookAllMethods(ctxImplClass, method, object : XC_MethodHook() {
                    override fun beforeHookedMethod(param: MethodHookParam) {
                        val intent = extractIntentFromHookParams(param.args) ?: return
                        val blockReason = getIntentBlockReason(intent, lpparam.packageName) ?: return
                        setBlockedMethodResult(param)
                        XposedBridge.log(
                            "FA.HybridAdHook blocked ContextImpl.$method in ${lpparam.packageName}: " +
                                "action=${intent.action} data=${intent.dataString} " +
                                "target=${intent.component?.packageName ?: intent.`package`} reason=$blockReason",
                        )
                    }
                })
            }
        }

        runCatching {
            val pendingIntentClass = Class.forName("android.app.PendingIntent", false, cl)
            listOf("getActivity", "getActivities", "getService", "getBroadcast").forEach { method ->
                XposedBridge.hookAllMethods(pendingIntentClass, method, object : XC_MethodHook() {
                    override fun beforeHookedMethod(param: MethodHookParam) {
                        val intent = extractIntentFromHookParams(param.args) ?: return
                        val blockReason = getIntentBlockReason(intent, lpparam.packageName) ?: return
                        setBlockedMethodResult(param)
                        XposedBridge.log(
                            "FA.HybridAdHook blocked PendingIntent.$method in ${lpparam.packageName}: " +
                                "action=${intent.action} data=${intent.dataString} reason=$blockReason",
                        )
                    }
                })
            }
            XposedBridge.hookAllMethods(pendingIntentClass, "send", object : XC_MethodHook() {
                override fun beforeHookedMethod(param: MethodHookParam) {
                    val intent = extractIntentFromHookParams(param.args) ?: return
                    val blockReason = getIntentBlockReason(intent, lpparam.packageName) ?: return
                    setBlockedMethodResult(param)
                    XposedBridge.log(
                        "FA.HybridAdHook blocked PendingIntent.send in ${lpparam.packageName}: " +
                            "action=${intent.action} data=${intent.dataString} reason=$blockReason",
                    )
                }
            })
        }.getOrElse { throw it }
    }

    private fun hookActivityTaskManagerGuards(lpparam: XC_LoadPackage.LoadPackageParam) {
        // Fix: also run ATM guard inside Chrome (browserGuard) and WebView bridge packages
        if (!shouldBlockIntentForThisPackage(lpparam.packageName) &&
            !isBrowserGuardPackage(lpparam.packageName)) return
        val cl = lpparam.classLoader
        val pkg = lpparam.packageName
        runCatching {
            val proxyClass = Class.forName("android.app.IActivityTaskManager\$Stub\$Proxy", false, cl)
            listOf(
                "startActivity",
                "startActivities",
                "startActivityAsUser",
                "startActivityWithConfig",
                "startActivityIntentSender",
                "startNextMatchingActivity",
            ).forEach { method ->
                XposedBridge.hookAllMethods(proxyClass, method, object : XC_MethodHook() {
                    override fun beforeHookedMethod(param: MethodHookParam) {
                        val intent = extractIntentFromHookParams(param.args) ?: return
                        // For browser guard packages, use dedicated gambling/malware check
                        if (isBrowserGuardPackage(pkg)) {
                            val dataString = intent.dataString.orEmpty()
                            val targetPkg = intent.component?.packageName ?: intent.`package` ?: ""
                            if (isMalwareOrGamblingIntent(dataString, targetPkg)) {
                                setBlockedMethodResult(param)
                                XposedBridge.log(
                                    "FA.HybridAdHook blocked IActivityTaskManager.$method in $pkg (browser-guard): " +
                                        "action=${intent.action} data=$dataString target=$targetPkg reason=malware-gambling",
                                )
                            }
                            return
                        }
                        val blockReason = getIntentBlockReason(intent, pkg) ?: return
                        setBlockedMethodResult(param)
                        XposedBridge.log(
                            "FA.HybridAdHook blocked IActivityTaskManager.$method in $pkg: " +
                                "action=${intent.action} data=${intent.dataString} " +
                                "target=${intent.component?.packageName ?: intent.`package`} reason=$blockReason",
                        )
                    }
                })
            }
        }
    }

    private fun hookKnownFullscreenAdActivities(lpparam: XC_LoadPackage.LoadPackageParam) {
        if (!isStrictAdPackage(resolvePolicyPackage(lpparam.packageName))) return
        val cl = lpparam.classLoader
        val candidates = listOf(
            "com.google.android.gms.ads.AdActivity",
            "com.google.ads.AdActivity",
            "com.applovin.adview.AppLovinFullscreenActivity",
            "com.applovin.adview.AppLovinInterstitialActivity",
            "com.ironsource.sdk.controller.ControllerActivity",
            "com.ironsource.mediationsdk.testSuite.TestSuiteActivity",
            "com.unity3d.services.ads.adunit.AdUnitActivity",
            "com.unity3d.services.ads.adunit.AdUnitTransparentActivity",
            "com.vungle.warren.ui.VungleActivity",
            "com.fyber.inneractive.sdk.activities.InneractiveFullscreenAdActivity",
            "com.bytedance.sdk.openadsdk.activity.TTFullScreenVideoActivity",
            "com.bytedance.sdk.openadsdk.activity.TTRewardVideoActivity",
            "com.bytedance.sdk.openadsdk.activity.TTDelegateActivity",
            "com.mbridge.msdk.activity.MBCommonActivity",
            "com.mbridge.msdk.reward.player.MBRewardVideoActivity",
        )
        candidates.forEach { className ->
            val clazz = runCatching { Class.forName(className, false, cl) }.getOrNull() ?: return@forEach
            runCatching {
                XposedBridge.hookAllMethods(clazz, "onResume", object : XC_MethodHook() {
                    override fun afterHookedMethod(param: MethodHookParam) {
                        val activity = param.thisObject as? Activity ?: return
                        runCatching { activity.finish() }
                        XposedBridge.log(
                            "FA.HybridAdHook closed fullscreen ad activity in ${lpparam.packageName}: ${activity.javaClass.name}",
                        )
                    }
                })
            }
        }
    }

    private fun hookGenericAdUiKillSwitch(lpparam: XC_LoadPackage.LoadPackageParam) {
        if (!isStrictAdPackage(resolvePolicyPackage(lpparam.packageName))) return
        val cl = lpparam.classLoader

        runCatching {
            val activityClass = Class.forName("android.app.Activity", false, cl)
            XposedBridge.hookAllMethods(activityClass, "onResume", object : XC_MethodHook() {
                override fun afterHookedMethod(param: MethodHookParam) {
                    val activity = param.thisObject as? Activity ?: return
                    if (shouldSkipGenericAdUiKill(lpparam.packageName, activity)) return
                    val className = activity.javaClass.name.lowercase(Locale.US)
                    if (!isLikelyAdUiClassName(className) && !hasLikelyAdOverlayOnScreen(activity)) return
                    runCatching { activity.finish() }
                    XposedBridge.log("FA.HybridAdHook generic ad-ui close activity in ${lpparam.packageName}: ${activity.javaClass.name}")
                }
            })
        }

        runCatching {
            val dialogClass = Class.forName("android.app.Dialog", false, cl)
            XposedBridge.hookAllMethods(dialogClass, "show", object : XC_MethodHook() {
                override fun afterHookedMethod(param: MethodHookParam) {
                    val dialog = param.thisObject as? Dialog ?: return
                    val className = dialog.javaClass.name.lowercase(Locale.US)
                    if (!isLikelyAdUiClassName(className)) return
                    runCatching { dialog.dismiss() }
                    XposedBridge.log("FA.HybridAdHook generic ad-ui dismiss dialog in ${lpparam.packageName}: ${dialog.javaClass.name}")
                }
            })
        }
    }

    private fun hookAdOverlayAndTimerBypass(lpparam: XC_LoadPackage.LoadPackageParam) {
        if (!isStrictAdPackage(resolvePolicyPackage(lpparam.packageName))) return
        val cl = lpparam.classLoader

        runCatching {
            val countDownTimerClass = Class.forName("android.os.CountDownTimer", false, cl)
            XposedBridge.hookAllMethods(countDownTimerClass, "start", object : XC_MethodHook() {
                override fun beforeHookedMethod(param: MethodHookParam) {
                    val ownerClass = param.thisObject?.javaClass?.name.orEmpty()
                    if (!isLikelyAdUiClassName(ownerClass.lowercase(Locale.US))) return
                    runCatching { param.thisObject?.javaClass?.getMethod("cancel")?.invoke(param.thisObject) }
                    invokeTimerFinish(param.thisObject)
                    param.result = param.thisObject
                    XposedBridge.log(
                        "FA.HybridAdHook bypassed CountDownTimer.start in ${lpparam.packageName}: $ownerClass",
                    )
                }
            })
        }

        runCatching {
            val handlerClass = Class.forName("android.os.Handler", false, cl)
            XposedBridge.hookAllMethods(handlerClass, "postDelayed", object : XC_MethodHook() {
                override fun beforeHookedMethod(param: MethodHookParam) {
                    val policyPkg = resolvePolicyPackage(lpparam.packageName)
                    if (policyPkg == "com.worldance.drama") return
                    val runnable = param.args.getOrNull(0) as? Runnable ?: return
                    val delay = (param.args.getOrNull(1) as? Long) ?: return
                    if (delay <= 250L) return
                    val runnableName = runnable.javaClass.name.lowercase(Locale.US)
                    if (!isLikelyAdUiClassName(runnableName)) return
                    param.args[1] = 80L
                    logNetworkEventOnce(
                        dedupKey = "short-delay|${lpparam.packageName}|${runnable.javaClass.name}|$delay",
                        message = "FA.HybridAdHook shortened ad delay in ${lpparam.packageName}: " +
                            "runnable=${runnable.javaClass.name} from=${delay}ms to=80ms",
                        ttlMs = 8_000L,
                    )
                }
            })
        }

        runCatching {
            val viewGroupClazz = Class.forName("android.view.ViewGroup", false, cl)
            XposedBridge.hookAllMethods(viewGroupClazz, "addView", object : XC_MethodHook() {
                override fun beforeHookedMethod(param: MethodHookParam) {
                    val child = param.args.firstOrNull() as? android.view.View ?: return
                    val parent = param.thisObject as? android.view.ViewGroup
                    if (shouldAllowHybridRendererView(lpparam.packageName, child, parent)) return
                    if (!looksLikeDynamicAdOverlay(child, parent)) return
                    suppressAdViewInstance(child, lpparam.packageName, "ViewGroup.addView.dynamic-overlay")
                    param.result = null
                    XposedBridge.log(
                        "FA.HybridAdHook blocked dynamic ad overlay addView in ${lpparam.packageName}: " +
                            "child=${child.javaClass.name} parent=${parent?.javaClass?.name.orEmpty()}",
                    )
                }
            })
        }
    }

    private fun shouldAllowHybridRendererView(
        packageName: String,
        child: android.view.View,
        parent: android.view.ViewGroup?,
    ): Boolean {
        val policyPkg = resolvePolicyPackage(packageName)
        if (policyPkg != "com.worldance.drama") return false
        val childName = child.javaClass.name.lowercase(Locale.US)
        val parentName = parent?.javaClass?.name.orEmpty().lowercase(Locale.US)
        val hybridMarkers = listOf(
            "com.bytedance.hybrid.spark.page.sparkview",
            "com.bytedance.lynx.hybrid.lynxkitview",
            "com.lynx.tasm.behavior.ui.",
        )
        val childHybrid = hybridMarkers.any { childName.contains(it) }
        val parentHybrid = hybridMarkers.any { parentName.contains(it) }
        if (childHybrid || parentHybrid) {
            XposedBridge.log(
                "FA.HybridAdHook allow hybrid renderer view in $packageName: " +
                    "child=${child.javaClass.name} parent=${parent?.javaClass?.name.orEmpty()}",
            )
            return true
        }
        return false
    }

    private fun invokeTimerFinish(timer: Any?) {
        if (timer == null) return
        var cls: Class<*>? = timer.javaClass
        while (cls != null) {
            val currentClass = cls
            val finish = runCatching {
                currentClass.declaredMethods.firstOrNull { it.name == "onFinish" && it.parameterCount == 0 }
            }.getOrNull()
            if (finish != null) {
                runCatching {
                    finish.isAccessible = true
                    finish.invoke(timer)
                }
                return
            }
            cls = cls.superclass
        }
    }

    private fun hasLikelyAdOverlayOnScreen(activity: Activity): Boolean {
        val root = runCatching { activity.window?.decorView as? android.view.ViewGroup }.getOrNull() ?: return false
        return containsAdOverlayView(root, depth = 0)
    }

    private fun containsAdOverlayView(view: android.view.View, depth: Int): Boolean {
        if (depth > 4) return false
        if (looksLikeDynamicAdOverlay(view, view.parent as? android.view.ViewGroup)) return true
        val group = view as? android.view.ViewGroup ?: return false
        for (i in 0 until group.childCount) {
            val child = group.getChildAt(i) ?: continue
            if (containsAdOverlayView(child, depth + 1)) return true
        }
        return false
    }

    private fun looksLikeDynamicAdOverlay(
        child: android.view.View,
        parent: android.view.ViewGroup?,
    ): Boolean {
        val childName = child.javaClass.name.lowercase(Locale.US)
        val parentName = parent?.javaClass?.name.orEmpty().lowercase(Locale.US)
        val idName = runCatching {
            val id = child.id
            if (id == android.view.View.NO_ID) "" else child.resources.getResourceEntryName(id).lowercase(Locale.US)
        }.getOrDefault("")
        if (isLikelyAdUiClassName(childName) || isLikelyAdUiClassName(parentName) || isLikelyAdUiClassName(idName)) {
            return true
        }
        val isWebOrVideo = childName.contains("webview") ||
            childName.contains("surfaceview") ||
            childName.contains("textureview")
        val parentLooksInterstitial = parentName.contains("interstitial") ||
            parentName.contains("reward") ||
            parentName.contains("splash") ||
            parentName.contains("endcard") ||
            idName.contains("interstitial") ||
            idName.contains("reward") ||
            idName.contains("splash") ||
            idName.contains("endcard")
        return isWebOrVideo && parentLooksInterstitial
    }

    private fun isLikelyAdUiClassName(classNameLower: String): Boolean {
        if (classNameLower.isBlank()) return false
        val keywords = listOf(
            "adactivity",
            "adview",
            "nativead",
            "bannerad",
            "adsdk",
            "googleads",
            "doubleclick",
            "interstitial",
            "reward",
            "rewarded",
            "fullscreen",
            "splashad",
            "splash",
            "offerwall",
            "endcard",
            "crosspromo",
            "adcontainer",
            "openad",
            "mbridge",
            "pangle",
            "bytedance",
            "vungle",
            "applovin",
            "ironsource",
            "unityads",
            "admob",
            "adcolony",
            "adx",
            "taxssp",
            "fyber",
            "inneractive",
            "adcolony",
            "inmobi",
            "chartboost",
            "mytarget",
        )
        return keywords.any { classNameLower.contains(it) }
    }

    private fun hookScreenshotBypass(lpparam: XC_LoadPackage.LoadPackageParam) {
        if (!isStrictAdPackage(resolvePolicyPackage(lpparam.packageName))) return
        val cl = lpparam.classLoader
        val flagSecure = runCatching { WindowManager.LayoutParams.FLAG_SECURE }.getOrDefault(0x00002000)

        runCatching {
            val windowClass = Class.forName("android.view.Window", false, cl)
            XposedBridge.hookAllMethods(windowClass, "setFlags", object : XC_MethodHook() {
                override fun beforeHookedMethod(param: MethodHookParam) {
                    val flags = (param.args.getOrNull(0) as? Int) ?: return
                    val mask = (param.args.getOrNull(1) as? Int) ?: return
                    if ((mask and flagSecure) == 0) return
                    param.args[0] = flags and flagSecure.inv()
                    param.args[1] = mask and flagSecure.inv()
                    XposedBridge.log("FA.HybridAdHook screenshot bypass setFlags in ${lpparam.packageName}")
                }
            })
            XposedBridge.hookAllMethods(windowClass, "addFlags", object : XC_MethodHook() {
                override fun beforeHookedMethod(param: MethodHookParam) {
                    val flags = (param.args.getOrNull(0) as? Int) ?: return
                    if ((flags and flagSecure) == 0) return
                    param.args[0] = flags and flagSecure.inv()
                    XposedBridge.log("FA.HybridAdHook screenshot bypass addFlags in ${lpparam.packageName}")
                }
            })
            XposedBridge.hookAllMethods(windowClass, "setAttributes", object : XC_MethodHook() {
                override fun beforeHookedMethod(param: MethodHookParam) {
                    val lp = param.args.getOrNull(0) as? WindowManager.LayoutParams ?: return
                    if ((lp.flags and flagSecure) == 0) return
                    lp.flags = lp.flags and flagSecure.inv()
                    XposedBridge.log("FA.HybridAdHook screenshot bypass setAttributes in ${lpparam.packageName}")
                }
            })
        }

        runCatching {
            val activityClass = Class.forName("android.app.Activity", false, cl)
            XposedBridge.hookAllMethods(activityClass, "onResume", object : XC_MethodHook() {
                override fun afterHookedMethod(param: MethodHookParam) {
                    val activity = param.thisObject as? Activity ?: return
                    runCatching { activity.window?.clearFlags(flagSecure) }
                }
            })
        }

        runCatching {
            val dialogClass = Class.forName("android.app.Dialog", false, cl)
            listOf("show", "onStart").forEach { method ->
                XposedBridge.hookAllMethods(dialogClass, method, object : XC_MethodHook() {
                    override fun afterHookedMethod(param: MethodHookParam) {
                        val dialog = param.thisObject as? Dialog ?: return
                        runCatching {
                            dialog.window?.clearFlags(flagSecure)
                            val attrs = dialog.window?.attributes
                            if (attrs != null && (attrs.flags and flagSecure) != 0) {
                                attrs.flags = attrs.flags and flagSecure.inv()
                                dialog.window?.attributes = attrs
                            }
                        }
                    }
                })
            }
        }

        runCatching {
            val surfaceViewClass = Class.forName("android.view.SurfaceView", false, cl)
            XposedBridge.hookAllMethods(surfaceViewClass, "setSecure", object : XC_MethodHook() {
                override fun beforeHookedMethod(param: MethodHookParam) {
                    if (param.args.isNotEmpty()) {
                        param.args[0] = false
                    }
                }
            })
        }
    }

    /**
     * Returns true when a URL string or target package looks like a gambling / malware destination.
     * Used for the browser-guard path where we do not want to block ALL external launches,
     * only launches that lead to known-bad content.
     */
    private fun isMalwareOrGamblingIntent(dataString: String, targetPkg: String): Boolean {
        if (dataString.isBlank() && targetPkg.isBlank()) return false
        val lowerData = dataString.lowercase(Locale.US)
        val lowerTarget = targetPkg.lowercase(Locale.US)
        // Block if data URL host matches known malware hosts
        val dataHost = runCatching { android.net.Uri.parse(dataString).host.orEmpty().lowercase(Locale.US) }.getOrDefault("")
        if (dataHost.isNotBlank()) {
            if (knownMalwareHosts.any { dataHost == it || dataHost.endsWith(".$it") || dataHost.contains(it) }) return true
            if (loadExternalBlockedHosts().let { feed -> feed.isNotEmpty() && isFeedBlockedHostDirect(dataHost, feed) }) return true
        }
        // Block if URL contains gambling keywords
        if (dataHost.isNotBlank() && containsAdultOrGamblingKeyword(lowerData, dataHost)) return true
        // Block if target package is not a known safe browser or app
        if (lowerTarget.isNotBlank()) {
            if (knownMalwareHosts.any { lowerTarget.contains(it.substringBefore('.')) }) return true
        }
        return false
    }

    private fun isFeedBlockedHostDirect(hostLower: String, feed: Set<String>): Boolean {
        var candidate = hostLower.trim().trimStart('.')
        while (true) {
            if (feed.contains(candidate)) return true
            val dot = candidate.indexOf('.')
            if (dot <= 0 || dot >= candidate.length - 1) return false
            candidate = candidate.substring(dot + 1)
        }
    }

    private fun setBlockedMethodResult(param: XC_MethodHook.MethodHookParam) {
        val returnType = runCatching {
            val field = runCatching { param.javaClass.getDeclaredField("method") }
                .recoverCatching { param.javaClass.getField("method") }
                .getOrNull()
                ?: return@runCatching null
            field.isAccessible = true
            (field.get(param) as? Method)?.returnType
        }.getOrNull()
        when (returnType) {
            null, java.lang.Void.TYPE -> param.result = null
            java.lang.Boolean.TYPE -> param.result = false
            java.lang.Integer.TYPE -> param.result = resolveStartCanceledCode()
            java.lang.Long.TYPE -> param.result = 0L
            java.lang.Float.TYPE -> param.result = 0f
            java.lang.Double.TYPE -> param.result = 0.0
            java.lang.Short.TYPE -> param.result = 0.toShort()
            java.lang.Byte.TYPE -> param.result = 0.toByte()
            java.lang.Character.TYPE -> param.result = 0.toChar()
            else -> param.result = null
        }
    }

    private fun resolveStartCanceledCode(): Int {
        return runCatching {
            val am = Class.forName("android.app.ActivityManager")
            val field = am.getDeclaredField("START_CANCELED")
            field.isAccessible = true
            field.getInt(null)
        }.getOrDefault(-96)
    }

    private fun shouldBlockIntentForThisPackage(pkg: String): Boolean {
        // Fix: guard ALL webview bridge packages unconditionally (not just when UID matches),
        // because the hook runs inside the WebView process itself — if an ad SDK in the host app
        // caused the WebView process to open a URL, we must block it regardless of UID check.
        return strictAdPackages.contains(pkg) ||
            webViewBridgePackages.contains(pkg) ||
            isWebViewBridgePackageForStrictUid(pkg)
    }

    private fun isBrowserGuardPackage(pkg: String): Boolean {
        return browserGuardPackages.contains(pkg)
    }

    private fun isWebViewBridgePackageForStrictUid(pkg: String): Boolean {
        if (!webViewBridgePackages.contains(pkg)) return false
        val app = runCatching {
            val activityThread = Class.forName("android.app.ActivityThread")
            val currentApplication = activityThread.getMethod("currentApplication").invoke(null)
            currentApplication as? Application
        }.getOrNull() ?: return false
        val packagesForUid = runCatching {
            app.packageManager.getPackagesForUid(Process.myUid())?.mapNotNull { it }?.toList().orEmpty()
        }.getOrDefault(emptyList())
        return packagesForUid.any { strictAdPackages.contains(it) }
    }

    private fun hookDownloadManagerGuards(lpparam: XC_LoadPackage.LoadPackageParam) {
        val pkg = lpparam.packageName
        if (!shouldBlockIntentForThisPackage(pkg) && !isBrowserGuardPackage(pkg)) return
        val cl = lpparam.classLoader
        runCatching {
            val dmClass = Class.forName("android.app.DownloadManager", false, cl)
            XposedBridge.hookAllMethods(dmClass, "enqueue", object : XC_MethodHook() {
                override fun beforeHookedMethod(param: MethodHookParam) {
                    val request = param.args.firstOrNull() ?: return
                    val uriString = runCatching {
                        val method = request.javaClass.getMethod("getUri")
                        (method.invoke(request) as? Uri)?.toString().orEmpty()
                    }.recoverCatching {
                        val field = request.javaClass.getDeclaredField("mUri")
                        field.isAccessible = true
                        (field.get(request) as? Uri)?.toString().orEmpty()
                    }.getOrDefault("")
                    if (uriString.isBlank()) return
                    val decision = requestDecisionEngine.evaluateNetwork(
                        pkg = pkg,
                        urlString = uriString,
                        method = "DOWNLOAD",
                        isDownload = true,
                    )
                    if (decision.action != DecisionAction.BLOCK) return
                    param.result = -1L
                    XposedBridge.log("FA.HybridAdHook blocked DownloadManager.enqueue in $pkg: $uriString reason=${decision.reason}")
                }
            })
        }
    }

    private fun extractIntentFromHookParams(args: Array<out Any?>): Intent? {
        args.firstOrNull { it is Intent }?.let { return it as Intent }
        args.forEach { arg ->
            val intentFromArray = when (arg) {
                is Array<*> -> arg.firstOrNull { it is Intent } as? Intent
                is kotlin.Array<*> -> arg.firstOrNull { it is Intent } as? Intent
                is java.util.ArrayList<*> -> arg.firstOrNull { it is Intent } as? Intent
                else -> null
            }
            if (intentFromArray != null) return intentFromArray
        }
        args.forEach { arg ->
            when (arg) {
                is String -> runCatching { Intent.parseUri(arg, Intent.URI_INTENT_SCHEME) }.getOrNull()?.let { return it }
                is android.net.Uri -> return Intent(Intent.ACTION_VIEW, arg)
                else -> Unit
            }
        }
        return null
    }

    private fun getIntentBlockReason(intent: Intent, sourcePkg: String): String? {
        return getIntentBlockReasonInternal(intent, sourcePkg, 0)
    }

    private fun getIntentBlockReasonInternal(intent: Intent, sourcePkg: String, depth: Int): String? {
        if (depth > 3) return "nested-intent-depth-exceeded"
        extractNestedIntents(intent).forEach { nested ->
            val nestedReason = getIntentBlockReasonInternal(nested, sourcePkg, depth + 1)
            if (nestedReason != null) return "nested-intent:$nestedReason"
        }
        val action = intent.action.orEmpty()
        val data = intent.data
        val dataString = data?.toString().orEmpty()
        val targetPkg = intent.component?.packageName ?: intent.`package`
        val policyPkg = resolvePolicyPackage(sourcePkg)
        val payloadUrl = extractCandidateUrlFromIntent(intent)
        val embeddedDataUrl = extractEmbeddedUrlCandidate(dataString)
        val effectiveData = when {
            dataString.isNotBlank() -> dataString
            payloadUrl.isNotBlank() -> payloadUrl
            else -> embeddedDataUrl
        }
        val decision = requestDecisionEngine.evaluateIntent(
            pkg = policyPkg,
            action = action,
            dataString = effectiveData,
            targetPackage = targetPkg.orEmpty(),
            mime = intent.type.orEmpty(),
        )
        if (decision.action == DecisionAction.BLOCK) return decision.reason
        val payloadLower = payloadUrl.lowercase(Locale.US)
        val embeddedLower = embeddedDataUrl.lowercase(Locale.US)
        if (payloadLower.isNotBlank()) {
            val payloadHost = runCatching { Uri.parse(payloadUrl).host.orEmpty().lowercase(Locale.US) }.getOrDefault("")
            if (isHighRiskNavigationUrl(payloadLower) || isKnownAdRedirectUrl(payloadLower, payloadHost, policyPkg) || containsAdultOrGamblingKeyword(payloadLower, payloadHost)) {
                return "payload-url-high-risk"
            }
        }
        if (embeddedLower.isNotBlank()) {
            val embeddedHost = runCatching { Uri.parse(embeddedDataUrl).host.orEmpty().lowercase(Locale.US) }.getOrDefault("")
            if (isHighRiskNavigationUrl(embeddedLower) || isKnownAdRedirectUrl(embeddedLower, embeddedHost, policyPkg) || containsAdultOrGamblingKeyword(embeddedLower, embeddedHost)) {
                return "embedded-url-high-risk"
            }
        }
        if (isStrictAdPackage(policyPkg) &&
            !isRelaxedStrictPackage(policyPkg) &&
            action.equals(Intent.ACTION_VIEW, ignoreCase = true) &&
            (dataString.startsWith("http://", true) ||
                dataString.startsWith("https://", true) ||
                dataString.startsWith("intent://", true) ||
                dataString.startsWith("market://", true) ||
                payloadLower.isNotBlank() ||
                embeddedLower.isNotBlank())
        ) {
            return "strict-action-view-block"
        }
        if (isStrictAdPackage(policyPkg) &&
            !isRelaxedStrictPackage(policyPkg) &&
            !targetPkg.isNullOrBlank() &&
            targetPkg != policyPkg
        ) {
            return "strict-cross-app-block target=$targetPkg"
        }
        if (isStrictAdPackage(policyPkg) &&
            !isRelaxedStrictPackage(policyPkg) &&
            action.equals(Intent.ACTION_CHOOSER, ignoreCase = true)
        ) {
            return "strict-chooser-block"
        }
        if (targetPkg.orEmpty().lowercase(Locale.US).contains("chrome") && dataString.isBlank() && payloadLower.isBlank()) {
            return "external-browser-launch"
        }
        return if (!targetPkg.isNullOrBlank() && targetPkg != policyPkg && isRiskyPackage(targetPkg)) "target package risk=$targetPkg" else null
    }

    private fun extractNestedIntents(intent: Intent): List<Intent> {
        val out = ArrayList<Intent>(4)
        val extras = runCatching { intent.extras }.getOrNull()
        val chooserBase = runCatching { extras?.get(Intent.EXTRA_INTENT) as? Intent }.getOrNull()
        if (chooserBase != null) out += chooserBase
        val initial = runCatching { extras?.get(Intent.EXTRA_INITIAL_INTENTS) as? Array<*> }.getOrNull().orEmpty()
        initial.forEach { item ->
            val nested = item as? Intent
            if (nested != null) out += nested
        }
        val clipData = runCatching { intent.clipData }.getOrNull()
        if (clipData != null) {
            for (i in 0 until clipData.itemCount) {
                val nested = runCatching { clipData.getItemAt(i).intent }.getOrNull()
                if (nested != null) out += nested
            }
        }
        return out
    }

    private fun isKnownAdRedirectUrl(urlLower: String, hostLower: String, sourcePkg: String): Boolean {
        if (urlLower.isBlank()) return false
        if (isStrictAdPackage(sourcePkg)) {
            if (urlLower.contains("intent://") || urlLower.startsWith("market://")) return true
            if (isHighConfidenceAdSignal(urlLower)) return true
            if (looksLikeAdNetworkUrl(urlLower, hostLower)) return true
            if (containsAdultOrGamblingKeyword(urlLower, hostLower)) return true
            if (urlLower.contains("ad_group_id=") || urlLower.contains("creative_id=") || urlLower.contains("auction_id=")) return true
            if (urlLower.contains("/mintegral/") || urlLower.contains("/vast/")) return true
            if (hostLower.contains("liftoff") || hostLower.contains("mintegral")) return true
            return false
        }
        return isHighRiskNavigationUrl(urlLower) || isLikelyRedirectHost(urlLower) || isLikelyTrackerUrl(urlLower)
    }

    private fun isStrictAdPackage(pkg: String): Boolean = strictAdPackages.contains(pkg)

    private fun isRelaxedStrictPackage(pkg: String): Boolean = relaxedStrictPackages.contains(pkg)

    private fun shouldSkipGenericAdUiKill(sourcePkg: String, activity: Activity): Boolean {
        val policyPkg = resolvePolicyPackage(sourcePkg)
        if (!isRelaxedStrictPackage(policyPkg)) return false
        val className = activity.javaClass.name.lowercase(Locale.US)
        return className.contains("activitysplash") ||
            className.contains(".splashactivity") ||
            className.endsWith(".splash")
    }

    private fun isHighRiskExternalJump(intent: Intent, sourcePkg: String): Boolean {
        return getIntentBlockReason(intent, sourcePkg) != null
    }

    private fun isRiskyPackage(pkg: String): Boolean {
        val lower = pkg.lowercase(Locale.US)
        return riskyClickRedirectPackages.any { lower.contains(it) }
    }

    private fun isHighRiskHost(hostLower: String): Boolean {
        return hostLower.contains("shopee") ||
            hostLower.contains("go.onelink") ||
            hostLower.contains("lazada") ||
            hostLower.contains("tokopedia") ||
            hostLower.contains("bukalapak")
    }

    private fun isLikelyRedirectHost(urlLower: String): Boolean {
        if (urlLower.isBlank()) return false
        return urlLower.contains("l.facebook.com") ||
            urlLower.contains("l.instagram.com") ||
            urlLower.contains("t.co/") ||
            urlLower.contains("bit.ly") ||
            urlLower.contains("goo.gl") ||
            urlLower.contains("amzn.to") ||
            urlLower.contains("adclick") ||
            urlLower.contains("click.") ||
            urlLower.contains("install=")
    }

    private fun isLikelyTrackerUrl(urlLower: String): Boolean {
        if (urlLower.isBlank()) return false
        return urlLower.contains("af_click") ||
            urlLower.contains("click_id=") ||
            urlLower.contains("utm_") ||
            urlLower.contains("fbclid=") ||
            urlLower.contains("gclid=") ||
            urlLower.contains("msclkid=") ||
            urlLower.contains("click_id")
    }

    /**
     * Hooks IronSource mediation adapters for all partner networks.
     *
     * Context: When you see logcat "impression-east.liftoff.io/ironsource/beacon",
     * the ad has ALREADY rendered via native IronSource→Liftoff adapter, not WebView.
     * The WebView intercept only catches the impression beacon (which is too late).
     *
     * Solution: Hook the IronSource mediation adapter classes directly so:
     *   1. Adapter's loadAd()/showAd() returns null before ad is fetched
     *   2. IronSource's own banner loading pipeline is terminated
     *   3. Covers both old (is4- prefix) and new SDK adapter namespaces
     */
    private fun hookIronSourceAdapters(lpparam: XC_LoadPackage.LoadPackageParam) {
        val cl = lpparam.classLoader

        // ─── IronSource Liftoff Monetize adapter (most common for Liftoff via IS) ───
        val liftoffAdapterClasses = listOf(
            "com.ironsource.adapters.liftoffmonetize.LiftoffMonetizeBannerAdapter",
            "com.ironsource.adapters.liftoffmonetize.LiftoffMonetizeInterstitialAdapter",
            "com.ironsource.adapters.liftoffmonetize.LiftoffMonetizeRewardedVideoAdapter",
            "com.ironsource.adapters.liftoffmonetize.LiftoffMonetizeNativeAdapter",
            // Older namespace
            "com.ironsource.adapters.vungle.VungleBannerAdapter",
            "com.ironsource.adapters.vungle.VungleInterstitialAdapter",
            "com.ironsource.adapters.vungle.VungleRewardedVideoAdapter",
        )
        val adapterLoadMethods = listOf("loadAd", "showAd", "fetchAd", "renderAd", "onAdReadyToShow", "requestAd")
        liftoffAdapterClasses.forEach { className ->
            val clazz = runCatching { Class.forName(className, false, cl) }.getOrNull() ?: return@forEach
            adapterLoadMethods.forEach { method ->
                runCatching {
                    XposedBridge.hookAllMethods(clazz, method, object : XC_MethodHook() {
                        override fun beforeHookedMethod(param: MethodHookParam) {
                            param.result = null
                            XposedBridge.log("FA.HybridAdHook blocked IronSource adapter ${className}#${method} in ${lpparam.packageName}")
                        }
                    })
                }
            }
        }

        // ─── IronSource AppLovin adapter ───
        val appLovinAdapterClasses = listOf(
            "com.ironsource.adapters.applovin.AppLovinBannerAdapter",
            "com.ironsource.adapters.applovin.AppLovinInterstitialAdapter",
            "com.ironsource.adapters.applovin.AppLovinRewardedVideoAdapter",
        )
        appLovinAdapterClasses.forEach { className ->
            val clazz = runCatching { Class.forName(className, false, cl) }.getOrNull() ?: return@forEach
            adapterLoadMethods.forEach { method ->
                runCatching {
                    XposedBridge.hookAllMethods(clazz, method, object : XC_MethodHook() {
                        override fun beforeHookedMethod(param: MethodHookParam) {
                            param.result = null
                            XposedBridge.log("FA.HybridAdHook blocked IS-AppLovin adapter ${method} in ${lpparam.packageName}")
                        }
                    })
                }
            }
        }

        // ─── IronSource UnityAds adapter ───
        val unityAdapterClasses = listOf(
            "com.ironsource.adapters.unityads.UnityAdsBannerAdapter",
            "com.ironsource.adapters.unityads.UnityAdsInterstitialAdapter",
            "com.ironsource.adapters.unityads.UnityAdsRewardedVideoAdapter",
        )
        unityAdapterClasses.forEach { className ->
            val clazz = runCatching { Class.forName(className, false, cl) }.getOrNull() ?: return@forEach
            adapterLoadMethods.forEach { method ->
                runCatching {
                    XposedBridge.hookAllMethods(clazz, method, object : XC_MethodHook() {
                        override fun beforeHookedMethod(param: MethodHookParam) {
                            param.result = null
                        }
                    })
                }
            }
        }

        // ─── IronSource AdMob/GMA adapter ───
        val admobAdapterClasses = listOf(
            "com.ironsource.adapters.admob.AdMobBannerAdapter",
            "com.ironsource.adapters.admob.AdMobInterstitialAdapter",
            "com.ironsource.adapters.admob.AdMobRewardedVideoAdapter",
        )
        admobAdapterClasses.forEach { className ->
            val clazz = runCatching { Class.forName(className, false, cl) }.getOrNull() ?: return@forEach
            adapterLoadMethods.forEach { method ->
                runCatching {
                    XposedBridge.hookAllMethods(clazz, method, object : XC_MethodHook() {
                        override fun beforeHookedMethod(param: MethodHookParam) {
                            param.result = null
                        }
                    })
                }
            }
        }

        // ─── IronSource BannerView — block at the View level so nothing renders ───
        runCatching {
            val bannerViewClazz = Class.forName(
                "com.ironsource.mediationsdk.ISBannerLayout",
                false, cl
            )
            XposedBridge.hookAllMethods(bannerViewClazz, "addView", object : XC_MethodHook() {
                override fun beforeHookedMethod(param: MethodHookParam) {
                    // Only block if the added view appears to be an ad view
                    param.result = null
                    XposedBridge.log("FA.HybridAdHook blocked ISBannerLayout.addView in ${lpparam.packageName}")
                }
            })
        }

        // ─── IronSource network manager — cuts all ad calls at transport level ───
        runCatching {
            val netMgrClazz = Class.forName(
                "com.ironsource.mediationsdk.sdk.ISMediationManager",
                false, cl
            )
            listOf("initBanners", "loadBanner", "showBanner",
                "initInterstitial", "loadInterstitial", "showInterstitial",
                "initRewardedVideo", "loadRewardedVideo", "showRewardedVideo").forEach { method ->
                runCatching {
                    XposedBridge.hookAllMethods(netMgrClazz, method, object : XC_MethodHook() {
                        override fun beforeHookedMethod(param: MethodHookParam) {
                            param.result = null
                            XposedBridge.log("FA.HybridAdHook blocked IS MediationManager.$method in ${lpparam.packageName}")
                        }
                    })
                }
            }
        }

        // ─── IronSource Banner Presenter / internal refresh — stops retry loop ───
        // When IronSource#loadBanner returns null, IS internally retries via
        // BannerPresenter. Block at origination to stop retry spam.
        val isBannerInternalClasses = listOf(
            "com.ironsource.mediationsdk.BannerLayout",
            "com.ironsource.mediationsdk.ISBannerLayout",
            // Placement models drive retry scheduling
            "com.ironsource.mediationsdk.placement.BannerPlacementModel",
            "com.ironsource.mediationsdk.placement.PlacementManager",
            // Banner Presenter drives the actual ad fetch
            "com.ironsource.sdk.presenter.BannerPresenter",
        )
        isBannerInternalClasses.forEach { className ->
            val clazz = runCatching { Class.forName(className, false, cl) }.getOrNull() ?: return@forEach
            listOf("startAutoRefresh", "stopAutoRefresh", "loadAd",
                "showAd", "refresh", "fetchAd", "loadNextAd").forEach { method ->
                runCatching {
                    XposedBridge.hookAllMethods(clazz, method, object : XC_MethodHook() {
                        override fun beforeHookedMethod(param: MethodHookParam) {
                            param.result = null
                        }
                    })
                }
            }
        }

        // ─── UnityAds via IronSource mediator ───
        // IronSource delegates to UnityAds internally via its own adapter bridge.
        // Hook the UnityAds SDK classes that IronSource calls.
        val unityAdsDirectClasses = listOf(
            "com.unity3d.ads.UnityAds",
            "com.unity3d.services.banners.UnityBanners",
            "com.unity3d.services.banners.BannerView",
            "com.unity3d.ads.IUnityAdsLoadListener",
        )
        unityAdsDirectClasses.forEach { className ->
            val clazz = runCatching { Class.forName(className, false, cl) }.getOrNull() ?: return@forEach
            listOf("load", "show", "loadBanner", "destroy").forEach { method ->
                runCatching {
                    XposedBridge.hookAllMethods(clazz, method, object : XC_MethodHook() {
                        override fun beforeHookedMethod(param: MethodHookParam) {
                            param.result = null
                            XposedBridge.log("FA.HybridAdHook blocked UnityAds direct $className#$method in ${lpparam.packageName}")
                        }
                    })
                }
            }
        }
    }





    private fun hookAdSdkLoads(lpparam: XC_LoadPackage.LoadPackageParam) {
        val sdkHooks = listOf(
            // Google Mobile Ads
            "com.google.android.gms.ads.AdView" to listOf("loadAd"),
            "com.google.android.gms.ads.BaseAdView" to listOf("loadAd"),
            "com.google.android.gms.ads.AdLoader" to listOf("loadAd", "loadAds"),
            "com.google.android.gms.ads.InterstitialAd" to listOf("load"),
            "com.google.android.gms.ads.appopen.AppOpenAd" to listOf("load"),
            "com.google.android.gms.ads.rewarded.RewardedAd" to listOf("load"),
            "com.google.android.gms.ads.rewardedinterstitial.RewardedInterstitialAd" to listOf("load"),
            "com.google.android.gms.ads.AdManagerInterstitialAd" to listOf("load"),
            "com.google.android.gms.ads.nativead.NativeAd" to listOf("load"),
            // AppLovin MAX
            "com.applovin.mediation.ads.MaxAdView" to listOf("loadAd", "startAutoRefresh"),
            "com.applovin.mediation.ads.MaxInterstitialAd" to listOf("loadAd", "showAd"),
            "com.applovin.mediation.ads.MaxRewardedAd" to listOf("loadAd", "showAd"),
            "com.applovin.sdk.AppLovinAdService" to listOf("loadNextAd", "loadNextAdForZoneId"),
            // Unity Ads
            "com.unity3d.ads.UnityAds" to listOf("load", "show"),
            // IronSource core
            "com.ironsource.mediationsdk.IronSource" to listOf(
                "loadInterstitial", "showInterstitial",
                "loadRewardedVideo", "showRewardedVideo",
                "loadBanner", "displayBanner", "destroyBanner",
                "loadISDemandOnlyInterstitial", "showISDemandOnlyInterstitial",
                "loadISDemandOnlyRewardedVideo", "showISDemandOnlyRewardedVideo",
            ),
            // NOTE: Do NOT hook ISBannerSize#getDescription — it's a data getter
            // and returning null causes IronSource internal retry loop (spam in logcat).
            // The banner is already blocked at loadBanner() level above.
            // Vungle (legacy + new)
            "com.vungle.warren.Vungle" to listOf("loadAd", "playAd"),
            "com.vungle.warren.Banners" to listOf("loadBanner"),
            "com.vungle.ads.VungleAds" to listOf("loadAd", "showAd"),
            "com.vungle.ads.BaseFullscreenAd" to listOf("loadAd", "show"),
            "com.vungle.ads.InterstitialAd" to listOf("load", "show"),
            "com.vungle.ads.RewardedAd" to listOf("load", "show"),
            "com.vungle.ads.BannerAd" to listOf("load", "getBannerView"),
            // Meta Audience Network
            "com.facebook.ads.AdView" to listOf("loadAd"),
            "com.facebook.ads.InterstitialAd" to listOf("loadAd", "show"),
            "com.facebook.ads.RewardedVideoAd" to listOf("loadAd", "show"),
            // Pangle / TikTok Ads
            "com.bytedance.sdk.openadsdk.TTAdSdk" to listOf("init"),
            "com.bytedance.sdk.openadsdk.TTAdNative" to listOf(
                "loadBannerExpressAd",
                "loadNativeExpressAd",
                "loadExpressDrawFeedAd",
                "loadFeedAd",
                "loadFullScreenVideoAd",
                "loadRewardVideoAd",
                "loadInteractionExpressAd",
                "loadNativeAd",
                "loadSplashAd",
                "loadDrawFeedAd",
                "loadStream",
            ),
            "com.bytedance.sdk.openadsdk.TTAdLoader" to listOf(
                "loadFeedAd",
                "loadNativeAd",
                "loadSplashAd",
                "loadRewardVideoAd",
                "loadFullScreenVideoAd",
            ),
            "com.bytedance.sdk.openadsdk.TTRewardVideoAd" to listOf("showRewardVideoAd"),
            "com.bytedance.sdk.openadsdk.TTFullScreenVideoAd" to listOf("showFullScreenVideoAd"),
            "com.bytedance.sdk.openadsdk.TTInterstitialAd" to listOf("showInterstitialAd"),
            "com.bytedance.sdk.openadsdk.TTNativeExpressAd" to listOf("render", "showInteractionExpressAd"),
            // Mintegral
            "com.mbridge.msdk.interstitialvideo.out.InterstitialVideoAdManager" to listOf("load", "show"),
            "com.mbridge.msdk.out.MBBannerView" to listOf("loadFromBid"),
            // InMobi
            "com.inmobi.ads.InMobiBanner" to listOf("load"),
            "com.inmobi.ads.InMobiInterstitial" to listOf("load", "show"),
            // Chartboost
            "com.chartboost.sdk.Chartboost" to listOf("cacheInterstitial", "showInterstitial", "cacheRewardedVideo", "showRewardedVideo"),
            // Fyber
            "com.fyber.inneractive.sdk.api.InneractiveAdSpot" to listOf("requestAd"),
            // HyprMX
            "com.hyprmx.android.sdk.HyprMX" to listOf("loadAd", "showAd"),
            // Liftoff SDK (standalone)
            "com.liftoff.publisher.LoHook" to listOf("loadAd"),
            "com.liftoff.publisher.Ad" to listOf("load", "show"),
            "com.liftoff.publisher.AdRequestManager" to listOf("requestAd", "requestAds"),
        )

        sdkHooks.forEach { (className, methods) ->
            val clazz = runCatching { Class.forName(className, false, lpparam.classLoader) }.getOrNull() ?: return@forEach

            methods.forEach { method ->
                runCatching {
                    XposedBridge.hookAllMethods(clazz, method, object : XC_MethodHook() {
                        override fun beforeHookedMethod(param: MethodHookParam) {
                            param.result = null
                            XposedBridge.log("FA.HybridAdHook blocked SDK ${className}#${method} in ${lpparam.packageName}")
                        }
                    })
                }
            }
        }

        // Hide ad view instances even when SDK serves from cache / local fallback.
        val adViewClasses = listOf(
            "com.google.android.gms.ads.AdView",
            "com.google.android.gms.ads.BaseAdView",
            "com.google.android.gms.ads.nativead.NativeAdView",
            "com.facebook.ads.AdView",
            "com.applovin.mediation.ads.MaxAdView",
            "com.mbridge.msdk.out.MBBannerView",
            "com.unity3d.services.banners.BannerView",
            "com.ironsource.mediationsdk.BannerLayout",
        )
        adViewClasses.forEach { className ->
            val clazz = runCatching { Class.forName(className, false, lpparam.classLoader) }.getOrNull() ?: return@forEach
            runCatching {
                XposedBridge.hookAllMethods(clazz, "onAttachedToWindow", object : XC_MethodHook() {
                    override fun beforeHookedMethod(param: MethodHookParam) {
                        suppressAdViewInstance(param.thisObject, lpparam.packageName, "$className#onAttachedToWindow")
                    }
                })
            }
            listOf("setAdListener", "loadAd", "render", "show").forEach { method ->
                runCatching {
                    XposedBridge.hookAllMethods(clazz, method, object : XC_MethodHook() {
                        override fun beforeHookedMethod(param: MethodHookParam) {
                            suppressAdViewInstance(param.thisObject, lpparam.packageName, "$className#$method")
                            param.result = null
                        }
                    })
                }
            }
        }

        runCatching {
            val vungleClazz = Class.forName("com.vungle.warren.Vungle", false, lpparam.classLoader)
            XposedBridge.hookAllMethods(vungleClazz, "canPlayAd", object : XC_MethodHook() {
                override fun beforeHookedMethod(param: MethodHookParam) {
                    param.result = false
                    XposedBridge.log("FA.HybridAdHook forced Vungle.canPlayAd=false in ${lpparam.packageName}")
                }
            })
        }
        runCatching {
            val vungleAdsClazz = Class.forName("com.vungle.ads.VungleAds", false, lpparam.classLoader)
            XposedBridge.hookAllMethods(vungleAdsClazz, "canPlayAd", object : XC_MethodHook() {
                override fun beforeHookedMethod(param: MethodHookParam) {
                    param.result = false
                    XposedBridge.log("FA.HybridAdHook forced VungleAds.canPlayAd=false in ${lpparam.packageName}")
                }
            })
        }
    }

    private fun suppressAdViewInstance(instance: Any?, pkg: String, source: String) {
        val view = instance as? android.view.View ?: return
        runCatching {
            view.visibility = android.view.View.GONE
            val params = view.layoutParams
            if (params != null) {
                params.width = 0
                params.height = 0
                view.layoutParams = params
            }
            (view.parent as? android.view.ViewGroup)?.removeView(view)
            view.alpha = 0f
            view.isClickable = false
            view.isEnabled = false
            XposedBridge.log("FA.HybridAdHook suppressed ad view from $source in $pkg class=${view.javaClass.name}")
        }
    }

    private fun hookAdActivityLifecycles(lpparam: XC_LoadPackage.LoadPackageParam) {
        val targetActivities = listOf(
            "com.applovin.adview.AppLovinFullscreenActivity",
            "com.applovin.adview.AppLovinInterstitialActivity",
            "com.bytedance.sdk.openadsdk.activity.TTFullScreenVideoActivity",
            "com.bytedance.sdk.openadsdk.activity.TTRewardVideoActivity",
            "com.bytedance.sdk.openadsdk.activity.TTInterstitialActivity",
            "com.bytedance.sdk.openadsdk.activity.TTFullScreenExpressVideoActivity",
            "com.bytedance.sdk.openadsdk.activity.TTRewardExpressVideoActivity",
            "com.vungle.warren.ui.VungleActivity",
            "com.vungle.ads.internal.ui.VungleActivity",
            "com.inmobi.ads.rendering.InMobiAdActivity",
            "com.facebook.ads.AudienceNetworkActivity",
            "com.chartboost.sdk.view.CBImpressionActivity",
            "com.mbridge.msdk.activity.MBCommonActivity",
            "com.mbridge.msdk.reward.player.MBRewardVideoActivity",
            "com.ironsource.sdk.controller.ControllerActivity",
            "com.ironsource.sdk.controller.InterstitialActivity",
            "com.ironsource.sdk.controller.OpenUrlActivity"
        )
        
        targetActivities.forEach { className ->
            val clazz = runCatching { Class.forName(className, false, lpparam.classLoader) }.getOrNull() ?: return@forEach
            
            runCatching {
                XposedBridge.hookAllMethods(clazz, "onCreate", object : XC_MethodHook() {
                    override fun afterHookedMethod(param: MethodHookParam) {
                        try {
                            val activity = param.thisObject as? android.app.Activity ?: return
                            activity.finish()
                            XposedBridge.log("FA.HybridAdHook killed Ad Activity $className in ${lpparam.packageName} (killed after onCreate)")
                        } catch (t: Throwable) {
                            XposedBridge.log("FA.HybridAdHook error killing ad activity $className: ${t.message}")
                        }
                    }
                })
            }
        }
    }

    /**
     * Package-specific kill switches for apps with unusually aggressive ad retry loops.
     *
     * Current target:
     * - com.worldance.drama
     *
     * This intentionally hooks deeper AppLovin/MAX internals than the generic layer above.
     * Tradeoff: it may disable some ad-driven reward flows, but it materially reduces repeated
     * background retries and the constant loader churn seen in logs.
     */
    private fun hookAggressivePackageMitigations(lpparam: XC_LoadPackage.LoadPackageParam) {
        if (lpparam.packageName != "com.worldance.drama" && lpparam.packageName != "com.freereels.app") return

        val deepHooks = listOf(
            // AppLovin / legacy adview paths
            "com.applovin.adview.AppLovinAdView" to listOf(
                "loadNextAd", "renderAd", "resume", "pause", "destroy",
            ),
            "com.applovin.impl.adview.AppLovinAdView" to listOf(
                "loadNextAd", "renderAd", "resume", "pause", "destroy",
            ),
            "com.applovin.impl.adview.AppLovinAdViewImpl" to listOf(
                "loadNextAd", "renderAd", "scheduleAdRefresh", "startAutoRefresh",
                "resume", "resumeAutoRefresh", "maybeScheduleRefresh", "destroy",
                "scheduleRefresh", "stopAutoRefresh", "onAdRefresh", "handleAdRefresh",
            ),
            // AppLovin SDK service / config fetch paths
            "com.applovin.impl.sdk.ad.AppLovinAdServiceImpl" to listOf(
                "loadNextAd", "loadNextAdForZoneId", "loadNextAdForZoneIds",
                "loadNextAdForAdToken", "maybeSubmitPersistentPostbacks",
                "enqueueAdLoad", "scheduleAdLoad", "retryLoad", "loadNextAdInternal",
            ),
            // AppLovin MAX mediation internals
            "com.applovin.impl.mediation.ads.MaxAdViewImpl" to listOf(
                "loadAd", "startAutoRefresh", "stopAutoRefresh", "scheduleAdRefresh",
                "resumeAutoRefresh", "maybeScheduleRefresh", "onAdRefresh", "destroy",
                "scheduleRefresh", "handleAdRefresh", "loadAdIfNeeded", "loadAdIfReady",
                "onAdLoadFailed", "retryLoad", "startRefreshTimer", "stopRefreshTimer",
            ),
            "com.applovin.impl.mediation.ads.MaxFullscreenAdImpl" to listOf(
                "loadAd", "showAd", "showAdIfReady",
                "loadAdIfReady", "scheduleLoad", "retryLoad", "onAdLoadFailed",
                "maybeScheduleAdLoad", "onAdHidden",
            ),
            // AppLovin scheduler / timer internals frequently responsible for endless retries
            "com.applovin.impl.sdk.utils.d" to listOf(
                "a", "b", "c", "run", "schedule",
            ),
            "com.applovin.impl.sdk.utils.p" to listOf(
                "a", "b", "run", "postDelayed",
            ),
            "com.applovin.impl.sdk.e.ab" to listOf(
                "run", "a", "b",
            ),
            "com.applovin.impl.sdk.e.z" to listOf(
                "run", "a", "b",
            ),
            // Google ads wrappers commonly used by aggressive reload loops
            "com.google.android.gms.ads.AdView" to listOf("loadAd", "pause", "resume", "destroy"),
            "com.google.android.gms.ads.BaseAdView" to listOf("loadAd", "pause", "resume", "destroy"),
            "com.google.android.gms.ads.AdLoader" to listOf("loadAd", "loadAds"),
        )

        deepHooks.forEach { (className, methods) ->
            val clazz = runCatching { Class.forName(className, false, lpparam.classLoader) }.getOrNull() ?: return@forEach
            methods.forEach { method ->
                runCatching {
                    XposedBridge.hookAllMethods(clazz, method, object : XC_MethodHook() {
                        override fun beforeHookedMethod(param: MethodHookParam) {
                            param.result = null
                            XposedBridge.log(
                                "FA.HybridAdHook aggressive blocked $className#$method in ${lpparam.packageName}",
                            )
                        }
                    })
                }
            }
        }

        hookAggressivePangleViewInjection(lpparam)
    }

    private fun hookAggressivePangleViewInjection(lpparam: XC_LoadPackage.LoadPackageParam) {
        if (lpparam.packageName != "com.worldance.drama" && lpparam.packageName != "com.freereels.app") return

        runCatching {
            val viewGroupClazz = Class.forName("android.view.ViewGroup", false, lpparam.classLoader)
            XposedBridge.hookAllMethods(viewGroupClazz, "addView", object : XC_MethodHook() {
                override fun beforeHookedMethod(param: MethodHookParam) {
                    val child = param.args.firstOrNull() ?: return
                    val childClass = child.javaClass.name
                    val parentClass = param.thisObject?.javaClass?.name.orEmpty()
                    if (!looksLikeAggressivePangleView(childClass, parentClass)) return
                    param.result = null
                    XposedBridge.log(
                        "FA.HybridAdHook blocked ViewGroup.addView child=$childClass parent=$parentClass in ${lpparam.packageName}",
                    )
                }
            })
        }
    }

    private fun looksLikeAggressivePangleView(childClass: String, parentClass: String): Boolean {
        val child = childClass.lowercase(Locale.US)
        val parent = parentClass.lowercase(Locale.US)
        val childLooksLikeAd = child.contains("pangle") ||
            child.contains("bytedance") ||
            child.contains("openadsdk") ||
            child.contains("ttad") ||
            child.contains("endcard") ||
            child.contains("expressad")
        if (childLooksLikeAd) return true

        val parentLooksLikeAd = parent.contains("pangle") ||
            parent.contains("bytedance") ||
            parent.contains("openadsdk") ||
            parent.contains("ttad")
        val childLooksLikeContainer = child.contains("webview") ||
            child.contains("imageview") ||
            child.contains("textureview") ||
            child.contains("surfaceview") ||
            child.contains("framelayout") ||
            child.contains("linearlayout") ||
            child.contains("relativelayout")
        return parentLooksLikeAd && childLooksLikeContainer
    }

    /**
     * Network-layer probe for packages that still leak ads outside the usual WebView / SDK entry points.
     *
     * Scope is intentionally narrow:
     * - Only com.worldance.drama
     *
     * Goal:
     * - Surface the real hosts/URLs that are still being requested
     * - Block them early if they clearly match known ad/tracker domains
     */
    private fun hookAggressivePackageNetworkLayer(lpparam: XC_LoadPackage.LoadPackageParam) {
        if (!shouldBlockIntentForThisPackage(lpparam.packageName) && lpparam.packageName != "com.happymod.apk") return

        hookOkHttpNetwork(lpparam)
        hookJavaUrlNetwork(lpparam)
        hookCronetNetwork(lpparam)
    }

    private fun hookOkHttpNetwork(lpparam: XC_LoadPackage.LoadPackageParam) {
        val cl = lpparam.classLoader

        // okhttp3.OkHttpClient#newCall(Request)
        runCatching {
            val okHttpClient = Class.forName("okhttp3.OkHttpClient", false, cl)
            XposedBridge.hookAllMethods(okHttpClient, "newCall", object : XC_MethodHook() {
                override fun beforeHookedMethod(param: MethodHookParam) {
                    val request = param.args.firstOrNull() ?: return
                    val urlString = runCatching {
                        val urlObj = request.javaClass.getMethod("url").invoke(request)
                        urlObj?.toString().orEmpty()
                    }.getOrDefault("")
                    if (urlString.isBlank()) return
                    val method = runCatching {
                        request.javaClass.getMethod("method").invoke(request)?.toString().orEmpty()
                    }.getOrDefault("")
                    val bodySize = runCatching {
                        val body = request.javaClass.getMethod("body").invoke(request) ?: return@runCatching -1L
                        body.javaClass.getMethod("contentLength").invoke(body) as? Long ?: -1L
                    }.getOrDefault(-1L)
                    handleObservedNetworkUrl(
                        lpparam = lpparam,
                        source = "okhttp.newCall",
                        urlString = urlString,
                        param = param,
                        method = method.ifBlank { "UNKNOWN" },
                        bodyOrFileBytes = bodySize,
                    )
                }
            })
        }

        // okhttp3.RealCall / okhttp3.internal.connection.RealCall execute/enqueue
        val realCallCandidates = listOf(
            "okhttp3.RealCall",
            "okhttp3.internal.connection.RealCall",
        )
        realCallCandidates.forEach { className ->
            val clazz = runCatching { Class.forName(className, false, cl) }.getOrNull() ?: return@forEach
            listOf("execute", "enqueue").forEach { method ->
                runCatching {
                    XposedBridge.hookAllMethods(clazz, method, object : XC_MethodHook() {
                        override fun beforeHookedMethod(param: MethodHookParam) {
                            val urlString = runCatching {
                                val req = param.thisObject.javaClass.getMethod("request").invoke(param.thisObject)
                                val urlObj = req?.javaClass?.getMethod("url")?.invoke(req)
                                urlObj?.toString().orEmpty()
                            }.getOrDefault("")
                            if (urlString.isBlank()) return
                            val req = runCatching {
                                param.thisObject.javaClass.getMethod("request").invoke(param.thisObject)
                            }.getOrNull()
                            val reqMethod = runCatching {
                                req?.javaClass?.getMethod("method")?.invoke(req)?.toString().orEmpty()
                            }.getOrDefault("")
                            handleObservedNetworkUrl(
                                lpparam = lpparam,
                                source = "$className#$method",
                                urlString = urlString,
                                param = param,
                                method = reqMethod.ifBlank { "UNKNOWN" },
                            )
                        }
                    })
                }
            }
        }

        // okhttp3 internal interceptor chain catches final requests after redirects / interceptors.
        val interceptorChainCandidates = listOf(
            "okhttp3.internal.http.RealInterceptorChain",
            "okhttp3.internal.http2.Http2ExchangeCodec",
        )
        interceptorChainCandidates.forEach { className ->
            val clazz = runCatching { Class.forName(className, false, cl) }.getOrNull() ?: return@forEach
            listOf("proceed").forEach { method ->
                runCatching {
                    XposedBridge.hookAllMethods(clazz, method, object : XC_MethodHook() {
                        override fun beforeHookedMethod(param: MethodHookParam) {
                            val request = param.args.firstOrNull() ?: return
                            val urlString = runCatching {
                                val urlObj = request.javaClass.getMethod("url").invoke(request)
                                urlObj?.toString().orEmpty()
                            }.getOrDefault("")
                            if (urlString.isBlank()) return
                            val reqMethod = runCatching {
                                request.javaClass.getMethod("method").invoke(request)?.toString().orEmpty()
                            }.getOrDefault("")
                            handleObservedNetworkUrl(
                                lpparam = lpparam,
                                source = "$className#$method",
                                urlString = urlString,
                                param = param,
                                method = reqMethod.ifBlank { "UNKNOWN" },
                            )
                        }
                    })
                }
            }
        }
    }

    private fun hookJavaUrlNetwork(lpparam: XC_LoadPackage.LoadPackageParam) {
        val cl = lpparam.classLoader

        // java.net.URL#openConnection / openStream
        runCatching {
            val urlClazz = Class.forName("java.net.URL", false, cl)
            listOf("openConnection", "openStream").forEach { method ->
                XposedBridge.hookAllMethods(urlClazz, method, object : XC_MethodHook() {
                    override fun beforeHookedMethod(param: MethodHookParam) {
                        val urlString = param.thisObject?.toString().orEmpty()
                        if (urlString.isBlank()) return
                        handleObservedNetworkUrl(lpparam, "java.net.URL#$method", urlString, param)
                    }
                })
            }
        }

        // java.net.HttpURLConnection#connect
        runCatching {
            val connClazz = Class.forName("java.net.HttpURLConnection", false, cl)
            listOf("connect", "getInputStream", "getResponseCode").forEach { method ->
                XposedBridge.hookAllMethods(connClazz, method, object : XC_MethodHook() {
                    override fun beforeHookedMethod(param: MethodHookParam) {
                        val urlString = runCatching {
                            val urlObj = param.thisObject?.javaClass?.getMethod("getURL")?.invoke(param.thisObject)
                            urlObj?.toString().orEmpty()
                        }.getOrDefault("")
                        if (urlString.isBlank()) return
                        handleObservedNetworkUrl(lpparam, "HttpURLConnection#$method", urlString, param)
                    }
                })
            }
        }

        // Generic URLConnection variants on some Android builds use implementation classes
        // that bypass the base HttpURLConnection hook above.
        val urlConnectionCandidates = listOf(
            "java.net.URLConnection",
            "com.android.okhttp.internal.huc.HttpURLConnectionImpl",
            "com.android.okhttp.internal.huc.HttpsURLConnectionImpl",
        )
        urlConnectionCandidates.forEach { className ->
            val clazz = runCatching { Class.forName(className, false, cl) }.getOrNull() ?: return@forEach
            listOf("getInputStream", "getContent").forEach { method ->
                runCatching {
                    XposedBridge.hookAllMethods(clazz, method, object : XC_MethodHook() {
                        override fun beforeHookedMethod(param: MethodHookParam) {
                            val urlString = runCatching {
                                val urlObj = param.thisObject?.javaClass?.getMethod("getURL")?.invoke(param.thisObject)
                                urlObj?.toString().orEmpty()
                            }.getOrDefault("")
                            if (urlString.isBlank()) return
                            handleObservedNetworkUrl(lpparam, "$className#$method", urlString, param)
                        }
                    })
                }
            }
        }
    }

    private fun hookCronetNetwork(lpparam: XC_LoadPackage.LoadPackageParam) {
        val cl = lpparam.classLoader

        val cronetBuilderCandidates = listOf(
            "org.chromium.net.UrlRequest\$Builder",
        )
        cronetBuilderCandidates.forEach { className ->
            val clazz = runCatching { Class.forName(className, false, cl) }.getOrNull() ?: return@forEach
            runCatching {
                XposedBridge.hookAllMethods(clazz, "build", object : XC_MethodHook() {
                    override fun beforeHookedMethod(param: MethodHookParam) {
                        val urlString = runCatching {
                            param.thisObject.toString()
                        }.getOrDefault("")
                        if (urlString.contains("http://", true) || urlString.contains("https://", true)) {
                            handleObservedNetworkUrl(lpparam, "$className#build", urlString, param)
                        }
                    }
                })
            }
        }

        runCatching {
            val requestClazz = Class.forName("org.chromium.net.impl.CronetUrlRequest", false, cl)
            XposedBridge.hookAllMethods(requestClazz, "start", object : XC_MethodHook() {
                override fun beforeHookedMethod(param: MethodHookParam) {
                    val urlString = runCatching {
                        val field = param.thisObject.javaClass.getDeclaredField("mInitialUrl")
                        field.isAccessible = true
                        field.get(param.thisObject)?.toString().orEmpty()
                    }.getOrDefault("")
                    if (urlString.isBlank()) return
                    handleObservedNetworkUrl(lpparam, "org.chromium.net.impl.CronetUrlRequest#start", urlString, param)
                }
            })
        }
    }

    private fun handleObservedNetworkUrl(
        lpparam: XC_LoadPackage.LoadPackageParam,
        source: String,
        urlString: String,
        param: XC_MethodHook.MethodHookParam,
        method: String = "UNKNOWN",
        bodyOrFileBytes: Long = -1L,
    ) {
        val policyPkg = resolvePolicyPackage(lpparam.packageName)
        val rewrittenUrl = maybeRewriteUrlBeforeWebViewNetwork(
            runtimePkg = lpparam.packageName,
            policyPkg = policyPkg,
            originalUrl = urlString,
        )
        val effectiveUrl = rewrittenUrl ?: urlString
        if (rewrittenUrl != null) {
            logNetworkEventOnce(
                dedupKey = "wv-rewrite|${lpparam.packageName}|$urlString",
                message = "FA.HybridAdHook webview pre-rewrite in ${lpparam.packageName}: $urlString => $rewrittenUrl",
            )
        }

        val lower = effectiveUrl.lowercase(Locale.US)
        val host = runCatching { java.net.URI(effectiveUrl).host.orEmpty() }.getOrDefault("")
        val hostLower = host.lowercase(Locale.US)
        val cleanMethod = method.ifBlank { "UNKNOWN" }
        val requestKind = inferRequestKind(cleanMethod, lower, bodyOrFileBytes)
        val hostType = classifyHostType(hostLower, lower)

        val hardBlockReason = hardBlockScopedMetaAdEndpoint(policyPkg, hostLower, lower)
        val decision = if (hardBlockReason != null) {
            DecisionResult(DecisionAction.BLOCK, hardBlockReason)
        } else {
            requestDecisionEngine.evaluateNetwork(
                pkg = policyPkg,
                urlString = effectiveUrl,
                method = cleanMethod,
                isDownload = requestKind == "download",
            )
        }
        if (decision.action != DecisionAction.BLOCK) {
            logNetworkEventOnce(
                dedupKey = "acc|${lpparam.packageName}|$policyPkg|$source|$cleanMethod|$urlString",
                message = "FA.HybridAdHook net event pkg=${lpparam.packageName} policy_pkg=$policyPkg source=$source " +
                    "url=$effectiveUrl host=$host type=$hostType request=$requestKind method=$cleanMethod " +
                    "size=${bodyOrFileBytes.coerceAtLeast(-1L)} status=acc reason=${decision.reason}",
            )
            val isLeakCandidate = isHighRiskNavigationUrl(lower) || isLikelyRedirectHost(lower) || isLikelyTrackerUrl(lower)
            if (isLeakCandidate) {
                XposedBridge.log("FA.HybridAdHook net suspicious in ${lpparam.packageName}: $effectiveUrl")
            }
            return
        }

        // Block obvious ad/tracker hosts at the network call boundary too.
        when (source) {
            "java.net.URL#openStream" -> {
                param.throwable = java.io.IOException("blocked_by_firewall_agent")
            }
            "HttpURLConnection#connect",
            "HttpURLConnection#getInputStream",
            "HttpURLConnection#getResponseCode" -> {
                param.throwable = java.io.IOException("blocked_by_firewall_agent")
            }
            "java.net.URLConnection#getInputStream",
            "java.net.URLConnection#getContent",
            "com.android.okhttp.internal.huc.HttpURLConnectionImpl#getInputStream",
            "com.android.okhttp.internal.huc.HttpURLConnectionImpl#getContent",
            "com.android.okhttp.internal.huc.HttpsURLConnectionImpl#getInputStream",
            "com.android.okhttp.internal.huc.HttpsURLConnectionImpl#getContent",
            "okhttp3.internal.http.RealInterceptorChain#proceed",
            "okhttp3.internal.http2.Http2ExchangeCodec#proceed",
            "org.chromium.net.impl.CronetUrlRequest#start" -> {
                param.throwable = java.io.IOException("blocked_by_firewall_agent")
            }
            else -> {
                // For methods that return an object, null short-circuits a number of call paths.
                param.result = null
            }
        }
        logNetworkEventOnce(
            dedupKey = "blocked-line|${lpparam.packageName}|$source|$urlString|${decision.reason}",
            message = "FA.HybridAdHook net blocked $source url=$effectiveUrl " +
                "reason=${decision.reason} in ${lpparam.packageName} policy_pkg=$policyPkg",
            ttlMs = 1500L,
        )
        logNetworkEventOnce(
            dedupKey = "blocked|${lpparam.packageName}|$policyPkg|$source|$cleanMethod|$urlString",
            message = "FA.HybridAdHook net event pkg=${lpparam.packageName} policy_pkg=$policyPkg source=$source " +
                "url=$effectiveUrl host=$host type=$hostType request=$requestKind method=$cleanMethod " +
                "size=${bodyOrFileBytes.coerceAtLeast(-1L)} status=blocked reason=${decision.reason}",
        )
    }

    private fun maybeRewriteUrlBeforeWebViewNetwork(
        runtimePkg: String,
        policyPkg: String,
        originalUrl: String,
    ): String? {
        if (runtimePkg != "com.google.android.webview" && runtimePkg != "com.android.webview") return null
        if (!isStrictAdPackage(policyPkg)) return null
        val lower = originalUrl.lowercase(Locale.US)
        val hostLower = runCatching { java.net.URI(originalUrl).host.orEmpty().lowercase(Locale.US) }.getOrDefault("")
        val shouldRewrite = isTrustedEndpointForEarlyWebViewRewrite(lower, hostLower) ||
            looksLikeAdNetworkUrl(lower, hostLower) ||
            hasAdUrlMarkers(lower)
        if (!shouldRewrite) return null
        val scheme = runCatching { java.net.URI(originalUrl).scheme.orEmpty() }.getOrDefault("https")
        val safeScheme = if (scheme.equals("http", true)) "http" else "https"
        return "$safeScheme://127.0.0.1/fa_blocked_webview"
    }

    private fun isTrustedEndpointForEarlyWebViewRewrite(urlLower: String, hostLower: String): Boolean {
        if (hostLower.contains("googleads.g.doubleclick.net")) return true
        if (hostLower.contains("doubleclick.net")) return true
        if (hostLower.contains("googleadservices.com")) return true
        if ((hostLower == "web.facebook.com" || hostLower.endsWith(".web.facebook.com")) &&
            (urlLower.contains("/adnw_sync2") || urlLower.contains("/adnw_logging") || urlLower.contains("/adnw"))
        ) return true
        return false
    }

    private fun hardBlockScopedMetaAdEndpoint(pkg: String, hostLower: String, urlLower: String): String? {
        if (pkg != "com.freereels.app" && pkg != "com.worldance.drama") return null
        if (hostLower.isBlank() || urlLower.isBlank()) return null
        if (hostLower == "web.facebook.com" || hostLower.endsWith(".web.facebook.com")) {
            if (urlLower.contains("/adnw_sync2") || urlLower.contains("/adnw")) {
                return "strict-meta-ad-endpoint"
            }
        }
        if (hostLower == "graph.facebook.com" || hostLower.endsWith(".graph.facebook.com")) {
            if (urlLower.contains("/app/mobile_sdk_gk") ||
                urlLower.contains("/app/model_asset") ||
                urlLower.contains("/activities")
            ) {
                return "strict-meta-ad-endpoint"
            }
        }
        return null
    }

    private fun shouldBlockNetworkRequest(urlLower: String, hostLower: String): String? {
        return shouldBlockNetworkRequest("", urlLower, hostLower)
    }

    private fun shouldBlockNetworkRequest(
        pkg: String,
        urlLower: String,
        hostLower: String,
    ): String? {
        if (urlLower.isBlank()) return null
        val decision = requestDecisionEngine.evaluateNetwork(pkg = resolvePolicyPackage(pkg), urlString = urlLower, method = "UNKNOWN")
        return if (decision.action == DecisionAction.BLOCK) decision.reason else null
    }

    private fun isLikelyAdOrAdultNavigation(urlLower: String, hostLower: String): Boolean {
        return isMalwareDownloadUrl(urlLower, hostLower) ||
            containsAdultOrGamblingKeyword(urlLower, hostLower) ||
            hostLower.contains("liftoff") ||
            hostLower.contains("mintegral") ||
            hasAdUrlMarkers(urlLower) ||
            isHighRiskNavigationUrl(urlLower) ||
            isLikelyRedirectHost(urlLower) ||
            isLikelyTrackerUrl(urlLower)
    }

    private fun inferRequestKind(method: String, urlLower: String, bodyOrFileBytes: Long): String {
        val m = method.uppercase(Locale.US)
        if (m == "POST" || m == "PUT" || m == "PATCH" || m == "DELETE") return "upload"
        if (bodyOrFileBytes > 0L && m != "GET") return "upload"
        if (urlLower.contains(".apk") || urlLower.contains("download") || urlLower.contains("file")) return "download"
        return "download"
    }

    private fun classifyHostType(hostLower: String, urlLower: String): String {
        if (hostLower.isBlank()) return "unknown"
        if (isOfficialTrustedHost(hostLower)) return "official-social"
        if (looksLikeAdNetworkUrl(urlLower, hostLower)) return "ads"
        if (isMalwareDownloadUrl(urlLower, hostLower) || containsAdultOrGamblingKeyword(urlLower, hostLower)) return "malware-risk"
        if (isLikelyTrackerUrl(urlLower)) return "tracker"
        return "other"
    }

    private fun isOfficialTrustedHost(hostLower: String): Boolean {
        if (hostLower.isBlank()) return false
        return officialTrustedHosts.any { hostLower == it || hostLower.endsWith(".$it") }
    }

    private fun isSuspiciousNonOfficialHost(hostLower: String, urlLower: String): Boolean {
        if (hostLower.isBlank()) return false
        if (isOfficialTrustedHost(hostLower)) return false
        if (isLikelyTrackerUrl(urlLower) || isLikelyRedirectHost(urlLower)) return true
        if (looksLikeAdNetworkUrl(urlLower, hostLower)) return true
        if (isMalwareDownloadUrl(urlLower, hostLower)) return true
        if (containsAdultOrGamblingKeyword(urlLower, hostLower)) return true
        return urlLower.contains(".apk") || urlLower.contains("download") || urlLower.contains("install")
    }

    private fun isMalwareDownloadUrl(urlLower: String, hostLower: String): Boolean {
        if (urlLower.isBlank()) return false
        val knownHost = knownMalwareHosts.any { hostLower == it || hostLower.endsWith(".$it") || hostLower.contains(it) } || isHostBlockedByExternalFeed(hostLower)
        val rpHostPattern = Regex("""(^|\.)\d{2,4}rp[\w-]*\.""").containsMatchIn(hostLower)
        val looksLikeApkDownload = urlLower.contains(".apk") ||
            urlLower.contains("application/vnd.android.package-archive") ||
            urlLower.contains("download") ||
            urlLower.contains("install")
        return knownHost || rpHostPattern || (looksLikeApkDownload && containsAdultOrGamblingKeyword(urlLower, hostLower))
    }

    private fun containsAdultOrGamblingKeyword(urlLower: String, hostLower: String = ""): Boolean {
        if (urlLower.isBlank()) return false
        val lowerHost = hostLower.lowercase(Locale.US)
        val combined = "$urlLower $lowerHost"
        return highRiskKeywordSet.any { keyword ->
            combined.contains(keyword, true)
        }
    }

    private fun looksLikeAdNetworkUrl(urlLower: String, hostLower: String): Boolean {
        if (isHighConfidenceAdSignal(urlLower)) return true
        if (hostLower.isBlank()) return false
        if (activeAdPatterns().any { hostLower == it || hostLower.contains(it) }) return true

        val extraAggressiveHosts = listOf(
            "applovin.com",
            "applvn.com",
            "facebook.com",
            "fbcdn.net",
            "doubleclick.net",
            "googlesyndication.com",
            "googleadservices.com",
            "adservice.google.",
            "pangle.io",
            "pangolin-sdk-toutiao.com",
            "byteoversea.com",
            "snssdk.com",
            "sgsnssdk.com",
            "zijieapi.com",
            "bytedance.com",
            "toutiao.com",
            "adx.opera.com",
            "op-mobile.opera.com",
            "shopee",
            "tokopedia",
            "lazada",
            "bukalapak",
        )
        return extraAggressiveHosts.any { hostLower == it || hostLower.endsWith(".$it") || hostLower.contains(it) }
    }

    private fun isHighConfidenceAdSignal(urlLower: String): Boolean {
        if (urlLower.isBlank()) return false
        return urlLower.contains("/beacon") ||
            urlLower.contains("liftoff") ||
            urlLower.contains("mintegral") ||
            urlLower.contains("impression-asia") ||
            urlLower.contains("ad_group_id=") ||
            urlLower.contains("creative_id=") ||
            urlLower.contains("auction_id=") ||
            urlLower.contains("origin=haggler")
    }

    /**
     * Chrome-specific guard: 9-layer defence against malware URL navigation and APK downloads.
     *
     * Layer 1: Activity.onCreate       — wipe malware intent before Chrome loads it
     * Layer 2: Activity.onNewIntent    — Chrome already running (MOST COMMON BYPASS PATH)
     * Layer 3: Activity.onStart        — belt-and-suspenders for forks that re-read intent in onStart
     * Layer 4: ContextWrapper.startActivity — block further navigation Chrome initiates
     * Layer 5: DownloadManager.enqueue — block APK/malware downloads via Android DL manager
     * Layer 6: java.net.URL (Chrome)   — block malware host HTTP connections at socket level
     * Layer 7: OkHttp (Chrome)         — block malware host OkHttp calls
     * Layer 8: Chromium download APIs  — reflective block of Chromium Java download bridge classes
     * Layer 9: WebView.loadUrl         — last-resort for internal WebView navigation
     */
    private fun hookChromeExternalNavigation(lpparam: XC_LoadPackage.LoadPackageParam) {
        if (!isBrowserGuardPackage(lpparam.packageName)) return
        val pkg = lpparam.packageName
        val cl = lpparam.classLoader

        // ─── Layer 1: Activity.onCreate ───────────────────────────────────────────────
        // Chrome opened fresh by a malware intent — sanitize URL and close activity immediately.
        // IMPORTANT: We do NOT skip onCreate (param.result = null) because that leaves the
        // Activity in a zombie lifecycle state which causes system instability (notifications, etc).
        // Instead we let onCreate run normally with a blank intent, then finish() in afterHookedMethod.
        runCatching {
            val activityClass = Class.forName("android.app.Activity", false, cl)
            XposedBridge.hookAllMethods(activityClass, "onCreate", object : XC_MethodHook() {
                override fun beforeHookedMethod(param: MethodHookParam) {
                    val activity = param.thisObject ?: return
                    val intent = runCatching {
                        activity.javaClass.getMethod("getIntent").invoke(activity) as? Intent
                    }.getOrNull() ?: return
                    val dataString = intent.dataString.orEmpty()
                    if (!isMalwareOrGamblingIntent(dataString, "")) return
                    // Store original malicious URL for afterHookedMethod
                    BlockedUrlMap.put(param, dataString)
                    // Sanitize intent so Chrome does not navigate to malware URL
                    runCatching {
                        val newIntent = Intent(intent)
                        newIntent.data = null
                        newIntent.removeExtra("url")
                        newIntent.removeExtra("com.android.browser.application_id")
                        activity.javaClass.getMethod("setIntent", Intent::class.java).invoke(activity, newIntent)
                    }
                    // Do NOT set param.result = null — let onCreate run normally to avoid lifecycle issues
                    XposedBridge.log("FA.HybridAdHook chrome-guard [L1-onCreate] sanitised in $pkg: data=$dataString")
                }
                override fun afterHookedMethod(param: MethodHookParam) {
                    val blockedUrl = BlockedUrlMap.remove(param) ?: return
                    val activity = param.thisObject ?: return
                    // Close Chrome since it was opened purely for this malware URL
                    runCatching {
                        activity.javaClass.getMethod("finish").invoke(activity)
                        XposedBridge.log("FA.HybridAdHook chrome-guard [L1-onCreate] finished Chrome in $pkg: data=$blockedUrl")
                    }
                }
            })
        }

        // ─── Layer 2: Activity.onNewIntent (MOST IMPORTANT — Chrome usually already running) ──
        // When Chrome is in background, Android brings it to front BEFORE calling onNewIntent.
        // We sanitize the intent (don't skip method — that causes lifecycle instability) and then
        // call finish() if Chrome was opened purely for this malware URL.
        runCatching {
            val activityClass = Class.forName("android.app.Activity", false, cl)
            XposedBridge.hookAllMethods(activityClass, "onNewIntent", object : XC_MethodHook() {
                override fun beforeHookedMethod(param: MethodHookParam) {
                    val intent = param.args.firstOrNull() as? Intent ?: return
                    val dataString = intent.dataString.orEmpty()
                    if (!isMalwareOrGamblingIntent(dataString, "")) return
                    // Store original URL for afterHookedMethod
                    BlockedUrlMap.put(param, dataString)
                    // Sanitize intent data — do NOT skip the method to avoid lifecycle issues
                    intent.data = null
                    intent.removeExtra("url")
                    intent.removeExtra("com.android.browser.application_id")
                    XposedBridge.log("FA.HybridAdHook chrome-guard [L2-onNewIntent] sanitised in $pkg: data=$dataString")
                }
                override fun afterHookedMethod(param: MethodHookParam) {
                    val blockedUrl = BlockedUrlMap.remove(param) ?: return
                    val activity = param.thisObject ?: return
                    // Only close Chrome if it was opened purely for this malware URL (isTaskRoot = true)
                    // to avoid closing Chrome when the user already had legitimate tabs open.
                    runCatching {
                        val isTaskRoot = activity.javaClass.getMethod("isTaskRoot").invoke(activity) as? Boolean ?: false
                        if (isTaskRoot) {
                            activity.javaClass.getMethod("finish").invoke(activity)
                            XposedBridge.log("FA.HybridAdHook chrome-guard [L2-onNewIntent] closed Chrome (isTaskRoot) in $pkg: data=$blockedUrl")
                        } else {
                            XposedBridge.log("FA.HybridAdHook chrome-guard [L2-onNewIntent] kept open (has tabs) in $pkg: data=$blockedUrl")
                        }
                    }
                }
            })
        }

        // Layer 3 (onStart) removed — too broad, causes system notification instability
        // onCreate + onNewIntent + finish() cover the same cases without side effects.

        // ─── Layer 4: ContextWrapper.startActivity ────────────────────────────────────
        runCatching {
            val ctxClass = Class.forName("android.content.ContextWrapper", false, cl)
            listOf("startActivity", "startActivities").forEach { method ->
                XposedBridge.hookAllMethods(ctxClass, method, object : XC_MethodHook() {
                    override fun beforeHookedMethod(param: MethodHookParam) {
                        val intent = extractIntentFromHookParams(param.args) ?: return
                        val dataString = intent.dataString.orEmpty()
                        val targetPkg = intent.component?.packageName ?: intent.`package` ?: ""
                        if (!isMalwareOrGamblingIntent(dataString, targetPkg)) return
                        setBlockedMethodResult(param)
                        XposedBridge.log("FA.HybridAdHook chrome-guard [L4-ctxStart] blocked $method in $pkg: data=$dataString")
                    }
                })
            }
        }

        // ─── Layer 5: DownloadManager.enqueue in Chrome's process ─────────────────────
        runCatching {
            val dmClass = Class.forName("android.app.DownloadManager", false, cl)
            XposedBridge.hookAllMethods(dmClass, "enqueue", object : XC_MethodHook() {
                override fun beforeHookedMethod(param: MethodHookParam) {
                    val request = param.args.firstOrNull() ?: return
                    val uriString = runCatching {
                        val m = request.javaClass.getMethod("getUri")
                        (m.invoke(request) as? Uri)?.toString().orEmpty()
                    }.recoverCatching {
                        val f = request.javaClass.getDeclaredField("mUri"); f.isAccessible = true
                        (f.get(request) as? Uri)?.toString().orEmpty()
                    }.getOrDefault("")
                    if (uriString.isBlank()) return
                    val uriLower = uriString.lowercase(Locale.US)
                    val host = runCatching { android.net.Uri.parse(uriString).host.orEmpty().lowercase(Locale.US) }.getOrDefault("")
                    val isMalware = knownMalwareHosts.any { host == it || host.endsWith(".$it") || host.contains(it) }
                    val isApk = uriLower.contains(".apk") || uriLower.contains("application/vnd.android.package-archive")
                    val isGambling = containsAdultOrGamblingKeyword(uriLower, host)
                    val isFeedBlocked = isHostBlockedByExternalFeed(host)
                    if (!isMalware && !isApk && !isGambling && !isFeedBlocked) return
                    param.result = -1L
                    XposedBridge.log("FA.HybridAdHook chrome-guard [L5-DlManager] blocked enqueue in $pkg: $uriString malware=$isMalware apk=$isApk")
                }
            })
        }

        // ─── Layer 6: java.net.URL (socket-level) ─────────────────────────────────────
        runCatching {
            val urlClazz = Class.forName("java.net.URL", false, cl)
            listOf("openConnection", "openStream").forEach { method ->
                XposedBridge.hookAllMethods(urlClazz, method, object : XC_MethodHook() {
                    override fun beforeHookedMethod(param: MethodHookParam) {
                        val urlStr = param.thisObject?.toString().orEmpty()
                        if (urlStr.isBlank()) return
                        val host = runCatching { java.net.URI(urlStr).host.orEmpty().lowercase(Locale.US) }.getOrDefault("")
                        val isApk = urlStr.lowercase(Locale.US).contains(".apk")
                        val isMalware = knownMalwareHosts.any { host == it || host.endsWith(".$it") || host.contains(it) }
                        if (!isMalware && !isApk) return
                        param.throwable = java.io.IOException("blocked_by_firewall_agent: chrome-L6 host=$host apk=$isApk")
                        XposedBridge.log("FA.HybridAdHook chrome-guard [L6-javaURL] blocked $method in $pkg: $urlStr")
                    }
                })
            }
        }

        // ─── Layer 7: OkHttp ──────────────────────────────────────────────────────────
        runCatching {
            val okhttpClient = Class.forName("okhttp3.OkHttpClient", false, cl)
            XposedBridge.hookAllMethods(okhttpClient, "newCall", object : XC_MethodHook() {
                override fun beforeHookedMethod(param: MethodHookParam) {
                    val req = param.args.firstOrNull() ?: return
                    val urlStr = runCatching {
                        req.javaClass.getMethod("url").invoke(req)?.toString().orEmpty()
                    }.getOrDefault("")
                    if (urlStr.isBlank()) return
                    val host = runCatching { java.net.URI(urlStr).host.orEmpty().lowercase(Locale.US) }.getOrDefault("")
                    val isApk = urlStr.lowercase(Locale.US).contains(".apk")
                    val isMalware = knownMalwareHosts.any { host == it || host.endsWith(".$it") || host.contains(it) }
                    if (!isMalware && !isApk) return
                    param.result = null
                    XposedBridge.log("FA.HybridAdHook chrome-guard [L7-OkHttp] blocked newCall in $pkg: $urlStr")
                }
            })
        }

        // ─── Layer 8: Chromium Java download bridge classes (reflective) ──────────────
        val chromiumDlClasses = listOf(
            "org.chromium.chrome.browser.download.DownloadUtils",
            "org.chromium.chrome.browser.download.ChromeDownloadDelegate",
            "org.chromium.chrome.browser.download.DownloadController",
            "org.chromium.components.browser_ui.util.DownloadUtils",
            "org.chromium.chrome.browser.download.DownloadManagerBridge",
        )
        val chromiumDlMethods = listOf(
            "requestStartDownload", "enqueueDownloadManagerRequest",
            "downloadUrl", "downloadFile", "addCompletedDownload",
            "requestStartNativeDownload", "requestDownload",
        )
        chromiumDlClasses.forEach { className ->
            val clazz = runCatching { Class.forName(className, false, cl) }.getOrNull() ?: return@forEach
            chromiumDlMethods.forEach { method ->
                runCatching {
                    XposedBridge.hookAllMethods(clazz, method, object : XC_MethodHook() {
                        override fun beforeHookedMethod(param: MethodHookParam) {
                            val urlCandidate = param.args.filterIsInstance<String>().firstOrNull {
                                it.startsWith("http://", true) || it.startsWith("https://", true)
                            }.orEmpty()
                            if (urlCandidate.isBlank()) return
                            val host = runCatching { java.net.URI(urlCandidate).host.orEmpty().lowercase(Locale.US) }.getOrDefault("")
                            val isApk = urlCandidate.lowercase(Locale.US).contains(".apk")
                            val isMalware = knownMalwareHosts.any { host == it || host.endsWith(".$it") || host.contains(it) }
                            if (!isApk && !isMalware) return
                            param.result = null
                            XposedBridge.log("FA.HybridAdHook chrome-guard [L8-Chromium] blocked $className#$method in $pkg: $urlCandidate")
                        }
                    })
                }
            }
        }

        // ─── Layer 9: WebView.loadUrl (last resort) ───────────────────────────────────
        runCatching {
            val webViewClass = Class.forName("android.webkit.WebView", false, cl)
            XposedBridge.hookAllMethods(webViewClass, "loadUrl", object : XC_MethodHook() {
                override fun beforeHookedMethod(param: MethodHookParam) {
                    val url = param.args.firstOrNull() as? String ?: return
                    val urlLower = url.lowercase(Locale.US)
                    val host = runCatching { android.net.Uri.parse(url).host.orEmpty().lowercase(Locale.US) }.getOrDefault("")
                    if (!knownMalwareHosts.any { host == it || host.endsWith(".$it") || host.contains(it) } &&
                        !containsAdultOrGamblingKeyword(urlLower, host) &&
                        !isHostBlockedByExternalFeed(host)) return
                    param.result = null
                    XposedBridge.log("FA.HybridAdHook chrome-guard [L9-WVloadUrl] blocked in $pkg: $url")
                }
            })
        }
    }

    private fun hookWebViewLoads(lpparam: XC_LoadPackage.LoadPackageParam) {
        val webViewClass = Class.forName("android.webkit.WebView", false, lpparam.classLoader)

        XposedBridge.hookAllMethods(webViewClass, "loadUrl", object : XC_MethodHook() {
            override fun beforeHookedMethod(param: MethodHookParam) {
                val url = param.args.firstOrNull() as? String ?: return
                if (param.args.isEmpty()) return
                if (!isAdUrl(url)) return
                param.result = null
                XposedBridge.log("FA.HybridAdHook blocked loadUrl in ${lpparam.packageName}: $url")
            }
        })

        XposedBridge.hookAllMethods(webViewClass, "postUrl", object : XC_MethodHook() {
            override fun beforeHookedMethod(param: MethodHookParam) {
                val url = param.args.firstOrNull() as? String ?: return
                if (!isAdUrl(url)) return
                param.result = null
                XposedBridge.log("FA.HybridAdHook blocked postUrl in ${lpparam.packageName}: $url")
            }
        })

        XposedBridge.hookAllMethods(webViewClass, "loadDataWithBaseURL", object : XC_MethodHook() {
            override fun beforeHookedMethod(param: MethodHookParam) {
                val baseUrl = param.args.getOrNull(0) as? String
                val data = param.args.getOrNull(1) as? String
                if (!looksLikeAdHtmlPayload(baseUrl, data)) return
                param.result = null
                XposedBridge.log("FA.HybridAdHook blocked loadDataWithBaseURL in ${lpparam.packageName}")
            }
        })

        XposedBridge.hookAllMethods(webViewClass, "loadData", object : XC_MethodHook() {
            override fun beforeHookedMethod(param: MethodHookParam) {
                val data = param.args.getOrNull(0) as? String
                if (!looksLikeAdHtmlPayload(null, data)) return
                param.result = null
                XposedBridge.log("FA.HybridAdHook blocked loadData in ${lpparam.packageName}")
            }
        })
    }

    private fun hookWebViewClientIntercept(lpparam: XC_LoadPackage.LoadPackageParam) {
        val clazz = Class.forName("android.webkit.WebViewClient", false, lpparam.classLoader)
        val emptyResponse = emptyNoContentResponse()

        XposedBridge.hookAllMethods(clazz, "shouldInterceptRequest", object : XC_MethodHook() {
            override fun beforeHookedMethod(param: MethodHookParam) {
                try {
                    val url = extractUrl(param.args) ?: return
                    if (!shouldInterceptWebViewRequest(url, lpparam.packageName)) return
                    param.result = emptyResponse
                    logNetworkEventOnce(
                        dedupKey = "wv-intercept|${lpparam.packageName}|$url",
                        message = "FA.HybridAdHook intercepted request in ${lpparam.packageName}: $url",
                    )
                } catch (t: Throwable) {
                    XposedBridge.log("FA.HybridAdHook webview intercept error in ${lpparam.packageName}: ${t::class.java.name} ${t.message}")
                }
            }
        })
    }

    private fun hookWebViewShouldOverrideUrlLoading(lpparam: XC_LoadPackage.LoadPackageParam) {
        val clazz = Class.forName("android.webkit.WebViewClient", false, lpparam.classLoader)
        XposedBridge.hookAllMethods(clazz, "shouldOverrideUrlLoading", object : XC_MethodHook() {
            override fun beforeHookedMethod(param: MethodHookParam) {
                try {
                    val url = extractUrlFromAnyArgs(param.args) ?: return
                    if (!shouldBlockUrlFromNavigation(lpparam.packageName, url)) return
                    param.result = true
                    logNetworkEventOnce(
                        dedupKey = "wv-override|${lpparam.packageName}|$url",
                        message = "FA.HybridAdHook blocked shouldOverrideUrlLoading in ${lpparam.packageName}: $url",
                    )
                } catch (t: Throwable) {
                    XposedBridge.log("FA.HybridAdHook shouldOverrideUrlLoading error in ${lpparam.packageName}: ${t::class.java.name} ${t.message}")
                }
            }
        })
    }

    private fun extractUrl(args: Array<out Any?>): String? {
        return extractUrlFromAnyArgs(args) { arg: Any ->
            when (arg) {
                is String -> arg
                is WebResourceRequest -> arg.url?.toString()
                else -> null
            }
        }
    }

    private fun extractUrlFromAnyArgs(args: Array<out Any?>, mapper: ((Any) -> String?)? = null): String? {
        if (args.isEmpty()) return null
        val value = args.firstNotNullOfOrNull { arg ->
            if (arg == null) return@firstNotNullOfOrNull null
            mapper?.invoke(arg) ?: when (arg) {
                is String -> arg
                is WebResourceRequest -> arg.url?.toString()
                is Uri -> arg.toString()
                is Intent -> arg.data?.toString()
                is android.webkit.WebResourceResponse -> null
                is java.net.URL -> arg.toString()
                else -> null
            }
        } ?: return null
        return if (value.startsWith("http", true) || value.startsWith("intent://", true) || value.startsWith("market://", true) || value.startsWith("https://", true) || value.startsWith("file:", true)) {
            value
        } else {
            null
        }
    }

    private fun shouldInterceptWebViewRequest(url: String, packageName: String): Boolean {
        return isStrictAdPackage(packageName) && shouldBlockNetworkRequest(packageName, url.lowercase(Locale.US), runCatching { Uri.parse(url).host.orEmpty() }.getOrDefault("").lowercase(Locale.US)) != null ||
            isAdUrl(url)
    }

    private fun shouldBlockUrlFromNavigation(packageName: String, url: String): Boolean {
        val decision = requestDecisionEngine.evaluateNetwork(
            pkg = resolvePolicyPackage(packageName),
            urlString = url,
            method = "NAVIGATION",
            isDownload = url.lowercase(Locale.US).contains(".apk"),
        )
        return decision.action == DecisionAction.BLOCK
    }

    private fun resolvePolicyPackage(pkg: String): String {
        if (strictAdPackages.contains(pkg)) return pkg
        if (!isWebViewBridgePackages(pkg)) return pkg
        return resolveStrictPackageForCurrentUid() ?: pkg
    }

    private fun isWebViewBridgePackages(pkg: String): Boolean = webViewBridgePackages.contains(pkg)

    private fun resolveStrictPackageForCurrentUid(): String? {
        val app = runCatching {
            val activityThread = Class.forName("android.app.ActivityThread")
            val currentApplication = activityThread.getMethod("currentApplication").invoke(null)
            currentApplication as? Application
        }.getOrNull() ?: return null
        val packagesForUid = runCatching {
            app.packageManager.getPackagesForUid(Process.myUid())?.mapNotNull { it }?.toList().orEmpty()
        }.getOrDefault(emptyList())
        return packagesForUid.firstOrNull { strictAdPackages.contains(it) }
    }

    private fun extractCandidateUrlFromIntent(intent: Intent): String {
        val extras = intent.extras
        val keys = listOf("url", "u", "target_url", "targetUrl", "link", "deeplink", "deeplink_url", "redirect", "redirect_url", "browser_fallback_url")
        for (key in keys) {
            val value = runCatching { extras?.get(key)?.toString().orEmpty() }.getOrDefault("")
            if (value.startsWith("http://", true) || value.startsWith("https://", true) || value.startsWith("intent://", true) || value.startsWith("market://", true)) {
                return value
            }
        }
        val raw = runCatching { intent.toUri(0) }.getOrDefault("")
        Regex("""(https?://[^\s\"']+)""", RegexOption.IGNORE_CASE)
            .find(raw)
            ?.groupValues
            ?.getOrNull(1)
            ?.let { return it }
        Regex("""(intent://[^\s\"']+)""", RegexOption.IGNORE_CASE)
            .find(raw)
            ?.groupValues
            ?.getOrNull(1)
            ?.let { return it }
        return Regex("""(market://[^\s\"']+)""", RegexOption.IGNORE_CASE)
            .find(raw)
            ?.groupValues
            ?.getOrNull(1)
            .orEmpty()
    }

    private fun extractEmbeddedUrlCandidate(rawValue: String): String {
        if (rawValue.isBlank()) return ""
        val lower = rawValue.lowercase(Locale.US)
        val keys = listOf("redirect=", "url=", "target_url=", "targeturl=", "link=", "browser_fallback_url=", "af_dp=")
        for (key in keys) {
            val idx = lower.indexOf(key)
            if (idx < 0) continue
            val encoded = rawValue.substring(idx + key.length)
            val token = encoded.substringBefore('&').substringBefore('#')
            val decoded = runCatching { java.net.URLDecoder.decode(token, "UTF-8") }.getOrDefault(token)
            if (decoded.startsWith("http://", true) || decoded.startsWith("https://", true) || decoded.startsWith("intent://", true) || decoded.startsWith("market://", true)) {
                return decoded
            }
        }
        return ""
    }

    private fun isAdUrl(url: String): Boolean {
        // Skip local resource requests. Blocking file/content URLs can break app UI while not reducing real ad traffic.
        if (!url.startsWith("http://", true) && !url.startsWith("https://", true)) return false
        val u = url.lowercase(Locale.US)
        val host = runCatching { java.net.URI(url).host.orEmpty().lowercase(Locale.US) }.getOrDefault("")
        return isHostBlockedByExternalFeed(host) || looksLikeAdNetworkUrl(u, host) || activeAdPatterns().any { u.contains(it) } || hasAdUrlMarkers(u)
    }

    private fun hasAdUrlMarkers(urlLower: String): Boolean {
        if (urlLower.isBlank()) return false
        return urlLower.contains("/mintegral/") ||
            urlLower.contains("/beacon") ||
            urlLower.contains("/event/vast/") ||
            urlLower.contains("liftoff.js") ||
            urlLower.contains("liftoff.source.js") ||
            urlLower.contains("liftoff-creatives") ||
            urlLower.contains("adexp") ||
            urlLower.contains("impression-asia")
    }

    private fun looksLikeAdHtmlPayload(baseUrl: String?, data: String?): Boolean {
        val base = baseUrl?.lowercase(Locale.US).orEmpty()
        if (base.isNotBlank() && isAdUrl(base)) return true
        val body = data?.lowercase(Locale.US).orEmpty()
        if (body.isBlank()) return false
        if (activeAdPatterns().any { body.contains(it) }) return true
        return body.contains("dsp_click_through=") ||
            body.contains("dsp_cover_url=") ||
            body.contains("dsp_creative_view=") ||
            body.contains("union/endcard/") ||
            body.contains("companionview") ||
            body.contains("mintegral") ||
            body.contains("mbridge") ||
            body.contains("liftoff")
    }

    private fun isHighRiskNavigationUrl(url: String): Boolean {
        val lower = url.lowercase(Locale.US)
        val host = runCatching { java.net.URI(url).host.orEmpty() }.getOrDefault("").lowercase(Locale.US)
        if (lower.startsWith("file://", true)) {
            return containsAdultOrGamblingKeyword(lower, host) || hasAdUrlMarkers(lower)
        }
        if (!lower.startsWith("http://", true) && !lower.startsWith("https://", true) && !lower.startsWith("intent://", true) && !lower.startsWith("market://", true)) {
            return false
        }
        return isMalwareDownloadUrl(lower, host) ||
            looksLikeAdNetworkUrl(lower, host) ||
            isLikelyRedirectHost(lower) ||
            isLikelyTrackerUrl(lower) ||
            isHighRiskHost(host)
    }

    private fun activeAdPatterns(): List<String> {
        val extras = loadExtraAdPatterns()
        if (extras.isEmpty()) return adPatterns
        val merged = LinkedHashSet<String>()
        for (pattern in adPatterns) {
            merged += pattern
        }
        for (pattern in extras) {
            merged += pattern
        }
        return merged.toList()
    }

    private fun loadExtraAdPatterns(): List<String> {
        val now = System.currentTimeMillis()
        if (now - lastExtraPatternLoadMs < 15_000L && cachedExtraPatterns.isNotEmpty()) return cachedExtraPatterns
        val extras = runCatching {
            val raw = readModulePrefsXml()
            val out = linkedSetOf<String>()
            val mlPatterns = parsePatternArray(extractPrefValue(raw, "ml_ad_patterns_json"))
            for (pattern in mlPatterns) {
                out += pattern
            }
            val userPatterns = parsePatternArray(extractPrefValue(raw, "user_ad_patterns_json"))
            for (pattern in userPatterns) {
                out += pattern
            }
            val feedHosts = parseCsvHosts(extractPrefValue(raw, "external_block_domains_csv")).take(4000)
            for (host in feedHosts) {
                out += host
            }
            out.toList()
        }.getOrDefault(emptyList())
        cachedExtraPatterns = extras
        lastExtraPatternLoadMs = now
        return extras
    }

    private fun loadExternalBlockedHosts(): Set<String> {
        val now = System.currentTimeMillis()
        val cached = cachedExternalBlockedHosts
        if (now - lastExternalBlockedHostLoadMs < 15_000L && cached.isNotEmpty()) return cached
        val loaded = runCatching {
            val raw = readModulePrefsXml()
            parseCsvHosts(extractPrefValue(raw, "external_block_domains_csv")).toSet()
        }.getOrDefault(emptySet())
        cachedExternalBlockedHosts = loaded
        lastExternalBlockedHostLoadMs = now
        return loaded
    }

    private fun isHostBlockedByExternalFeed(hostLower: String): Boolean {
        if (hostLower.isBlank()) return false
        val blocked = loadExternalBlockedHosts()
        if (blocked.isEmpty()) return false
        var candidate = hostLower.trim().trim('.').lowercase(Locale.US)
        while (true) {
            if (blocked.contains(candidate)) return true
            val dot = candidate.indexOf('.')
            if (dot <= 0 || dot >= candidate.length - 1) return false
            candidate = candidate.substring(dot + 1)
        }
    }

    private fun parseCsvHosts(raw: String?): List<String> {
        if (raw.isNullOrBlank()) return emptyList()
        return raw.split(',')
            .map { it.trim().trim('.').lowercase(Locale.US) }
            .filter { it.isNotBlank() && it.contains('.') }
    }

    private fun parsePatternArray(raw: String?): List<String> {
        if (raw.isNullOrBlank()) return emptyList()
        return runCatching {
            val arr = JSONArray(raw)
            buildList {
                for (i in 0 until arr.length()) {
                    val s = arr.optString(i).trim().lowercase(Locale.US)
                    if (s.isNotBlank()) add(s)
                }
            }
        }.getOrDefault(emptyList())
    }

    private fun readModulePrefsXml(): String {
        val candidates = listOf(
            "/data/user/0/com.mrksvt.firewallagent/shared_prefs/adguard_dns.xml",
            "/data/data/com.mrksvt.firewallagent/shared_prefs/adguard_dns.xml",
        )
        candidates.forEach { path ->
            val file = File(path)
            if (file.exists() && file.canRead()) {
                val text = runCatching { file.readText() }.getOrDefault("")
                if (text.isNotBlank()) return text
            }
        }
        return ""
    }

    private fun extractPrefValue(xml: String, key: String): String? {
        if (xml.isBlank()) return null
        val pattern = Regex("""<string\s+name="$key">([^<]*)</string>""")
        val value = pattern.find(xml)?.groupValues?.getOrNull(1) ?: return null
        return value
            .replace("&quot;", "\"")
            .replace("&apos;", "'")
            .replace("&lt;", "<")
            .replace("&gt;", ">")
            .replace("&amp;", "&")
    }

    private fun emptyNoContentResponse(): WebResourceResponse {
        return WebResourceResponse(
            "application/json",
            "utf-8",
            204,
            "No Content",
            mapOf(
                "Cache-Control" to "no-store",
                "Access-Control-Allow-Origin" to "*"
            ),
            ByteArrayInputStream(ByteArray(0))
        )
    }

    private fun logNetworkEventOnce(dedupKey: String, message: String, ttlMs: Long = 1200L) {
        val now = System.currentTimeMillis()
        val last = networkEventDedup[dedupKey]
        if (last != null && now - last < ttlMs) return
        if (networkEventDedup.size > 5000) networkEventDedup.clear()
        networkEventDedup[dedupKey] = now
        XposedBridge.log(message)
    }
}
