package com.mrksvt.firewallagent.xposed

import android.webkit.WebResourceRequest
import android.webkit.WebResourceResponse
import de.robv.android.xposed.IXposedHookLoadPackage
import de.robv.android.xposed.XC_MethodHook
import de.robv.android.xposed.XposedBridge
import de.robv.android.xposed.callbacks.XC_LoadPackage
import java.io.ByteArrayInputStream
import java.util.Locale

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
        "applovin",
        "ironsrc",
        "vungle",
        "adnxs.com",
        "mintegral.",
        "hyprmx.com",
        "inmobi.",
        "liftoff.",
        "moloco.",
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

    override fun handleLoadPackage(lpparam: XC_LoadPackage.LoadPackageParam) {
        val pkg = lpparam.packageName ?: return
        if (pkg == "android" || pkg == "com.android.systemui" || pkg == "com.mrksvt.firewallagent") {
            return
        }

        try {
            hookWebViewLoads(lpparam)
            hookWebViewClientIntercept(lpparam)
            hookAdSdkLoads(lpparam)
            XposedBridge.log("FA.HybridAdHook init ok in ${lpparam.packageName}")
        } catch (t: Throwable) {
            XposedBridge.log("FA.HybridAdHook init failed for $pkg: ${t.message}")
        }

        // Apply DNS hide hooks — prevents apps from detecting Private DNS as active
        // and prevents ad SDK connectivity checks from failing with UnknownHostException
        try {
            dnsHideHook.handleLoadPackage(lpparam)
        } catch (t: Throwable) {
            XposedBridge.log("FA.DnsHideHook init failed for $pkg: ${t.message}")
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
            // IronSource
            "com.ironsource.mediationsdk.IronSource" to listOf("loadInterstitial", "showInterstitial", "loadRewardedVideo", "showRewardedVideo"),
            // Vungle (legacy + new)
            "com.vungle.warren.Vungle" to listOf("loadAd", "playAd"),
            "com.vungle.warren.Banners" to listOf("loadBanner"),
            "com.vungle.ads.VungleAds" to listOf("loadAd", "showAd"),
            "com.vungle.ads.BaseFullscreenAd" to listOf("loadAd", "show"),
            "com.vungle.ads.InterstitialAd" to listOf("load", "show"),
            "com.vungle.ads.RewardedAd" to listOf("load", "show"),
            // Meta Audience Network
            "com.facebook.ads.AdView" to listOf("loadAd"),
            "com.facebook.ads.InterstitialAd" to listOf("loadAd", "show"),
            "com.facebook.ads.RewardedVideoAd" to listOf("loadAd", "show"),
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
            // Liftoff / Vungle
            "com.liftoff.publisher.LoHook" to listOf("loadAd"),
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

    private fun hookWebViewLoads(lpparam: XC_LoadPackage.LoadPackageParam) {
        val webViewClass = Class.forName("android.webkit.WebView", false, lpparam.classLoader)

        XposedBridge.hookAllMethods(webViewClass, "loadUrl", object : XC_MethodHook() {
            override fun beforeHookedMethod(param: MethodHookParam) {
                val url = param.args.firstOrNull() as? String ?: return
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
    }

    private fun hookWebViewClientIntercept(lpparam: XC_LoadPackage.LoadPackageParam) {
        val clazz = Class.forName("android.webkit.WebViewClient", false, lpparam.classLoader)
        val emptyResponse = emptyNoContentResponse()

        XposedBridge.hookAllMethods(clazz, "shouldInterceptRequest", object : XC_MethodHook() {
            override fun beforeHookedMethod(param: MethodHookParam) {
                val url = extractUrl(param.args) ?: return
                if (!isAdUrl(url)) return
                param.result = emptyResponse
                XposedBridge.log("FA.HybridAdHook intercepted request in ${lpparam.packageName}: $url")
            }
        })
    }

    private fun extractUrl(args: Array<out Any?>): String? {
        if (args.size < 2) return null
        val second = args[1] ?: return null
        return when (second) {
            is String -> second
            is WebResourceRequest -> second.url?.toString()
            else -> null
        }
    }

    private fun isAdUrl(url: String): Boolean {
        // Skip local resource requests. Blocking file/content URLs can break app UI while not reducing real ad traffic.
        if (!url.startsWith("http://", true) && !url.startsWith("https://", true)) return false
        val u = url.lowercase(Locale.US)
        return adPatterns.any { u.contains(it) }
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
}
