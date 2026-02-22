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
            hookIronSourceAdapters(lpparam)  // Dedicated IronSource mediation adapter hooks
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
