package com.mrksvt.firewallagent.xposed

import android.webkit.WebResourceRequest
import android.webkit.WebResourceResponse
import de.robv.android.xposed.IXposedHookLoadPackage
import de.robv.android.xposed.XC_MethodHook
import de.robv.android.xposed.XposedBridge
import de.robv.android.xposed.callbacks.XC_LoadPackage
import java.net.InetAddress
import java.util.Locale

/**
 * DnsHideHook — Xposed module that intercepts Private DNS detection by apps.
 *
 * Problem: When Private DNS (AdGuard/Quad9/etc.) is active, some apps detect it via:
 *   1. LinkProperties.getPrivateDnsServerName() returning a non-null value
 *   2. ConnectivityManager checking NET_CAPABILITY_PRIVATE_DNS_BROKEN
 *   3. InetAddress.getAllByName() failures for hardcoded ad-SDK domains (which get
 *      blocked by AG DNS), causing the app to think "no network" → refuse to work
 *
 * Solution (per-app via Xposed):
 *   1. Hook LinkProperties to return null for private DNS server name (app sees "off")
 *   2. Hook InetAddress for known ad domains → return a benign localhost fallback so
 *      SDK connectivity checks pass (they just get an empty/null response from our
 *      HybridAdHook WebView intercept anyway)
 *   3. Hook NetworkCapabilities to report Private DNS as not broken
 *
 * Note: Uses XposedBridge.hookAllMethods directly (no XposedHelpers dependency
 * since our stub jar only contains core API).
 */
class DnsHideHook : IXposedHookLoadPackage {

    // Ad SDK domains that must "resolve" to prevent apps from failing connectivity checks.
    // We return a loopback address so the TCP connection attempt simply sees no service,
    // which is handled gracefully by the SDK (vs. NXDOMAIN which triggers "no network").
    private val adSdkDomainsToFake = setOf(
        "googleads.g.doubleclick.net",
        "adservice.google.com",
        "pagead2.googlesyndication.com",
        "googleadservices.com",
        "admob.com",
        "securepubads.g.doubleclick.net",
        "tpc.googlesyndication.com",
        "mobile.adnxs.com",
        "ib.adnxs.com",
        "aax.amazon-adsystem.com",
        "unityads.unity3d.com",
        "ads.mopub.com",
        "config.applovin.com",
        "rt.applovin.com",
        "ms.applovin.com",
        "d.applovin.com",
        "events3alt.applovin.com",
        "pdn.applovin.com",
        "sdk.applovin.com",
        "api2.appsflyer.com",
        "sdk-api.singular.net",
        "sdk.vungle.com",
        "api.vungle.com",
        "ads6.vungle.com",
        "adapi.ironsrc.com",
        "sdk.ironsrc.com",
        "sdk.supersonic.com",
        "outcome-ssp.supersonicads.com",
        "mediation.mintegral.com",
        "net.mintegral.com",
        "cdn-adn.mintegral.com",
        "ads.mintegral.com",
        "hb.chartboost.com",
        "live.chartboost.com",
        "ads.chartboost.com",
        "da.chartboost.com",
        "an.facebook.com",
        "graph.facebook.com",
        "edge-mqtt.facebook.com",
        "a.startappservice.com",
        "prm.smartadserver.com",
        "ads.smartadserver.com",
        "tracking.criteo.com",
        "gum.criteo.com",
        "ssp.yahoo.com",
        "ads.yieldmo.com",
        "prebid.media.net",
        "ads.pubmatic.com",
    )

    // System packages to skip — never interfere with OS-level components
    private val systemPackagePrefixes = setOf(
        "android",
        "com.android.",
        "com.google.android.gms",
        "com.google.android.gsf",
        "com.mrksvt.firewallagent",
    )

    override fun handleLoadPackage(lpparam: XC_LoadPackage.LoadPackageParam) {
        val pkg = lpparam.packageName ?: return
        if (systemPackagePrefixes.any { pkg == it || pkg.startsWith(it) }) return

        try {
            hookLinkProperties(lpparam)
        } catch (_: Throwable) {}

        try {
            hookNetworkCapabilities(lpparam)
        } catch (_: Throwable) {}

        try {
            hookInetAddressForAdDomains(lpparam)
        } catch (_: Throwable) {}

        XposedBridge.log("FA.DnsHideHook init ok in $pkg")
    }

    /**
     * Hook LinkProperties.getPrivateDnsServerName() to return null.
     * Apps query this to detect if Private DNS is configured. A null return
     * means "automatic" (no custom Private DNS) from the app's perspective.
     */
    private fun hookLinkProperties(lpparam: XC_LoadPackage.LoadPackageParam) {
        val clazz = findClassSafe("android.net.LinkProperties", lpparam.classLoader) ?: return

        XposedBridge.hookAllMethods(clazz, "getPrivateDnsServerName", object : XC_MethodHook() {
            override fun afterHookedMethod(param: MethodHookParam) {
                if (param.result != null) {
                    param.result = null
                    XposedBridge.log("FA.DnsHideHook masked getPrivateDnsServerName in ${lpparam.packageName}")
                }
            }
        })

        // Android 12+: isPrivateDnsActive()
        runCatching {
            XposedBridge.hookAllMethods(clazz, "isPrivateDnsActive", object : XC_MethodHook() {
                override fun afterHookedMethod(param: MethodHookParam) {
                    // Return false — app thinks no Private DNS is active
                    param.result = false
                }
            })
        }

        // Android 12+: getValidatedPrivateDnsServers()
        runCatching {
            XposedBridge.hookAllMethods(clazz, "getValidatedPrivateDnsServers", object : XC_MethodHook() {
                override fun afterHookedMethod(param: MethodHookParam) {
                    param.result = emptyList<Any>()
                }
            })
        }
    }

    /**
     * Hook NetworkCapabilities to hide NET_CAPABILITY_PRIVATE_DNS_BROKEN.
     * When Private DNS can't resolve a domain (because we blocked it),
     * Android marks the capability as "broken". Some apps detect this and
     * refuse to work. We mask this so the network always appears healthy.
     */
    private fun hookNetworkCapabilities(lpparam: XC_LoadPackage.LoadPackageParam) {
        val clazz = findClassSafe("android.net.NetworkCapabilities", lpparam.classLoader) ?: return

        // hasCapability(int capability) — NET_CAPABILITY_PRIVATE_DNS_BROKEN = 77
        XposedBridge.hookAllMethods(clazz, "hasCapability", object : XC_MethodHook() {
            private val PRIVATE_DNS_BROKEN = 77

            override fun afterHookedMethod(param: MethodHookParam) {
                val cap = param.args.firstOrNull() as? Int ?: return
                if (cap == PRIVATE_DNS_BROKEN) {
                    param.result = false // Always report as NOT broken
                }
            }
        })
    }

    /**
     * Hook InetAddress.getAllByName() for known ad SDK domains.
     *
     * When Private DNS blocks ad domains at DNS level, InetAddress throws
     * UnknownHostException. Ad SDKs interpret this as "no network" and may
     * shut down the entire network stack of the app or crash.
     *
     * We intercept lookups for known ad domains and return a loopback IP.
     * This means:
     *   - App's connectivity probe succeeds (InetAddress doesn't throw)
     *   - Any TCP connection to 127.0.0.1 will be refused (no server there)
     *   - HybridAdHook already blocks the WebView/SDK calls at a higher level
     *   - The ad is never shown, but the app doesn't crash or "think" offline
     */
    private fun hookInetAddressForAdDomains(lpparam: XC_LoadPackage.LoadPackageParam) {
        val inetClass = findClassSafe("java.net.InetAddress", lpparam.classLoader) ?: return

        val loopbackAddr = InetAddress.getByName("127.0.0.1")
        val loopbackArray = arrayOf(loopbackAddr)

        XposedBridge.hookAllMethods(inetClass, "getAllByName", object : XC_MethodHook() {
            override fun beforeHookedMethod(param: MethodHookParam) {
                val host = param.args.firstOrNull() as? String ?: return
                val hostLower = host.lowercase(Locale.US)
                if (adSdkDomainsToFake.any { hostLower == it || hostLower.endsWith(".$it") }) {
                    // Return loopback — prevents UnknownHostException without enabling real ad traffic
                    param.result = loopbackArray
                    XposedBridge.log("FA.DnsHideHook faked InetAddress.getAllByName for $host in ${lpparam.packageName}")
                }
            }
        })

        // Also hook getByName for single resolution
        XposedBridge.hookAllMethods(inetClass, "getByName", object : XC_MethodHook() {
            override fun beforeHookedMethod(param: MethodHookParam) {
                val host = param.args.firstOrNull() as? String ?: return
                val hostLower = host.lowercase(Locale.US)
                if (adSdkDomainsToFake.any { hostLower == it || hostLower.endsWith(".$it") }) {
                    param.result = loopbackAddr
                    XposedBridge.log("FA.DnsHideHook faked InetAddress.getByName for $host in ${lpparam.packageName}")
                }
            }
        })
    }

    /**
     * Safe class lookup using the app's classLoader — does NOT throw if class is absent.
     * This replaces XposedHelpers.findClassIfExists() since our stub jar doesn't include it.
     */
    private fun findClassSafe(name: String, classLoader: ClassLoader?): Class<*>? =
        runCatching { Class.forName(name, false, classLoader ?: ClassLoader.getSystemClassLoader()) }.getOrNull()
}
