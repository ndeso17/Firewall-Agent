# Xposed Hooks (xposed/)

**Part of:** Firewall-Agent android-app (see `../../AGENTS.md`)

## OVERVIEW
LSPosed/Xposed module — hybrid ad blocking + DNS masking at app level. 3 files, loaded into target packages via `xposed_scope`.

## FILES
| File | Role |
|------|------|
| HybridAdHook.kt:31 | IXposedHookLoadPackage — WebView/WebResourceRequest interception, ad URL blocking via empty WebResourceResponse |
| DnsHideHook.kt:32 | IXposedHookLoadPackage — masks Private DNS detection, fakes ad domains → 127.0.0.1 |
| RequestDecisionEngine.kt:20 | pure logic — `DecisionAction` enum (:9), `DecisionResult` (:15), per-request allow/block/redirect decision |

## HOW IT WORKS
- **Entry**: `IXposedHookLoadPackage.handleLoadPackage` — each class independent hook
- **HybridAdHook**: intercepts `WebViewClient.shouldInterceptRequest` → URL matches ads patterns → return empty `WebResourceResponse`; anti-redirect for browser/store/installer
- **DnsHideHook**: hooks `LinkProperties`/`NetworkCapabilities` to mask private-DNS signal; DNS resolver answers faked to 127.0.0.1
- **Scope**: `res/values/xposed_scope.xml` — explicit target packages (chrome, webview, app stores)
- **Lifecycle**: module-level `xposedmodule=true` metadata in manifest; min version 93

## CONVENTIONS
- `compileOnly files("libs/xposed-api-stub.jar")` — stub never bundled into APK
- Keep engine (RequestDecisionEngine) separate from hook wiring — testable pure logic
- Patterns arrays centralized (ads matcher), not inline

## ANTI-PATTERNS
- Hardcoded 127.0.0.1 literals (HybridAdHook.kt:2066, DnsHideHook.kt:208,215) — centralize
- HybridAdHook.kt is 2830 lines — split hooks by concern before growing further
