pluginManagement {
    repositories {
        google()
        mavenCentral()
        gradlePluginPortal()
        // Mirror aliyun — fallback saat maven central diblok (403 di network tertentu)
        maven { url = uri("https://maven.aliyun.com/repository/central") }
        maven { url = uri("https://maven.aliyun.com/repository/google") }
    }
}

dependencyResolutionManagement {
    repositoriesMode.set(RepositoriesMode.FAIL_ON_PROJECT_REPOS)
    repositories {
        google()
        mavenCentral()
        maven { url = uri("https://jitpack.io") }
        // Mirror aliyun — fallback saat maven central diblok (403 di network tertentu)
        maven { url = uri("https://maven.aliyun.com/repository/central") }
        maven { url = uri("https://maven.aliyun.com/repository/google") }
        maven { url = uri("https://maven.aliyun.com/repository/public") }
    }
}

rootProject.name = "FirewallAgentRootApp"
include(":app")
