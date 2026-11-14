plugins {
    id("com.android.application")
    id("org.jetbrains.kotlin.android")
    id("org.jetbrains.kotlin.plugin.compose")
}

android {
    namespace = "com.embasic.escanner.android"
    compileSdk = 36

    defaultConfig {
        applicationId = "com.embasic.escanner.android"
        minSdk = 26
        targetSdk = 36
        versionCode = 1
        versionName = "0.1.0-workspace-preview"
    }

    buildFeatures {
        compose = true
    }

    compileOptions {
        sourceCompatibility = JavaVersion.VERSION_17
        targetCompatibility = JavaVersion.VERSION_17
    }
}

kotlin {
    compilerOptions {
        jvmTarget.set(org.jetbrains.kotlin.gradle.dsl.JvmTarget.JVM_17)
    }
}

// First functional Compose slice. Native platform PdfDocument is used for local PDF;
// Compose direct+transitive licensing and SDK distribution remain RELEASE NO-GO.

// Test-only dependency (never part of release APK): JUnit 4.13.2, EPL-1.0.
// Direct POM compile transitive: hamcrest-core 1.3, BSD-style license.
// See docs/ANDROID-TOOLCHAIN-LICENSE-RESEARCH-20261029.md; not runtime license clearance.
dependencies {
    implementation(platform("androidx.compose:compose-bom:2026.09.00"))
    implementation("androidx.compose.ui:ui")
    implementation("androidx.compose.foundation:foundation")
    implementation("androidx.compose.material3:material3")
    testImplementation("junit:junit:4.13.2")
}
