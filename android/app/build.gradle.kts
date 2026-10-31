plugins {
    id("com.android.application")
    id("org.jetbrains.kotlin.android")
}

android {
    namespace = "com.embasic.escanner.android"
    compileSdk = 36

    defaultConfig {
        applicationId = "com.embasic.escanner.android"
        minSdk = 26
        targetSdk = 36
        versionCode = 1
        versionName = "0.0.1-foundation"
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

// No CameraX, Compose, OCR, ads or network runtime dependencies yet:
// direct/transitive licenses and real device acceptance have not been cleared.

// Test-only dependency (never part of release APK): JUnit 4.13.2, EPL-1.0.
// Direct POM compile transitive: hamcrest-core 1.3, BSD-style license.
// See docs/ANDROID-TOOLCHAIN-LICENSE-RESEARCH-20261029.md; not runtime license clearance.
dependencies {
    testImplementation("junit:junit:4.13.2")
}
