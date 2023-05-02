import kotlinx.benchmark.gradle.JvmBenchmarkTarget

plugins {
    kotlin("multiplatform")
    id("org.jetbrains.kotlinx.benchmark")
    id("org.jetbrains.kotlin.plugin.allopen")
}

allOpen {
    annotation("org.openjdk.jmh.annotations.State")
}

kotlin {
    sourceSets {
        val commonMain by getting {
            dependencies {
                api(project(":kotlinx-crypto-digest"))
                implementation("io.github.andreypfau:kotlinx-encoding-binary:1.0-SNAPSHOT")
            }
        }
        val commonTest by getting {
            dependencies {
                implementation("io.github.andreypfau:kotlinx-encoding-hex:1.0-SNAPSHOT")
            }
        }
        val jvmMain by getting {
            dependencies {
                implementation("org.jetbrains.kotlinx:kotlinx-benchmark-runtime:0.4.4")
            }
        }
    }
}

benchmark {
    targets {
        register("jvmTest") {
            if (this is JvmBenchmarkTarget) {
                jmhVersion = "1.21"
            }
        }
    }
}
