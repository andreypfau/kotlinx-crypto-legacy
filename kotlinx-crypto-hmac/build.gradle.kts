plugins {
    kotlin("multiplatform")
}

kotlin {
    sourceSets {
        val commonMain by getting {
            dependencies {
                api(project(":kotlinx-crypto-mac"))
                api(project(":kotlinx-crypto-digest"))
            }
        }
        val commonTest by getting {
            dependencies {
                implementation(project(":kotlinx-crypto-sha256"))
                implementation(project(":kotlinx-crypto-sha512"))
                implementation("io.github.andreypfau:kotlinx-encoding-hex:1.0-SNAPSHOT")
            }
        }
    }
}
