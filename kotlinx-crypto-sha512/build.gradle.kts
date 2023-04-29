plugins {
    kotlin("multiplatform")
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
    }
}
