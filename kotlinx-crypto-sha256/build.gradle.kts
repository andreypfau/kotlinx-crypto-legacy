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
    }
}
