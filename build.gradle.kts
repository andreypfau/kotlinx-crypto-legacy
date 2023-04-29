import org.gradle.internal.os.OperatingSystem
import org.jetbrains.kotlin.gradle.ExperimentalKotlinGradlePluginApi
import org.jetbrains.kotlin.gradle.dsl.KotlinMultiplatformExtension
import org.jetbrains.kotlin.gradle.plugin.KotlinPlatformType
import org.jetbrains.kotlin.gradle.plugin.KotlinTarget
import org.jetbrains.kotlin.gradle.plugin.mpp.KotlinMultiplatformPlugin

plugins {
    kotlin("multiplatform") version "1.8.20" apply false
    id("maven-publish")
    signing
}

allprojects {
    repositories {
        mavenCentral()
        maven("https://s01.oss.sonatype.org/content/repositories/snapshots/")
    }
}

subprojects {
    apply(plugin = "kotlin-multiplatform")
    apply(plugin = "maven-publish")
    apply(plugin = "signing")

    group = "io.github.andreypfau"
    version = "1.0-SNAPSHOT"

    buildDir = File(rootDir, "build/${project.name}")

    @OptIn(ExperimentalKotlinGradlePluginApi::class)
    extensions.getByType<KotlinMultiplatformExtension>().apply {
        explicitApi()
        targetHierarchy.default()

        jvm {
            compilations.all {
                kotlinOptions {
                    jvmTarget = "1.8"
                }
            }
            testRuns["test"].executionTask.configure {
                useJUnitPlatform()
            }
        }
        js(IR) {
            browser()
            nodejs()
        }

        macosArm64()
        macosX64()
        ios()
        watchos()
        tvos()
        linuxX64()
        linuxArm64()
        mingwX64()

        targets.configureEach {
            disableCompilationsIfNeeded()
        }

        sourceSets {
            val commonMain by getting
            val commonTest by getting {
                dependencies {
                    implementation(kotlin("test"))
                }
            }
        }
    }

    publishing {
        // Configure maven central repository
        repositories {
            maven {
                name = "sonatype"
                if (version.toString().endsWith("-SNAPSHOT")) {
                    setUrl("https://s01.oss.sonatype.org/content/repositories/snapshots/")
                } else {
                    setUrl("https://s01.oss.sonatype.org/service/local/staging/deploy/maven2/")
                }
                credentials {
                    username = System.getenv("OSSRH_USERNAME")
                    password = System.getenv("OSSRH_PASSWORD")
                }
            }
        }

        publications.withType<MavenPublication> {

            val javadocJar by tasks.register("${this@withType.name}JavadocJar", Jar::class) {
                archiveClassifier.set("javadoc")
                archiveAppendix.set("-${this@withType.name}")
            }
            artifact(javadocJar)

            pom {
                name.set("kotlinx-crypto")
                url.set("https://github.com/andreypfau/kotlinx-crypto")

                licenses {
                    license {
                        name.set("MIT")
                        url.set("https://opensource.org/licenses/MIT")
                    }
                }
                developers {
                    developer {
                        id.set("andreypfau")
                        name.set("Andrey Pfau")
                        email.set("andreypfau@ton.org")
                    }
                }
                scm {
                    url.set("https://github.com/andreypfau/kotlinx-crypto")
                }
            }
        }
    }

    disablePublicationTasksIfNeeded()

    signing {
        val signingKey = project.findProperty("signing.secretKey") as? String ?: System.getenv("SIGNING_KEY")
        val signingPassword = project.findProperty("signing.password") as? String ?: System.getenv("SIGNING_PASSWORD")
        isRequired = signingKey != null && signingPassword != null
        useInMemoryPgpKeys(
            signingKey,
            signingPassword,
        )
        sign(publishing.publications)
    }
}

disableUnreachableTasks()

fun Project.disableUnreachableTasks() {
    require(rootProject == this) { "Must be called on a root project" }

    gradle.taskGraph.whenReady {
        DisableTasks(graph = this).disableTasks()
    }
}

fun KotlinTarget.getHostType(): HostType? =
    when (platformType) {
        KotlinPlatformType.androidJvm,
        KotlinPlatformType.jvm,
        KotlinPlatformType.wasm,
        KotlinPlatformType.js -> HostType.LINUX

        KotlinPlatformType.native ->
            when {
                name.startsWith("ios") -> HostType.MAC_OS
                name.startsWith("watchos") -> HostType.MAC_OS
                name.startsWith("tvos") -> HostType.MAC_OS
                name.startsWith("macos") -> HostType.MAC_OS
                name.startsWith("linux") -> HostType.LINUX
                name.startsWith("mingw") -> HostType.WINDOWS
                else -> error("Unsupported native target: $this")
            }

        KotlinPlatformType.common -> null
    }

enum class HostType {
    MAC_OS, LINUX, WINDOWS
}

val splitTargets get() = System.getProperty("split_targets") != null
val metadataOnly get() = System.getProperty("metadata_only") != null

fun KotlinTarget.disableCompilationsIfNeeded() {
    if (!isCompilationAllowed()) {
        compilations.configureEach {
            compileTaskProvider.get().enabled = false
        }
    }
}

fun KotlinTarget.isCompilationAllowed(): Boolean {
    if ((name == KotlinMultiplatformPlugin.METADATA_TARGET_NAME) || !splitTargets) {
        return true
    }

    val os = OperatingSystem.current()

    return when (getHostType()) {
        HostType.MAC_OS -> os.isMacOsX
        HostType.LINUX -> os.isLinux
        HostType.WINDOWS -> os.isWindows
        null -> true
    }
}

fun AbstractPublishToMaven.isAllowed(targets: NamedDomainObjectCollection<KotlinTarget>): Boolean {
    val publicationName: String? = publication?.name

    return when {
        publicationName == "kotlinMultiplatform" -> metadataOnly || !splitTargets
        metadataOnly -> false
        publicationName != null -> {
            val target = targets.find { it.name.startsWith(publicationName) }
            checkNotNull(target) { "Target not found for publication $publicationName" }
            target.isCompilationAllowed()
        }

        else -> {
            val target = targets.find { name.contains(other = it.name, ignoreCase = true) }
            checkNotNull(target) { "Target not found for publication $this" }
            target.isCompilationAllowed()
        }
    }
}

fun Project.disablePublicationTasksIfNeeded() {
    val targets = extensions.getByType<KotlinMultiplatformExtension>().targets

    tasks.withType<AbstractPublishToMaven>().configureEach {
        if (!isAllowed(targets)) {
            enabled = false
        }
    }
}

private class DisableTasks(
    private val graph: TaskExecutionGraph
) {
    private val rootTasks = findRootTasks()
    private val results = HashMap<Pair<Task, Task>, Boolean>()

    private fun findRootTasks(): List<Task> {
        val rootTasks = ArrayList<Task>()

        val children = HashSet<Task>()
        graph.allTasks.forEach {
            children += graph.getDependencies(it)
        }

        graph.allTasks.forEach {
            if (it !in children) {
                rootTasks += it
            }
        }

        return rootTasks
    }

    fun disableTasks() {
        graph
            .allTasks
            .filterNot { it.enabled }
            .forEach { disableChildren(it) }
    }

    private fun disableChildren(task: Task) {
        graph.getDependencies(task).forEach { child ->
            if (child.enabled) {
                if (!isTaskAccessible(task = child)) {
                    child.enabled = false
                    disableChildren(task = child)
                }
            } else {
                disableChildren(task = child)
            }
        }
    }

    private fun isTaskAccessible(task: Task): Boolean =
        rootTasks.any { (it != task) && isPathExists(source = it, destination = task) }

    private fun isPathExists(source: Task, destination: Task): Boolean =
        results.getOrPut(source to destination) {
            when {
                !source.enabled -> false
                source == destination -> true
                else -> graph.getDependencies(source).any { isPathExists(source = it, destination = destination) }
            }
        }
}
