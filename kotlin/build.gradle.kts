plugins {
    kotlin("jvm") version "2.2.20"
    `java-library-distribution`
    id("com.diffplug.spotless") version "8.0.0"
}

repositories {
    mavenCentral()
}

dependencies {
    implementation("org.bouncycastle:bcprov-jdk18on:1.81")
    testImplementation(kotlin("test"))
}

kotlin {
    jvmToolchain(17)
}

spotless {
    kotlin { ktlint() }
    kotlinGradle { ktlint() }
}

tasks.test {
    useJUnitPlatform()
}
