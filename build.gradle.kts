import org.jetbrains.kotlin.gradle.tasks.KotlinCompile

plugins {
    kotlin("jvm") version "1.4.10"
    `maven-publish`
    `java-library`
}

configure(allprojects) {
    group = "punkhomov.spring"
    version = "0.0.3"

    repositories {
        mavenCentral()
        jcenter()
    }
}

configure(subprojects) {
    apply(plugin = "maven-publish")
    apply(plugin = "java-library")

    tasks.withType<KotlinCompile> {
        kotlinOptions {
            jvmTarget = "1.8"
            useIR = true
        }
    }
}