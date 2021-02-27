import punkhomov.spring.replaceuser.gradle.Versions

plugins {
    kotlin("jvm") apply true
}

repositories {
    mavenCentral()
    jcenter()
}

dependencies {
    api(project(":replace-user-core"))

    compileOnly("io.projectreactor", "reactor-core", Versions.reactorCore)
}