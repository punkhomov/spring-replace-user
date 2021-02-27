import punkhomov.spring.replaceuser.gradle.Versions

plugins {
    kotlin("jvm") apply true
}

repositories {
    mavenCentral()
    jcenter()
}

dependencies {
    api(kotlin("stdlib"))

    api("org.springframework.security", "spring-security-core", Versions.springFramework)
    api("org.springframework.security", "spring-security-web", Versions.springFramework)
    api("org.springframework.security", "spring-security-config", Versions.springFramework)
}