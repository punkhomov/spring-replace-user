import punkhomov.spring.replaceuser.gradle.Versions

plugins {
    kotlin("jvm") apply true
}

repositories {
    mavenCentral()
    jcenter()
}

dependencies {
    implementation(project(":replace-user-core"))
    implementation(project(":replace-user-webflux"))
    implementation(project(":replace-user-webmvc"))

    implementation("javax.servlet", "javax.servlet-api", Versions.javaxServlet)
    implementation("io.projectreactor", "reactor-core", Versions.reactorCore)
    implementation("io.projectreactor.kotlin", "reactor-kotlin-extensions", Versions.reactorKotlin)

    testImplementation(platform("org.junit:junit-bom:5.7.1"))
    testImplementation("org.junit.jupiter", "junit-jupiter")
    testImplementation("org.springframework", "spring-test", Versions.springFramework)
    testImplementation("org.mockito", "mockito-inline", "3.8.0")
    testImplementation("io.projectreactor", "reactor-test", Versions.reactorCore)
}

tasks.test {
    useJUnitPlatform()
}