import punkhomov.spring.replaceuser.gradle.Versions

plugins {
    kotlin("jvm") apply true
}

dependencies {
    api(project(":replace-user-core"))

    compileOnly("io.projectreactor", "reactor-core", Versions.reactorCore)
    compileOnly("io.projectreactor.kotlin", "reactor-kotlin-extensions", Versions.reactorKotlin)
}

val sourcesJar by tasks.creating(Jar::class) {
    archiveClassifier.set("sources")
    from(sourceSets.getByName("main").allSource)
}

publishing {
    publications {
        create<MavenPublication>("maven") {
            from(components["kotlin"])
            artifact(sourcesJar)

            pom {
                name.set(project.name)
                description.set(project.description)
                url.set("https://github.com/punkhomov/spring-replace-user")
                developers {
                    developer {
                        id.set("punkhomov")
                        name.set("Nikita Pakhomov")
                        email.set("punkhomov@gmail.com")
                    }
                }
                scm {
                    connection.set("scm:git:git://github.com/punkhomov/spring-replace-user.git")
                    developerConnection.set("scm:git:ssh://github.com/punkhomov/spring-replace-user.git")
                    url.set("https://github.com/punkhomov/spring-replace-user")
                }
            }
        }
    }
}